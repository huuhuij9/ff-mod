import socketserver
import http.server
import json
import re
import requests

def load_deny_rules(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        deny_rules = [rule for rule in data.get('filters', []) if rule.get('pkg1Name') == 'com.dts.freefireth' and rule.get('mobile') == 'deny']
        return deny_rules
    except Exception as e:
        print(f"[ERRO] Falha ao carregar filtros: {e}")
        return []

DENY_RULES = load_deny_rules('/sdcard/Download/filters.json')

def should_block(host):
    for rule in DENY_RULES:
        server_type = rule.get('serverStrType')
        server_value = rule.get('server')
        if server_type == 'ip4':
            if server_value == '*': return True
            ip_pattern = server_value.replace('.', '\.').replace('*', '.*')
            if re.match(ip_pattern, host): return True
        elif server_type == 'host' and server_value == host:
            return True
    return False

class FirewallHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()

    def handle_request(self):
        host = self.headers.get('Host')
        if not host:
            self.send_error(400, "Bad Request")
            return

        if should_block(host):
            print(f"[FIREWALL] BLOQUEADO: {host}{self.path}")
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Bloqueado pelo Firewall")
            return

        try:
            url = self.path if self.path.startswith('http') else f"http://{host}{self.path}"
            headers = {k: v for k, v in self.headers.items() if k not in ['Proxy-Connection', 'Proxy-Authorization']}
            
            if self.command == 'GET':
                resp = requests.get(url, headers=headers, allow_redirects=True)
            elif self.command == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                resp = requests.post(url, headers=headers, data=post_data, allow_redirects=True)
            else:
                self.send_error(501, "Unsupported method")
                return

            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() not in ['transfer-encoding', 'content-encoding', 'proxy-authenticate', 'proxy-authorization']:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)
        except Exception as e:
            print(f"[FIREWALL] Erro ao encaminhar para {host}: {e}")
            self.send_error(502, "Bad Gateway")

if __name__ == '__main__':
    PORT = 8080
    with socketserver.ThreadingTCPServer(("", PORT), FirewallHandler) as httpd:
        print(f"[FIREWALL] Iniciado na porta {PORT}")
        print("[FIREWALL] Configure o proxy HTTP do Android para o IP do Termux e porta 8080.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("[FIREWALL] Parado.")
