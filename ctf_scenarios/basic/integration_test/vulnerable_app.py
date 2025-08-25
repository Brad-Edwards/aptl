#!/usr/bin/env python3
import http.server
import socketserver
import subprocess
import urllib.parse
import os
import signal
import sys

def signal_handler(sig, frame):
    print("\nShutting down server...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/ping'):
            # Extract IP parameter
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            
            if 'ip' in params:
                ip = params['ip'][0]
                # Vulnerable: command injection
                result = subprocess.run(f"ping -c 1 {ip}", 
                                      shell=True, 
                                      capture_output=True, 
                                      text=True)
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Ping result:\n{result.stdout}\n{result.stderr}".encode())
            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Missing 'ip' parameter")
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"""
<html>
<body>
<h1>Network Diagnostic Tool</h1>
<form action="/ping" method="get">
    <label>IP Address: <input type="text" name="ip" /></label>
    <input type="submit" value="Ping" />
</form>
</body>
</html>
""")

PORT = 8080
with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
    print(f"Server running on port {PORT}")
    httpd.serve_forever()
