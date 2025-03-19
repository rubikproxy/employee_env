import os
import http.server
import socketserver
import subprocess
import re

def get_wireguard_ip(interface="wg0"):
    try:
        result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True)
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
        return match.group(1) if match else None
    except Exception:
        return None

def is_wireguard_running():
    try:
        result = subprocess.run(["wg"], capture_output=True, text=True)
        return "interface:" in result.stdout
    except FileNotFoundError:
        return False

def start_server(directory, ip, port=8000):
    os.chdir(directory)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer((ip, port), handler) as httpd:
        print(f"Serving HTTP on port {port} from {directory}")
        print(f"Access the server at: http://{ip}:{port}/")
        httpd.serve_forever()

def main():
    if not is_wireguard_running():
        print("Error: Please turn on WireGuard before starting the server.")
        return

    wg_ip = get_wireguard_ip()
    if not wg_ip:
        print("Error: Unable to retrieve WireGuard IP.")
        return

    path = input("Enter the folder or file path to serve: ").strip()

    if not os.path.exists(path):
        print("Error: The specified path does not exist.")
        return

    if os.path.isfile(path):
        directory, filename = os.path.split(path)
        os.chdir(directory)
        print(f"Serving file: {filename}")
    else:
        directory = path

    start_server(directory, wg_ip)

if __name__ == "__main__":
    main()
