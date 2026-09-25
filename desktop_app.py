import os
import sys
import time
import socket
import threading
import webview
from nitesentinels.web.app import app

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def run_flask(port):
    # Run Flask server silently without debug reload
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)

def main():
    port = find_free_port()
    
    # Start Flask in background thread
    server_thread = threading.Thread(target=run_flask, args=(port,), daemon=True)
    server_thread.start()
    
    # Wait for Flask to bind
    url = f"http://127.0.0.1:{port}/security/dashboard"
    for _ in range(30):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                break
        except Exception:
            time.sleep(0.1)

    # Launch native desktop application window
    # No browser URL bar, no localhost text visible to client
    window = webview.create_window(
        title="NiteSentinel Enterprise - Cyber Security & Vulnerability Assessment Platform",
        url=url,
        width=1380,
        height=880,
        min_size=(1024, 700),
        confirm_close=False,
    )
    
    webview.start(private_mode=False)

if __name__ == "__main__":
    main()
