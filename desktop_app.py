import os
import sys
import time
import socket
import threading
import ctypes
import webview
from nitesentinels.web.app import app

APP_ID = "nitechspark.nitesentinel.enterprise.1.0"
ICON_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "nitesentinel.ico"))

def setup_windows_branding():
    """Configure Windows AppUserModelID and window icons to replace Python branding."""
    if sys.platform != "win32":
        return

    try:
        # Prevents Windows from grouping under Python on the Taskbar
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except Exception:
        pass

    def _apply_icon_loop():
        user32 = ctypes.windll.user32
        # Load small (16x16 for top-left titlebar) and big (32x32 for taskbar / Alt+Tab) icons
        # IMAGE_ICON = 1, LR_LOADFROMFILE = 0x0010
        h_icon_small = user32.LoadImageW(0, ICON_PATH, 1, 16, 16, 0x0010)
        h_icon_big = user32.LoadImageW(0, ICON_PATH, 1, 32, 32, 0x0010)

        for _ in range(50):
            time.sleep(0.15)
            found = False

            def enum_proc(hwnd, lparam):
                nonlocal found
                length = user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buff = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buff, length + 1)
                    if "NiteSentinel" in buff.value:
                        # WM_SETICON = 0x0080
                        # ICON_SMALL = 0, ICON_BIG = 1
                        if h_icon_small:
                            user32.SendMessageW(hwnd, 0x0080, 0, h_icon_small)
                        if h_icon_big:
                            user32.SendMessageW(hwnd, 0x0080, 1, h_icon_big)
                        found = True
                return True

            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
            user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
            if found:
                break

    threading.Thread(target=_apply_icon_loop, daemon=True).start()


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run_flask(port):
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)


def main():
    setup_windows_branding()
    port = find_free_port()

    # Start Flask backend in daemon thread
    server_thread = threading.Thread(target=run_flask, args=(port,), daemon=True)
    server_thread.start()

    # Direct loopback route that auto-authenticates local admin session and loads Dashboard
    url = f"http://127.0.0.1:{port}/desktop-auth"

    for _ in range(40):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                break
        except Exception:
            time.sleep(0.1)

    # Launch native desktop application window
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
