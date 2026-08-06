import threading
import subprocess
import sys
import os
import time
import webview

ROOT = os.path.dirname(__file__)
APP = os.path.join(ROOT, "dashboard", "app.py")

def run_streamlit():
    subprocess.run([
        sys.executable,
        "-m",
        "streamlit",
        "run",
        APP,
        "--server.headless=true"
    ])

threading.Thread(target=run_streamlit, daemon=True).start()

time.sleep(3)

webview.create_window(
    "MaxGuard",
    "http://localhost:8501",
    width=1400,
    height=900
)

webview.start()
