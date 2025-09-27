# streamlit_checkexe.py

import streamlit.web.cli as stcli
import sys
import os
import socket

def find_available_port(start_port):
    """Finds an available port starting from start_port."""
    port = start_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("localhost", port))
                return port
            except OSError:
                port += 1

if __name__ == "__main__":
    # Handle both one-file and one-folder PyInstaller builds
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_dir = sys._MEIPASS
    else:
        # Fallback for when not running as a frozen executable
        base_dir = os.path.dirname(os.path.abspath(__file__))

    # Switch to the base directory so Streamlit can find files
    os.chdir(base_dir)

    # Get the absolute path to the main Streamlit application script
    app_script_path = os.path.join(base_dir, "harmony.py")
    
    port = find_available_port(8502)

    # Print the port number for the parent process (Electron)
    if sys.stdout:
        print(f"STREAMLIT_PORT:{port}")
        sys.stdout.flush()
        
    sys.argv = [
        "streamlit",
        "run",
        app_script_path,
        f"--server.port={port}",
        "--server.headless=true",  # Add a comma here to fix concatenation
        "--global.developmentMode=false"
    ]
    sys.exit(stcli.main())