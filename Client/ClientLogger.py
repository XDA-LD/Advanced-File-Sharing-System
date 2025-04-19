# ClientLogger.py
from datetime import datetime
import threading
import os

lock = threading.Lock()
LOG_FILE = "ClientLog.txt" # Name for the client-side log file

def log(user_name, action, details=""):
    """Logs an action to the client log file with thread safety."""
    # action can be Uploading, Upload Success, Upload Error, Downloading, Download Success, Download Error, etc.
    # details can include filename, error messages, etc.
    with lock:
        curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] # Format time
        try:
            # Use 'a' mode (append), create file if it doesn't exist
            with open(LOG_FILE, "a", encoding='utf-8') as file:
                log_entry = f"[{curr_time}] User:'{user_name or 'N/A'}' Action:'{action}'"
                if details:
                    log_entry += f" Details:'{details}'"
                log_entry += "\n"
                file.write(log_entry)
        except Exception as e:
            # Log errors to stderr if writing to file fails
            print(f"CRITICAL: Error writing to client log file '{LOG_FILE}': {e}", file=os.sys.stderr)
