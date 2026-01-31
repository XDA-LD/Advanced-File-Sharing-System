#This file is the combined work of Enzo Lindauer Lui-ji Daou,and Olexandr Ghanem

from datetime import datetime
import threading
import os

lock = threading.Lock()
LOG_FILE = "ClientLog.txt"

def log(user_name, action, details=""):
    """Logs an action to the client log file with thread safety."""
    with lock:
        curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        try:

            with open(LOG_FILE, "a", encoding='utf-8') as file:
                log_entry = f"[{curr_time}] User:'{user_name or 'N/A'}' Action:'{action}'"
                if details:
                    log_entry += f" Details:'{details}'"
                log_entry += "\n"
                file.write(log_entry)
        except Exception as e:

            print(f"CRITICAL: Error writing to client log file '{LOG_FILE}': {e}", file=os.sys.stderr)
