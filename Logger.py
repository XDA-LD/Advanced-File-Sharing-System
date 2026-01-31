#This file is the combined work of Enzo Lindauer Lui-ji Daou,and Olexandr Ghanem


from datetime import datetime
import threading
import os # To check if file exists

lock = threading.Lock()
LOG_FILE = "Log.txt"

def log(file_name, user_name, action):
    """Logs an action to the log file with thread safety."""

    with lock:
        curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        try:

            with open(LOG_FILE, "a", encoding='utf-8') as file:

                if file_name:
                    message = f"[{curr_time}] User:'{user_name}' Action:'{action}' File:'{file_name}'\n"
                else:
                    message = f"[{curr_time}] User:'{user_name}' Action:'{action}'\n"
                file.write(message)
        except Exception as e:

            print(f"CRITICAL: Error writing to log file '{LOG_FILE}': {e}", file=os.sys.stderr)
