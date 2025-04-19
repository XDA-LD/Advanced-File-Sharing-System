from datetime import datetime
import threading
import os # To check if file exists

lock = threading.Lock()
LOG_FILE = "Log.txt"

def log(file_name, user_name, action):
    """Logs an action to the log file with thread safety."""
    # action can be Uploaded, Deleted, Downloaded, Logged in, Login Failed, etc.
    with lock:
        curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] # Format time
        try:
            # Use 'a' mode (append), create file if it doesn't exist
            with open(LOG_FILE, "a", encoding='utf-8') as file:
                # Corrected logic: Include filename if it's provided and relevant
                if file_name: # Check if file_name is not empty/None
                    message = f"[{curr_time}] User:'{user_name}' Action:'{action}' File:'{file_name}'\n"
                else: # Log actions without a specific file (like login)
                    message = f"[{curr_time}] User:'{user_name}' Action:'{action}'\n"
                file.write(message)
        except Exception as e:
            # Log errors to stderr if writing to file fails
            print(f"CRITICAL: Error writing to log file '{LOG_FILE}': {e}", file=os.sys.stderr)

# Example of ensuring the log file exists at startup (optional)
# def initialize_log():
#     with lock:
#         if not os.path.exists(LOG_FILE):
#             try:
#                 with open(LOG_FILE, "w", encoding='utf-8') as f:
#                     f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] Log file created.\n")
#             except Exception as e:
#                 print(f"CRITICAL: Failed to create log file '{LOG_FILE}': {e}", file=os.sys.stderr)
#
# initialize_log()