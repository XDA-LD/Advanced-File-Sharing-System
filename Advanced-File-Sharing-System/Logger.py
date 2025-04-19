from datetime import datetime
import threading

lock = threading.Lock()
def log(file_name, user_name, action):
    # action can be uploaded, deleted, downloaded
    with lock:
        curr_time = datetime.now()
        file = open("Log.txt", "a")
        if not file_name == "":

            message = f"{action} by user {user_name} at time: {curr_time}\n"
        else:

            message = f"File {file_name} {action} by user {user_name} at time: {curr_time}\n"
        file.write(message)
        file.close()