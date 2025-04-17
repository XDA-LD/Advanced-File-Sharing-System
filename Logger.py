from datetime import datetime


def log(file_name, user_name, action):
    # action can be uploaded, deleted, downloaded
    curr_time = datetime.now()
    message = f"File {file_name} {action} by user {user_name} at time: {curr_time}"
    file = open("Log.txt", "a")
    file.write(message)
    file.close()


