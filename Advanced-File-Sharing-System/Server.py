
import hashlib
import socket
import threading
from socket import *
import db_handler as db
import Logger
import os

"""
------------------------------------
MANY THREADS: FOR SERVICE HANDLING
------------------------------------
"""


def clientHandler(clientSocket, addr):
    # TEMPORARY VARIABLE
    isAdmin = False
    username = ""
    password = ""

    clientSocket.send(str(isAdmin).encode())
    print("The server has sent ", isAdmin)
    while True:

        choice = clientSocket.recv(1024).decode()

        if choice == "UploadFiles":
            response = uploadFile(clientSocket)
            clientSocket.send(response.encode())
        elif choice == "DownloadFiles":
            print("Files will be downloaded")
        elif choice == "ListFiles":
            listAvailableFiles(clientSocket)
        elif choice == "DeleteFiles":
            response = deleteFile(clientSocket, isAdmin, username)
            clientSocket.send(response.encode())
        elif choice == "CheckLogs":
            checkLog(clientSocket)
        elif choice == "Login":
            isAdmin, response, username, password = login(clientSocket)
            clientSocket.send(response.encode())
        else:
            print("Invalid Input")


"""
------------------------------------
HELPER METHODS
------------------------------------
"""
def checkLog(clientSocket, isAdmin):

    clientSocket.send(isAdmin.encode())
    if isAdmin:
        with open("Log.txt", "r") as file:

            log_content = file.read()
            clientSocket.send(str(len(log_content)).encode())
            clientSocket.send(log_content)

def uploadFile(clientSocket):
    """Handles receiving a file upload from a client."""
    print("entered upload file")
    filename = clientSocket.recv(1024).decode()
    print("received filename")

    username = clientSocket.recv(1024).decode()
    print("received username")

    file_size_str = clientSocket.recv(1024).decode()
    print(file_size_str, type(file_size_str))
    file_size = int(file_size_str)
    print("received file_size")

    # frontend_checksum = clientSocket.recv(1024).decode()
    # print("received checksum")
    file_path = clientSocket.recv(1024).decode()

    base_filename, file_extension = filename.rsplit('.', 1)
    file_extension = '.' + file_extension

    print(base_filename + "V1" + file_extension)

    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, 'wb') as file:
        bytes_received = 0
        while bytes_received < file_size:
            chunk = clientSocket.recv(min(4096, file_size - bytes_received))
            if not chunk:
                break
            file.write(chunk)
            bytes_received += len(chunk)

    backend_checksum = getChecksum(file_path)

    if backend_checksum:

        db.addfileDir(db_connection, base_filename + "V1" + file_extension, "V1", file_path, backend_checksum)
        return "SUCCESS"
    else:
        print(f"the checksums werent equal, backend: {backend_checksum}, frontend: {frontend_checksum}")
        os.remove(file_path)
        return "NOOOOO"

def downloadFile(clientSocket):
    """Handles sending a requested file to a client."""
    filename = clientSocket.recv(1024)
    file_path, expected_checksum = db.getFileDir(db_connection, filename, db.getFileVersion(db_connection, filename))

    file_size = os.path.getsize(file_path)
    clientSocket.send(str(file_size).encode())
    clientSocket.send(expected_checksum.encode())

    with open(file_path, 'rb') as file:
        bytes_sent = 0
        while bytes_sent < file_size:
            # Read the file in chunks of 4096 bytes
            chunk = file.read(4096)
            if not chunk:
                break
            clientSocket.send(chunk)
            bytes_sent += len(chunk)
    confirmation = clientSocket.recv(1024).decode()
    print(confirmation)

def deleteFile(clientSocket, isAdmin, username):

    filename = clientSocket.recv(1024).decode()
    base_filename, file_extension = filename.rsplit('.', 1)
    file_extension = '.' + file_extension
    if isAdmin:

        base_filename, version = extractVersion(base_filename)
        db.delFileDir(db_connection, base_filename, version)
        Logger.log(base_filename, username, "DeleteFiles")

        return "SUCCESS"
    else:
        return 'NOOOOOO'

def extractVersion(filename):
    version = ""
    for i in range(len(filename) - 1, -1, -1):
        if filename[i].isupper() and filename[i] == 'V':  # Looks for a capital V
            version = filename[i:]  # From 'V' onward
            filename = filename[:i]
            break
    return filename, version


def listAvailableFiles(clientSocket):
    """Sends the list of available files to the client."""
    files = db.listAllFiles(db_connection)
    file_nb = len(files)
    clientSocket.send(str(file_nb).encode())

    for file in files:
        clientSocket.send(file.encode())


def getChecksum(file_path):
    """Verifies file integrity using a checksum."""
    hash_func = getattr(hashlib, "md5")()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def receiveMessage(client_socket):
    """Reliably receives a message from the socket."""
    pass


def sendMessage(client_socket, message):
    """Reliably sends a message to the socket."""
    pass

def login(clientSocket):

    print("has entered login")

    username = clientSocket.recv(1024).decode()
    print("received username")
    password = clientSocket.recv(1024).decode()
    print("received username and password")
    if db.userExists(db_connection, username, password):

        isAdmin = db.isAdmin(db_connection, username, password)
        Logger.log("", username, "Logged in")
        return isAdmin, "SUCCESS", username, password
    else:

        return False, "NOOOOO", "", ""

"""
------------------------------------
MAIN THREAD: FOR CONNECTION INITIATION
------------------------------------
"""
def startServer():
    """Initializes the server socket and enters the main accept loop."""
    serverPort = 12344
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(('', serverPort))
    serverSocket.listen(1)

    print('The server is ready to receive')
    try:
        while True:
            clientSocket, addr = serverSocket.accept()
            print(f"Connection from {addr}")

            thread = threading.Thread(target=clientHandler, args=(clientSocket, addr))
            thread.start()

    except KeyboardInterrupt:
        print("\nServer is shutting down...")
    finally:
        serverSocket.close()


if __name__ == "__main__":
    db_connection = db.create_connection()
    startServer()
