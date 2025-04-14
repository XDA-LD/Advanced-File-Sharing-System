import hashlib
import socket
import threading
from socket import *

"""
------------------------------------
MANY THREADS: FOR SERVICE HANDLING
------------------------------------
"""


def clientHandler(clientSocket, addr):
    # TEMPORARY VARIABLE
    isAdmin = 0

    clientSocket.send(str(isAdmin).encode())
    print("The server has sent ", isAdmin)
    while True:

        choice = clientSocket.recv(1024).decode()

        if choice == "UploadFiles":
            print("files will be uploaded here")
        elif choice == "DownloadFiles":
            print("Files will be downloaded")
        elif choice == "ListFiles":
            print("The files will be displayed")
        elif choice == "DeleteFiles":
            print("The files will be deleted")
        elif choice == "CheckLogs":
            print("The log will be displayed")
        else:
            print("Invalid Input")


"""
------------------------------------
HELPER METHODS
------------------------------------
"""


def uploadFile(client_socket, address):
    """Handles receiving a file upload from a client."""


def downloadFile(client_socket, address):
    """Handles sending a requested file to a client."""
    pass


def listAvailableFiles(client_socket, address):
    """Sends the list of available files to the client."""
    pass


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


"""
------------------------------------
MAIN THREAD: FOR CONNECTION INITIATION
------------------------------------
"""


def startServer():
    """Initializes the server socket and enters the main accept loop."""
    serverPort = 12345
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
    # db_connection = db_handler.create_connection()
    startServer()
