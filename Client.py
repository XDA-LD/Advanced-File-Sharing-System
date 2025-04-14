import socket
import threading
import hashlib
import os
from socket import *

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

# Global State
client_socket = None
is_connected = False


def connect_to_server(host=SERVER_HOST, port=SERVER_PORT):
    """Establishes connection to the server."""
    pass


def send_choice(choice):
    """Sends a command string to the server."""
    pass


def receive_message():
    """Receives a message string from the server."""
    pass


def disconnect_from_server():
    """Closes the client socket connection."""
    pass


def upload_file_action(file_path):
    """Coordinates the file upload process with the server."""
    pass


def download_file_action(file_name, save_path):
    """Coordinates the file download process with the server."""
    pass


def list_available_files_action():
    """Requests and potentially displays the list of files from the server."""
    pass


def getChecksum(file_path):
    """Verifies file integrity using a checksum."""
    hash_func = getattr(hashlib, "md5")()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def console_ui_loop():
    """Basic console interface for client actions."""
    pass


"""
------------------------------------
HELPER FUNCTIONS:
------------------------------------
"""


def userMenu(clientSocket):
    while True:
        print("1: List available files")
        print("2: Upload a file")
        print("3: Download a file")
        print("----------------------------------------")
        choice = input("Enter your choice")

        if choice == "1":
            clientSocket.send("ListFiles".encode())
        elif choice == "2":
            clientSocket.send("UploadFiles".encode())
        elif choice == "3":
            clientSocket.send("DownloadFiles".encode())
        else:
            print("Invalid input")


def adminMenu(clientSocket):
    while True:

        print("1: List available files")
        print("2: Upload a file")
        print("3: Download a file")
        print("4: Delete a file")
        print("5: Check the log")
        print("----------------------------------------")

        choice = input("Enter your choice")

        if choice == "1":

            clientSocket.send("ListFiles".encode())
        elif choice == "2":

            clientSocket.send("UploadFiles".encode())
        elif choice == "3":

            clientSocket.send("DownloadFiles".encode())
        elif choice == "4":

            clientSocket.send("DeleteFiles".encode())
        elif choice == "5":

            clientSocket.send("CheckLogs".encode())
        else:

            print("Invalid input")


def startApp():
    # Start UI
    serverName = '127.0.0.1'
    serverPort = 12345
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((serverName, serverPort))

    isAdmin = clientSocket.recv(1024)

    if isAdmin == "0":

        userMenu(clientSocket)
    else:

        adminMenu(clientSocket)


if __name__ == "__main__":
    startApp()