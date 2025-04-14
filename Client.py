

# def sendChoice():
#     try:
#         send(bytes)
#     catch:

# DO GUI STUFF AND CALL NON-GUI METHODS
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


"""
------------------------------------
MANY THREADS: FOR SERVICE HANDLING
------------------------------------
"""

# def uploadFiles(...):


# def etc etc():
# - List available Files
# - Download File
# - Upload File


# def fileIntegrityCheck(...):


"""
------------------------------------
MAIN THREAD: FOR GUI
------------------------------------
"""
from socket import *

#from db_handler import isAdmin

serverName = '127.0.0.1'
serverPort = 12345
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))

isAdmin = clientSocket.recv(1024)

if isAdmin == "0":

    userMenu(clientSocket)
else:

    adminMenu(clientSocket)


