#import db_handler
#from db_handler import isAdmin
import threading
import sys

total_logs = ""

"""
------------------------------------
MANY THREADS: FOR SERVICE HANDLING
------------------------------------
"""
def clientHandler(clientSocket, addr):

    #TEMPORARY VARIABLE
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




# def uploadFiles(...):


# def etc etc():
# - Menu
# - List available Files
# - Download File
# - Upload File


#def fileIntegrityCheck(...):

"""
------------------------------------
MAIN THREAD: FOR CONNECTION INITIATION
------------------------------------
"""

from socket import *

serverPort = 12345
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('', serverPort))
serverSocket.listen(1)

print('The server is ready to receive')
try:
    while True:
        clientSocket, addr = serverSocket.accept()
        print(f"Connection from {addr}")

        thread = threading.Thread(target= clientHandler, args=(clientSocket, addr))
        thread.start()

except KeyboardInterrupt:
    print("\nServer is shutting down...")
finally:
    serverSocket.close()


