

# def sendChoice():
#     try:
#         send(bytes)
#     catch:



"""
------------------------------------
MAIN THREAD: FOR GUI
------------------------------------
"""
from socket import *

serverName = '127.0.0.1'
serverPort = 12345
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName, serverPort))


# DO GUI STUFF AND CALL NON-GUI METHODS


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


