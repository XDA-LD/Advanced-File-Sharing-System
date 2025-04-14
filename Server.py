import db_handler
total_logs = ""




"""
------------------------------------
MAIN THREAD: FOR CONNECTION INITIATION
------------------------------------
"""


from socket import *
serverPort = 12000
serverSocket = socket(AF_INET,SOCK_STREAM)
serverSocket.bind(('',serverPort))
serverSocket.listen(1)

print('The server is ready to receive')
while True:
    clientSocket, addr = serverSocket.accept()

    
    clientSocket.close()

serverSocket.close()



"""
------------------------------------
MANY THREADS: FOR SERVICE HANDLING
------------------------------------
"""

# session_key = None

# ```python
# While True:
#     choice = receive(...)
#     if choice == "UploadFiles":
#         UploadFiles(...)
#     ...
#     elif choice == "Case i":
#     caseI(...)
#     ...
#     else:
#     closeConnection(...)
#     break;
# ```

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


