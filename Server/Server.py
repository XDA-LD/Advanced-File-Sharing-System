# import hashlib
# import socket
# import threading
# import os
# from socket import *
#
# # Define base directory for file storage
# BASE_DIR = "/"
# os.makedirs(BASE_DIR, exist_ok=True)
#
# # Simple user database (replace with a real database in production)
# users = {
#     'admin': 'admin',
#     'user': 'user'
# }
#
# """
# ------------------------------------
# MANY THREADS: FOR SERVICE HANDLING
# ------------------------------------
# """
#
#
# def clientHandler(clientSocket, addr):
#     """Handles client connections and processes commands."""
#     authenticated = False
#     current_user = None
#
#     print(f"Connection established with {addr}")
#
#     while True:
#         try:
#             choice = clientSocket.recv(1024).decode()
#
#             if not choice:
#                 print(f"Client {addr} disconnected")
#                 break
#
#             print(f"Received command from {addr}: {choice}")
#
#             # Login command doesn't require authentication
#             if choice == "Login":
#                 username = clientSocket.recv(1024).decode()
#                 password = clientSocket.recv(1024).decode()
#
#                 if username in users and users[username] == password:
#                     clientSocket.send("SUCCESS".encode())
#                     authenticated = True
#                     current_user = username
#                     print(f"User {username} logged in from {addr}")
#                 else:
#                     clientSocket.send("FAILURE".encode())
#                     print(f"Failed login attempt for user {username} from {addr}")
#                 continue
#
#             # All other commands require authentication
#             if not authenticated:
#                 clientSocket.send("NOT_AUTHENTICATED".encode())
#                 continue
#
#             if choice == "UploadFiles":
#                 uploadFile(clientSocket, addr, current_user)
#             elif choice == "DownloadFiles":
#                 downloadFile(clientSocket, addr, current_user)
#             elif choice == "ListFiles":
#                 listAvailableFiles(clientSocket, addr, current_user)
#             elif choice == "DeleteFiles":
#                 deleteFile(clientSocket, addr, current_user)
#             elif choice == "CheckLogs":
#                 # Only admin can check logs
#                 if current_user == "admin":
#                     print("The log will be displayed")
#                     # Implementation for logs display
#                 else:
#                     clientSocket.send("PERMISSION_DENIED".encode())
#             else:
#                 print(f"Invalid command received: {choice}")
#                 clientSocket.send("INVALID_COMMAND".encode())
#
#         except Exception as e:
#             print(f"Error handling client {addr}: {e}")
#             break
#
#     clientSocket.close()
#     print(f"Connection with {addr} closed")
#
#
# """
# ------------------------------------
# HELPER METHODS
# ------------------------------------
# """
#
#
# def uploadFile(client_socket, address, username):
#     """Handles receiving a file upload from a client."""
#     try:
#         # Receive filename
#         filename = client_socket.recv(1024).decode()
#
#         # Receive username (for verification)
#         received_username = client_socket.recv(1024).decode()
#         if received_username != username:
#             client_socket.send("UNAUTHORIZED".encode())
#             return
#
#         # Receive file size
#         file_size_str = client_socket.recv(1024).decode()
#         file_size = int(file_size_str)
#
#         # Receive checksum
#         expected_checksum = client_socket.recv(1024).decode()
#
#         # Create user directory if it doesn't exist
#         user_dir = os.path.join(BASE_DIR, username)
#         os.makedirs(user_dir, exist_ok=True)
#
#         file_path = os.path.join(user_dir, filename)
#
#         # Receive and save the file
#         with open(file_path, 'wb') as file:
#             bytes_received = 0
#             while bytes_received < file_size:
#                 # Receive the file in chunks
#                 chunk = client_socket.recv(min(4096, file_size - bytes_received))
#                 if not chunk:
#                     break
#                 file.write(chunk)
#                 bytes_received += len(chunk)
#
#         # Verify checksum
#         actual_checksum = getChecksum(file_path)
#         if actual_checksum != expected_checksum:
#             print(f"Checksum verification failed. Expected: {expected_checksum}, Got: {actual_checksum}")
#             os.remove(file_path)  # Remove corrupted file
#             client_socket.send("CHECKSUM_FAILED".encode())
#         else:
#             print(f"File {filename} successfully uploaded by {username}")
#             client_socket.send("SUCCESS".encode())
#
#     except Exception as e:
#         print(f"Error handling file upload from {address}: {e}")
#         client_socket.send("ERROR".encode())
#
#
# def downloadFile(client_socket, address, username):
#     """Handles sending a requested file to a client."""
#     try:
#         # Receive filename
#         filename = client_socket.recv(1024).decode()
#
#         # Check if file exists in user's directory
#         user_dir = os.path.join(BASE_DIR, username)
#         file_path = os.path.join(user_dir, filename)
#
#         if not os.path.exists(file_path):
#             client_socket.send("FILE_NOT_FOUND".encode())
#             return
#
#         # Get file size
#         file_size = os.path.getsize(file_path)
#         client_socket.send(str(file_size).encode())
#
#         # Calculate and send checksum
#         checksum = getChecksum(file_path)
#         client_socket.send(checksum.encode())
#
#         # Send the file content
#         with open(file_path, 'rb') as file:
#             bytes_sent = 0
#             while bytes_sent < file_size:
#                 # Read the file in chunks
#                 chunk = file.read(4096)
#                 if not chunk:
#                     break
#                 client_socket.send(chunk)
#                 bytes_sent += len(chunk)
#
#         print(f"File {filename} successfully downloaded by {username}")
#
#     except Exception as e:
#         print(f"Error handling file download for {address}: {e}")
#         try:
#             client_socket.send("ERROR".encode())
#         except:
#             pass
#
#
# def deleteFile(client_socket, address, username):
#     """Handles deletion of a file."""
#     try:
#         # Receive filename
#         filename = client_socket.recv(1024).decode()
#
#         # Check if file exists in user's directory
#         user_dir = os.path.join(BASE_DIR, username)
#         file_path = os.path.join(user_dir, filename)
#
#         if not os.path.exists(file_path):
#             client_socket.send("FILE_NOT_FOUND".encode())
#             return
#
#         # Delete the file
#         os.remove(file_path)
#         client_socket.send("SUCCESS".encode())
#         print(f"File {filename} successfully deleted by {username}")
#
#     except Exception as e:
#         print(f"Error handling file deletion for {address}: {e}")
#         client_socket.send("ERROR".encode())
#
#
# def listAvailableFiles(client_socket, address, username):
#     """Sends the list of available files to the client."""
#     try:
#         # Get files in user's directory
#         user_dir = os.path.join(BASE_DIR, username)
#         os.makedirs(user_dir, exist_ok=True)
#
#         files = [f for f in os.listdir(user_dir) if os.path.isfile(os.path.join(user_dir, f))]
#
#         # Send number of files
#         client_socket.send(str(len(files)).encode())
#
#         # Send each filename
#         for filename in files:
#             client_socket.send(filename.encode())
#             # Small delay to ensure messages don't get combined
#             import time
#             time.sleep(0.01)
#
#         print(f"File list sent to {username}")
#
#     except Exception as e:
#         print(f"Error sending file list to {address}: {e}")
#         try:
#             client_socket.send("0".encode())  # No files
#         except:
#             pass
#
#
# def getChecksum(file_path):
#     """Verifies file integrity using a checksum."""
#     hash_func = getattr(hashlib, "md5")()
#     with open(file_path, 'rb') as f:
#         for chunk in iter(lambda: f.read(4096), b''):
#             hash_func.update(chunk)
#     return hash_func.hexdigest()
#
#
# def receiveMessage(client_socket):
#     """Reliably receives a message from the socket."""
#     # Implementation would depend on specific protocol requirements
#     pass
#
#
# def sendMessage(client_socket, message):
#     """Reliably sends a message to the socket."""
#     # Implementation would depend on specific protocol requirements
#     pass
#
#
# """
# ------------------------------------
# MAIN THREAD: FOR CONNECTION INITIATION
# ------------------------------------
# """
#
#
# def startServer():
#     """Initializes the server socket and enters the main accept loop."""
#     serverPort = 12345
#     serverSocket = socket(AF_INET, SOCK_STREAM)
#     serverSocket.bind(('', serverPort))
#     serverSocket.listen(1)
#
#     print('The server is ready to receive connections on port', serverPort)
#     try:
#         while True:
#             clientSocket, addr = serverSocket.accept()
#             print(f"Connection from {addr}")
#
#             thread = threading.Thread(target=clientHandler, args=(clientSocket, addr))
#             thread.daemon = True  # Make thread exit when main thread exits
#             thread.start()
#
#     except KeyboardInterrupt:
#         print("\nServer is shutting down...")
#     finally:
#         serverSocket.close()
#
#
# if __name__ == "__main__":
#     startServer()