
import socket
import hashlib
import os
from socket import *
class Client:
    def __init__(self):
        self.serverName = '127.0.0.1'
        self.serverPort = 12344
        self.serverSocket = None
        self.connected = False

    def connectToServer(self):
        """Establishes connection to the server."""
        if not self.connected:
            try:
                self.serverSocket = socket(AF_INET, SOCK_STREAM)
                self.serverSocket.connect((self.serverName, self.serverPort))
                self.connected = True
                return True
            except Exception as e:
                print(f"Connection error: {e}")
                return False
        return True

    def sendChoice(self, choice):
        """Sends a command string to the server."""
        if not self.connected:
            if not self.connectToServer():
                return False

        try:
            self.serverSocket.send(choice.encode())
            return True
        except Exception as e:
            print(f"Error sending choice: {e}")
            self.connected = False
            return False

    def disconnectFromServer(self):
        """Closes the client socket connection."""
        if self.connected and self.serverSocket:
            try:
                self.serverSocket.close()
                self.connected = False
            except Exception as e:
                print(f"Error disconnecting: {e}")


    def uploadFileAction(self, file_path, original_filename, username):
        #return True
        """Coordinates the file upload process with the server."""
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return False

        if not self.connected:
            if not self.connectToServer():
                return False

        try:
            # Send upload command
            self.sendChoice("UploadFiles")

            # Send filename
            self.serverSocket.send(original_filename.encode())

            # Send username
            self.serverSocket.send(username.encode())

            # Get file size
            file_size = os.path.getsize(file_path)
            print(file_size, type(file_size))
            self.serverSocket.send(str(file_size).encode())

            # Calculate and send checksum
            # checksum = getChecksum(file_path)
            # print(checksum)
            # self.serverSocket.send(checksum.encode())

            print(file_path, type(file_path))
            self.serverSocket.send(file_path.encode())

            # Send the file content
            with open(file_path, 'rb') as file:
                bytes_sent = 0
                while bytes_sent < file_size:
                    # Read the file in chunks of 4096 bytes
                    chunk = file.read(4096)
                    if not chunk:
                        break
                    self.serverSocket.send(chunk)
                    bytes_sent += len(chunk)

            # Get confirmation from server
            confirmation = self.serverSocket.recv(1024).decode()
            return confirmation == "SUCCESS"

        except Exception as e:
            print(f"Error uploading file: {e}")
            self.connected = False
            return False

    def downloadFileAction(self, file_name, save_path): #how are you getting the path?
        #return True
        """Coordinates the file download process with the server."""
        if not self.connected:
            if not self.connectToServer():
                return False

        try:
            # Send download command
            self.sendChoice("DownloadFiles")

            # Send the filename to download
            self.serverSocket.send(file_name.encode())

            # Receive file size
            file_size_str = self.serverSocket.recv(1024).decode()
            if file_size_str == "FILE_NOT_FOUND":
                print(f"File not found on server: {file_name}")
                return False

            file_size = int(file_size_str)

            # Receive checksum
            expected_checksum = self.serverSocket.recv(1024).decode()

            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Receive and save the file
            with open(save_path, 'wb') as file:
                bytes_received = 0
                while bytes_received < file_size:
                    # Receive the file in chunks
                    chunk = self.serverSocket.recv(min(4096, file_size - bytes_received))
                    if not chunk:
                        break
                    file.write(chunk)
                    bytes_received += len(chunk)

            # Verify checksum
            actual_checksum = getChecksum(save_path)
            if actual_checksum != expected_checksum:
                self.serverSocket.send("Failed".encode())
                print(f"Checksum verification failed. Expected: {expected_checksum}, Got: {actual_checksum}")
                os.remove(save_path)  # Remove corrupted file
                return False

            self.serverSocket.send("Confirmed".encode())
            return True

        except Exception as e:
            print(f"Error downloading file: {e}")
            self.connected = False
            return False

    def checkLogAction(self):
        if not self.connected:
            if not self.connectToServer():
                return ["Connection error"]
        try:
            self.sendChoice("CheckLogs")

            isAdmin = self.serverSocket.recv(1024)

            if isAdmin == "True":

                file_size = self.serverSocket.recv(1024)
                file_size = int(file_size)

                log_content = self.serverSocket.recv(file_size)
                return log_content
            else:

                return "NOT AN ADMIN"



        except Exception as e:
            print(f"Error loggin")
            self.connected = False
            # For testing, return dummy files if server connection fails
            return "The log is empty"
    def listAllFiles(self):
        #return ["HAha.png", "no.pdf"]
        """Requests and displays the list of files from the server."""
        if not self.connected:
            if not self.connectToServer():
                return ["Connection error"]

        try:
            # Send list files command
            self.sendChoice("ListFiles")

            # Receive number of files
            num_files_str = self.serverSocket.recv(1024).decode()
            try:
                num_files = int(num_files_str)
            except ValueError:
                print(f"Invalid response from server: {num_files_str}")
                return ["Server error"]

            # Receive file names
            files = []
            for _ in range(num_files):
                file_name = self.serverSocket.recv(1024).decode()
                files.append(file_name)

            return files

        except Exception as e:
            print(f"Error listing files: {e}")
            self.connected = False
            # For testing, return dummy files if server connection fails
            return ["dummy1.pdf", "dummy2.pdf", "dummy3.pdf"]

    def deleteFile(self, filename):
        #return True
        """Sends a request to delete a file on the server."""
        if not self.connected:
            if not self.connectToServer():
                return False

        try:
            # Send delete command
            self.sendChoice("DeleteFiles")

            # Send the filename to delete
            self.serverSocket.send(filename.encode())

            # Receive confirmation
            response = self.serverSocket.recv(1024).decode()
            return response == "SUCCESS"

        except Exception as e:
            print(f"Error deleting file: {e}")
            self.connected = False
            return False

    def login(self, username, password):
        #return True
        """Authenticates user with the server."""
        try:
            # Send login command
            self.sendChoice("Login")
            print(f"Sending username: {username}")
            print(f"Sending password: {password}")
            # Send username and password
            self.serverSocket.send(username.encode())
            self.serverSocket.send(password.encode())

            # Get authentication result
            result = self.serverSocket.recv(1024).decode()
            return result == "SUCCESS"

        except Exception as e:
            print(f"Login error: {e}")
            self.connected = False
            # For testing purposes, allow simple login
            return username == password

"""
------------------------------------
      START     : HELPER FUNCTIONS :
------------------------------------
"""


def getChecksum(file_path):
    """Verifies file integrity using a checksum."""
    hash_func = getattr(hashlib, "md5")()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()


"""
------------------------------------
       END      : HELPER FUNCTIONS :
------------------------------------
"""
