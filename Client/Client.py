#This file is the combined work of Enzo Lindauer Lui-ji Daou,and Olexandr Ghanem

import socket
import hashlib
import os
import sys
import struct
from socket import AF_INET, SOCK_STREAM, SHUT_RDWR, timeout as socket_timeout
import ClientLogger # Import the new client logger

def send_msg(sock, msg):
    """Sends a message prefixed with its 4-byte length."""
    try:

        msg_bytes = msg.encode('utf-8')
        msg_len = len(msg_bytes)

        len_prefix = struct.pack('!I', msg_len)

        sock.sendall(len_prefix)
        sock.sendall(msg_bytes)
        return True
    except (Exception,OSError) as e:
        print(f"Unexpected error in send_msg: {e}")
        ClientLogger.log(None, "Send Error", f"Unexpected error: {e}") # Log error
        return False


def recv_msg(sock):
    """Receives a message prefixed with its 4-byte length."""
    try:

        len_prefix = recv_all(sock, 4)
        if not len_prefix:
            return None

        msg_len = struct.unpack('!I', len_prefix)[0]

        msg_bytes = recv_all(sock, msg_len)
        if not msg_bytes:
             return None

        return msg_bytes.decode('utf-8')
    except (Exception, OSError) as e:
        print(f"Unexpected error in recv_msg: {e}")
        ClientLogger.log(None, "Receive Error", f"Unexpected error: {e}") # Log error
        return None

"""
------------------------------------
HELPER METHODS 
------------------------------------
"""
def recv_all(sock, n):
    """Receives exactly n bytes from the socket."""
    data = bytearray()
    while len(data) < n:
        try:

            packet = sock.recv(n - len(data))
            if not packet:

                print("recv_all: Connection closed.")
                return None
            data.extend(packet)
        except OSError as e:
            print(f"Socket error in recv_all: {e}")
            return None
        except (Exception,OSError) as e:
            print(f"Unexpected error in recv_all: {e}")
            ClientLogger.log(None, "Receive Error", f"Unexpected recv_all error: {e}") # Log unexpected error
            return None
    return bytes(data)
"""
------------------------------------
HELPER METHODS - END
------------------------------------
"""

class Client:
    def __init__(self, server_ip='127.0.0.1', server_port=12344):
        self.serverName = server_ip
        self.serverPort = server_port
        self.serverSocket = None
        self.connected = False
        self.username = None

    def connectToServer(self):
        """Establishes connection to the server."""
        if self.connected:
            return True
        ClientLogger.log(self.username, "Connecting", f"Attempting to connect to {self.serverName}:{self.serverPort}")
        try:
            print(f"Attempting to connect to {self.serverName}:{self.serverPort}...")
            self.serverSocket = socket.socket(AF_INET, SOCK_STREAM)

            self.serverSocket.connect((self.serverName, self.serverPort))

            self.connected = True
            print("Connection successful.")
            ClientLogger.log(self.username, "Connection Success", f"Connected to {self.serverName}:{self.serverPort}")
            return True
        except socket_timeout:
             print("Connection attempt timed out.")
             ClientLogger.log(self.username, "Connection Error", "Timeout")
             self.serverSocket = None
             self.connected = False
             return False
        except Exception as e:
            print(f"Unexpected connection error: {e}")
            ClientLogger.log(self.username, "Connection Error", f"Unexpected Error: {e}")
            self.serverSocket = None
            self.connected = False
            return False

    def handleConnectionLoss(self):
         """Actions to take when connection is lost."""
         print("Connection lost.")
         ClientLogger.log(self.username, "Connection Lost") # Log connection loss
         self.connected = False
         if self.serverSocket:
             try: self.serverSocket.close()
             except: pass
         self.serverSocket = None
         self.username = None #Reset

    def disconnectFromServer(self):
        """Sends disconnect signal and closes the client socket connection."""
        print("Disconnecting from server...")
        ClientLogger.log(self.username, "Disconnecting")
        if self.connected and self.serverSocket:
            send_msg(self.serverSocket, "Disconnect")
            try:
                self.serverSocket.shutdown(SHUT_RDWR)
                self.serverSocket.close()
            except (Exception, OSError) as e:
                print(f"Unexpected error during disconnect: {e}")
                ClientLogger.log(self.username, "Disconnect Error", f"Unexpected error: {e}")
        self.connected = False
        self.serverSocket = None
        log_username = self.username # Keep username for logging before clearing
        self.username = None
        print("Disconnected.")
        ClientLogger.log(log_username, "Disconnected")

    def uploadFileAction(self, file_path, original_filename):
        """Coordinates the file upload process with logging."""
        if not self.username:
            print("Cannot upload: Not logged in.")
            ClientLogger.log(self.username, "Upload Error", "Not logged in")
            return False

        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            ClientLogger.log(self.username, "Upload Error", f"File not found: {original_filename}")
            return False

        ClientLogger.log(self.username, "Upload Started", f"File: {original_filename}, Path: {file_path}")
        print(f"Calculating checksum for {original_filename}...")
        local_checksum = getChecksum(file_path)
        if local_checksum is None:
             print("Error: Could not calculate checksum for local file.")
             ClientLogger.log(self.username, "Upload Error", f"Checksum calculation failed: {original_filename}")
             return False
        print(f"Local checksum: {local_checksum}")

        if not self.connected:
            if not self.connectToServer():
                ClientLogger.log(self.username, "Upload Error", "Connection failed before upload")
                return False

        upload_status = False
        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                 print("Cannot upload empty file.")
                 ClientLogger.log(self.username, "Upload Error", f"Empty file: {original_filename}")
                 return False

            print(f"Uploading '{original_filename}' ({file_size} bytes)...")

            if not send_msg(self.serverSocket, "UploadFiles"): return False # Error logged in send_msg
            if not send_msg(self.serverSocket, original_filename): return False
            if not send_msg(self.serverSocket, str(file_size)): return False
            if not send_msg(self.serverSocket, local_checksum): return False
            print("Sent metadata and checksum to server.")

            with open(file_path, 'rb') as file:
                bytes_sent = 0
                while bytes_sent < file_size:
                    chunk = file.read(4096)
                    if not chunk:
                        print("Error reading file chunk during upload.")
                        ClientLogger.log(self.username, "Upload Error", f"File read error during upload: {original_filename}")
                        return False
                    try:
                        self.serverSocket.sendall(chunk)
                        bytes_sent += len(chunk)
                    except OSError as e:
                        print(f"\nSocket error during file send: {e}")
                        ClientLogger.log(self.username, "Upload Error", f"Socket error during send: {e}")
                        self.handleConnectionLoss()
                        return False
            print(f"\nFile content sent. Waiting for confirmation...")

            confirmation = recv_msg(self.serverSocket)
            if confirmation is None:
                print("Connection error receiving confirmation.")
                ClientLogger.log(self.username, "Upload Error", "Connection lost waiting for confirmation")
                self.handleConnectionLoss()
                return False

            print(f"Server confirmation: {confirmation}")
            if confirmation == "SUCCESS":
                ClientLogger.log(self.username, "Upload Success", f"File: {original_filename}")
                upload_status = True
            elif confirmation == "ERROR_CHECKSUM_MISMATCH":
                 print("Upload failed: Server reported checksum mismatch.")
                 ClientLogger.log(self.username, "Upload Error", f"Checksum mismatch reported by server: {original_filename}")
            else:

                 ClientLogger.log(self.username, "Upload Error", f"Server error: {confirmation}, File: {original_filename}")

            return upload_status # True if SUCCESS

        except (Exception, OSError) as e:
            print(f"Error uploading file '{original_filename}': {e}")
            ClientLogger.log(self.username, "Upload Error", f"Unexpected error: {e}, File: {original_filename}")
            return False

    def downloadFileAction(self, file_name, save_path):
        """Coordinates the file download process with logging."""
        if not self.username:
            print("Cannot download: Not logged in.")
            ClientLogger.log(self.username, "Download Error", "Not logged in")
            return False
        if not self.connected:
            if not self.connectToServer():
                 ClientLogger.log(self.username, "Download Error", "Connection failed before download")
                 return False

        ClientLogger.log(self.username, "Download Started", f"File: {file_name}, Save Path: {save_path}")
        download_success_flag = False

        try:
            print(f"Requesting download for '{file_name}'...")
            if not send_msg(self.serverSocket, "DownloadFiles"): return False
            if not send_msg(self.serverSocket, file_name): return False

            str_file_size = recv_msg(self.serverSocket)
            if str_file_size is None:
                 print("Connection error receiving file size.")
                 ClientLogger.log(self.username, "Download Error", "Connection lost receiving file size")
                 self.handleConnectionLoss()
                 return False

            if str_file_size in ["FILE_NOT_FOUND", "FILE_NOT_FOUND_DISK", "DB_ERROR", "SERVER_ERROR"]:
                print(f"Server response: {str_file_size}")
                ClientLogger.log(self.username, "Download Error", f"Server error: {str_file_size}, File: {file_name}")
                return False

            try:
                file_size = int(str_file_size)
                print(f"Server reports file size: {file_size} bytes.")
            except ValueError:
                 print(f"Error: Invalid file size received from server: {str_file_size}")
                 ClientLogger.log(self.username, "Download Error", f"Invalid file size from server: {str_file_size}")
                 return False

            expected_checksum = recv_msg(self.serverSocket)
            if expected_checksum is None:
                 print("Connection error receiving checksum.")
                 ClientLogger.log(self.username, "Download Error", "Connection lost receiving checksum")
                 self.handleConnectionLoss()
                 return False
            elif len(expected_checksum) != 32 and expected_checksum != "":
                 print(f"Warning: Received potentially invalid checksum format from server: {expected_checksum}")
                 ClientLogger.log(self.username, "Download Warning", f"Invalid checksum format from server: {expected_checksum}")

            print(f"Server expects checksum: {expected_checksum or 'N/A'}")

            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            print(f"Receiving file to: {save_path}")
            bytes_received = 0
            with open(save_path, 'wb') as file:
                while bytes_received < file_size:
                    remaining_bytes = file_size - bytes_received
                    chunk_size = min(4096, remaining_bytes)
                    chunk = recv_all(self.serverSocket, chunk_size)
                    if chunk is None:
                        print("\nError: Connection lost or error during download.")
                        ClientLogger.log(self.username, "Download Error", "Connection lost during file transfer")
                        if os.path.exists(save_path): os.remove(save_path)
                        self.handleConnectionLoss()
                        return False
                    file.write(chunk)
                    bytes_received += len(chunk)

            print("\nFile received completely.")
            download_success_flag = True

            print("Calculating checksum for downloaded file...")
            actual_checksum = getChecksum(save_path)
            if actual_checksum is None:
                 print("Error: Could not calculate checksum for downloaded file.")
                 ClientLogger.log(self.username, "Download Error", f"Checksum calculation failed: {save_path}")
                 return False

            print(f"Downloaded file checksum: {actual_checksum}")

            if actual_checksum == expected_checksum:
                 print("Checksum verification successful!")
                 ClientLogger.log(self.username, "Download Success", f"File: {file_name} (Checksum verified)")
                 return True
            else:
                 print("!!! CHECKSUM MISMATCH !!!")
                 print(f"Expected: {expected_checksum}")
                 print(f"Got:      {actual_checksum}")
                 ClientLogger.log(self.username, "Download Error", f"Checksum mismatch: Expected={expected_checksum}, Got={actual_checksum}, File={file_name}")
                 print("Downloaded file might be corrupted.")
                 try:
                     os.remove(save_path)
                     print(f"Deleted corrupted file: {save_path}")
                     ClientLogger.log(self.username, "Download Cleanup", f"Deleted corrupted file: {save_path}")
                 except OSError as e:
                     print(f"Error deleting corrupted file {save_path}: {e}")
                     ClientLogger.log(self.username, "Download Error", f"Failed to delete corrupted file {save_path}: {e}")
                 return False

        except (Exception, OSError) as e:
            print(f"Error downloading file '{file_name}': {e}")
            ClientLogger.log(self.username, "Download Error", f"Unexpected error: {e}, File: {file_name}")
            if download_success_flag and os.path.exists(save_path): # Cleanup
                 try: os.remove(save_path)
                 except: pass
            return False

    def checkLogAction(self):
        """Requests server log, logging the action."""
        if not self.username:
             print("Cannot check logs: Not logged in.")
             ClientLogger.log(self.username, "CheckLog Error", "Not logged in")
             return "Login Required"
        if not self.connected:
            if not self.connectToServer():
                ClientLogger.log(self.username, "CheckLog Error", "Connection failed")
                return "Connection Error"

        ClientLogger.log(self.username, "CheckLog Started")
        try:
            print("Requesting logs...")
            if not send_msg(self.serverSocket, "CheckLogs"): return "Connection Error"

            isAdmin_str = recv_msg(self.serverSocket)
            if isAdmin_str is None:
                ClientLogger.log(self.username, "CheckLog Error", "Connection lost receiving admin status")
                self.handleConnectionLoss()
                return "Connection Error"
            print(f"Received admin status response: {isAdmin_str}") # Debugging

            if isAdmin_str == "True":
                print("Admin access granted by server. Receiving log size...")
                log_size_str = recv_msg(self.serverSocket)
                if log_size_str is None:
                    ClientLogger.log(self.username, "CheckLog Error", "Connection lost receiving log size")
                    self.handleConnectionLoss()
                    return "Connection Error"
                try:
                    log_size = int(log_size_str)
                    print(f"Received log size: {log_size}")
                except ValueError:
                    print(f"Invalid log size received: {log_size_str}")
                    ClientLogger.log(self.username, "CheckLog Error", f"Invalid log size from server: {log_size_str}")
                    return "Error: Invalid size from server"

                if log_size == 0:
                    ClientLogger.log(self.username, "CheckLog Success", "Log file empty or inaccessible")
                    return "Log file is empty or inaccessible on server."

                print("Receiving log content...")
                log_content_bytes = recv_all(self.serverSocket, log_size)
                if log_content_bytes is None:
                    print("Error: Connection lost or error while receiving log.")
                    ClientLogger.log(self.username, "CheckLog Error", "Connection lost receiving log content")
                    self.handleConnectionLoss()
                    return "Error: Incomplete log received"

                print("Log content received.")
                log_content = log_content_bytes.decode('utf-8', errors='ignore')
                ClientLogger.log(self.username, "CheckLog Success", f"Received {log_size} bytes")
                return log_content

            elif isAdmin_str == "False":
                print("Server denied access: Not an admin.")
                ClientLogger.log(self.username, "CheckLog Denied", "Not an admin")
                return "ACCESS_DENIED: You are not an admin."
            else:
                print(f"Unexpected admin status from server: {isAdmin_str}")
                ClientLogger.log(self.username, "CheckLog Error", f"Unexpected admin status from server: {isAdmin_str}")
                return f"Error: Unexpected server response ({isAdmin_str})"

        except (Exception, OSError) as e:
            print(f"Error checking log: {e}")
            ClientLogger.log(self.username, "CheckLog Error", f"Unexpected error: {e}")
            return f"Error during log check: {e}"

    def listAllFiles(self):
        """Requests file list with details, logging the action.""" # Updated docstring
        if not self.username:
             print("Cannot list files: Not logged in.")
             ClientLogger.log(self.username, "ListFiles Error", "Not logged in")

             return []
        if not self.connected:
            if not self.connectToServer():
                ClientLogger.log(self.username, "ListFiles Error", "Connection failed")
                return []

        ClientLogger.log(self.username, "ListFiles Started")
        files_details = [] # Store list of dictionaries
        try:
            print("Requesting file list...")
            if not send_msg(self.serverSocket, "ListFiles"): return [] # Return empty list on error

            num_files_str = recv_msg(self.serverSocket)
            if num_files_str is None:
                ClientLogger.log(self.username, "ListFiles Error", "Connection lost receiving file count")
                self.handleConnectionLoss()
                return []
            try:
                num_files = int(num_files_str)
                print(f"Server reports {num_files} files.")
            except ValueError:
                print(f"Invalid file count received: {num_files_str}")
                ClientLogger.log(self.username, "ListFiles Error", f"Invalid file count: {num_files_str}")
                return []

            for i in range(num_files):
                details_str = recv_msg(self.serverSocket)
                if details_str is None:
                    print(f"Connection error receiving file details #{i+1}")
                    ClientLogger.log(self.username, "ListFiles Error", f"Connection lost receiving file details #{i+1}")
                    self.handleConnectionLoss()
                    break # Stop trying to receive more details

                print(f"Received details string #{i+1}: {details_str}")

                try:
                    parts = details_str.split('\t')
                    if len(parts) == 3:
                        file_info = {
                            'name': parts[0],
                            'size': parts[1],
                            'timestamp': parts[2]
                        }
                        files_details.append(file_info)
                    else:
                         # Handle unexpected format
                         print(f"Warning: Received malformed details string: {details_str}")
                         file_info = {'name': details_str, 'size': 'N/A', 'timestamp': 'N/A'}
                         files_details.append(file_info)

                except Exception as e:
                    print(f"Error parsing details string '{details_str}': {e}")
                    # Add a placeholder if parsing fails
                    file_info = {'name': 'Parse Error', 'size': 'N/A', 'timestamp': 'N/A'}
                    files_details.append(file_info)


            print("Finished receiving file details list.")
            ClientLogger.log(self.username, "ListFiles Success", f"Received details for {len(files_details)} files")
            return files_details

        except OSError as e:
            print(f"Socket error listing files: {e}")
            ClientLogger.log(self.username, "ListFiles Error", f"Socket error: {e}")
            self.handleConnectionLoss()
            return []
        except Exception as e:
            print(f"Error listing files: {e}")
            ClientLogger.log(self.username, "ListFiles Error", f"Unexpected error: {e}")
            return []

    def deleteFile(self, filename):
        """Requests file deletion, logging the action."""
        if not self.username:
             print("Cannot delete: Not logged in.")
             ClientLogger.log(self.username, "Delete Error", "Not logged in")
             return False
        if not self.connected:
            if not self.connectToServer():
                ClientLogger.log(self.username, "Delete Error", "Connection failed")
                return False

        ClientLogger.log(self.username, "Delete Started", f"File: {filename}")
        try:
            print(f"Requesting to delete '{filename}'...")
            if not send_msg(self.serverSocket, "DeleteFiles"): return False
            if not send_msg(self.serverSocket, filename): return False

            response = recv_msg(self.serverSocket)
            if response is None:
                ClientLogger.log(self.username, "Delete Error", "Connection lost waiting for response")
                self.handleConnectionLoss()
                return False
            print(f"Server delete response: {response}")

            if response == "SUCCESS":
                ClientLogger.log(self.username, "Delete Success", f"File: {filename}")
                return True
            else:
                ClientLogger.log(self.username, "Delete Error", f"Server error: {response}, File: {filename}")
                return False

        except OSError as e:
            print(f"Socket error deleting file: {e}")
            ClientLogger.log(self.username, "Delete Error", f"Socket error: {e}")
            self.handleConnectionLoss()
            return False
        except Exception as e:
            print(f"Error deleting file '{filename}': {e}")
            ClientLogger.log(self.username, "Delete Error", f"Unexpected error: {e}, File: {filename}")
            return False

    def login(self, username_in, password_in):
        """Authenticates user, logging the action."""

        current_log_user = self.username if self.connected else None
        ClientLogger.log(current_log_user, "Login Started", f"Attempting login for user: {username_in}")

        if not self.connected:
            if not self.connectToServer():

                return False

        try:
            print(f"Attempting login for user '{username_in}'...")
            if not send_msg(self.serverSocket, "Login"): return False
            if not send_msg(self.serverSocket, username_in): return False
            if not send_msg(self.serverSocket, password_in): return False # Don't log password

            result = recv_msg(self.serverSocket)
            if result is None:
                 print("Connection error receiving login response.")
                 ClientLogger.log(username_in, "Login Error", "Connection lost receiving response")
                 self.handleConnectionLoss()
                 return False
            print(f"Server login response: {result}")

            if result == "SUCCESS":
                 self.username = username_in
                 print(f"Login successful as '{self.username}'.")
                 ClientLogger.log(self.username, "Login Success")
                 return True
            else:
                 print(f"Login failed (Server response: {result}).")
                 ClientLogger.log(username_in, "Login Failed", f"Server response: {result}")
                 self.username = None
                 return False

        except (Exception, OSError) as e:
            print(f"Login error: {e}")
            ClientLogger.log(username_in, "Login Error", f"Unexpected error: {e}")
            self.username = None
            return False

"""
------------------------------------
      START     : HELPER FUNCTIONS : (Checksum)
------------------------------------
"""

def getChecksum(file_path):
    """Calculates MD5 checksum for a file."""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
         print(f"Error calculating checksum: File not found at {file_path}")

         return None
    except Exception as e:
         print(f"Error calculating checksum for {file_path}: {e}")

         return None

"""
------------------------------------
       END      : HELPER FUNCTIONS :
------------------------------------
"""
