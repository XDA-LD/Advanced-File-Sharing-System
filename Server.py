import hashlib
import socket
import threading
import time

import db_handler as db  # Assuming db_handler is updated/standardized
import Logger
import os
import struct # Added

# --- Add Helper Functions Here ---
# Helper to send a length-prefixed message
def send_msg(sock, msg):
    """Sends a message prefixed with its 4-byte length."""
    try:
        # Encode message to bytes, get length
        msg_bytes = msg.encode('utf-8')
        msg_len = len(msg_bytes)
        # Pack length as 4-byte unsigned integer (!I means network byte order, unsigned int)
        len_prefix = struct.pack('!I', msg_len)
        # Send length prefix first, then the message
        sock.sendall(len_prefix)
        sock.sendall(msg_bytes)
        return True
    except OSError as e:
        print(f"Error sending message: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error in send_msg: {e}")
        return False

# Helper to receive a length-prefixed message
def recv_msg(sock):
    """Receives a message prefixed with its 4-byte length."""
    try:
        # Read the 4-byte length prefix
        len_prefix = recv_all(sock, 4)
        if not len_prefix:
            return None # Connection closed or error
        # Unpack length
        msg_len = struct.unpack('!I', len_prefix)[0]
        # Read exactly msg_len bytes for the message
        msg_bytes = recv_all(sock, msg_len)
        if not msg_bytes:
             return None # Connection closed or error during message read
        # Decode and return message string
        return msg_bytes.decode('utf-8')
    except OSError as e:
        print(f"Error receiving message length/data: {e}")
        return None
    except struct.error as e:
        print(f"Error unpacking message length: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error in recv_msg: {e}")
        return None


# Helper to ensure all requested bytes are received
def recv_all(sock, n):
    """Receives exactly n bytes from the socket."""
    data = bytearray()
    while len(data) < n:
        try:
            # Request remaining bytes
            packet = sock.recv(n - len(data))
            if not packet:
                # Connection closed prematurely
                print("recv_all: Connection closed.")
                return None
            data.extend(packet)
        except OSError as e: # Catch socket errors during recv
            print(f"Socket error in recv_all: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error in recv_all: {e}")
            return None
    return bytes(data)
# --- End Helper Functions ---


# --- Recommendation: Use a more robust way to manage this directory ---
SERVER_BASE_DIR = "server_storage"
os.makedirs(SERVER_BASE_DIR, exist_ok=True)

"""
------------------------------------
MANY THREADS: FOR SERVICE HANDLING
------------------------------------
"""

def clientHandler(clientSocket, addr):
    # Handler-specific state
    isAdmin = False
    username = ""
    password = ""
    db_connection_thread = None # Recommendation: Connection per thread

    try:
        # Recommendation: Create DB connection per thread
        db_connection_thread = db.create_connection()
        if not db_connection_thread:
            print(f"[{addr}] Could not establish database connection. Closing thread.")
            return

        print(f"[{addr}] Connection established.")

        while True:
            try:
                 # --- Use recv_msg to get the command reliably ---
                choice = recv_msg(clientSocket)
                if choice is None:
                    print(f"[{addr}] Client disconnected or error reading command.")
                    break # Exit loop

                print(f"[{addr}] Received choice: {choice}") # Debugging

                # --- Update handlers to use send_msg/recv_msg ---
                if choice == "UploadFiles":
                    # Modify uploadFile to use new helpers if needed for its protocol steps
                    response = uploadFile(clientSocket, db_connection_thread, username) # Pass username
                    send_msg(clientSocket, response) # Send response prefixed
                elif choice == "DownloadFiles":
                     # Modify downloadFile to use new helpers
                    downloadFile(clientSocket, db_connection_thread)
                elif choice == "ListFiles":
                     # Pass db_connection_thread
                    listAvailableFiles(clientSocket, db_connection_thread)
                elif choice == "DeleteFiles":
                    # Modify deleteFile to use new helpers
                    response = deleteFile(clientSocket, db_connection_thread, isAdmin, username)
                    send_msg(clientSocket, response) # Send response prefixed
                elif choice == "CheckLogs":
                    # Modify checkLog to use new helpers
                    checkLog(clientSocket, isAdmin)
                elif choice == "Login":
                    # login function now needs adapting internally
                    login_isAdmin, login_response, logged_in_username, logged_in_password = login(clientSocket, db_connection_thread)
                    if login_response == "SUCCESS":
                        # Update handler's state variables upon successful login
                        isAdmin = login_isAdmin
                        username = logged_in_username
                        password = logged_in_password
                        print(f"[{addr}] User '{username}' logged in. Admin: {isAdmin}") # Debugging
                    else:
                        print(f"[{addr}] Login failed.") # Debugging
                    # Send response using prefixing
                    send_msg(clientSocket, login_response)

                elif choice == "Disconnect": # Optional: Add a clean disconnect choice
                    print(f"[{addr}] Client requested disconnect.")
                    break
                else:
                    print(f"[{addr}] Invalid Input: {choice}")
                    # Optionally send an error to client using prefixing
                    send_msg(clientSocket, "INVALID_CHOICE")


            except ConnectionResetError:
                print(f"[{addr}] Client connection forcibly closed.")
                break
            except OSError as e: # Catch socket errors
                print(f"[{addr}] Socket error in handler loop: {e}")
                break
            except Exception as e:
                print(f"[{addr}] Error in handler loop: {e}")
                # Optionally send error using prefixing
                # try: send_msg(clientSocket, "SERVER_ERROR") catch: pass
                break # Exit loop on general error


    finally:
        print(f"[{addr}] Closing connection.")
        if db_connection_thread:
            try:
                db_connection_thread.close()
                print(f"[{addr}] DB connection closed.")
            except Exception as db_e:
                print(f"[{addr}] Error closing DB connection: {db_e}")
        try:
            clientSocket.close()
        except Exception as sock_e:
             print(f"[{addr}] Error closing client socket: {sock_e}")


"""
------------------------------------
HELPER METHODS (Updated for prefixing)
------------------------------------
"""
def checkLog(clientSocket, isAdmin):
    # Send admin status as a string FIRST (prefixed)
    if not send_msg(clientSocket, str(isAdmin)): return
    print(f"Sent isAdmin status: {isAdmin}") # Debugging

    if isAdmin:
        log_file_path = "Log.txt"
        try:
            if not os.path.exists(log_file_path):
                 print("Log file not found.")
                 send_msg(clientSocket, str(0)) # Send size 0 (prefixed)
                 return

            with open(log_file_path, "rb") as file: # Read as bytes
                log_content = file.read()
                log_size = len(log_content)
                print(f"Sending log file size: {log_size}") # Debugging

                # Send length first using prefixing
                if not send_msg(clientSocket, str(log_size)): return

                # Send content if size > 0 (raw bytes, no prefixing needed here)
                if log_size > 0:
                    clientSocket.sendall(log_content) # Use sendall for large files
                print("Log content sent.") # Debugging

        except FileNotFoundError:
            print("Log file not found during read attempt.")
            send_msg(clientSocket, str(0)) # Send size 0 (prefixed)
        except Exception as e:
            print(f"Error reading/sending log file: {e}")
            try:
                send_msg(clientSocket, str(0)) # Send size 0 on error (prefixed)
            except:
                 pass # Avoid crashing if socket is already closed
    else:
         print("Access denied for checkLog (not admin).") # Debugging


# In Server.py

# In Server.py

def uploadFile(clientSocket, db_connection, username):
    """Handles receiving a file upload, verifies checksum using prefixing for metadata."""
    if not username:
        print("Upload attempt failed: User not logged in.")
        return "ERROR_AUTH"

    server_file_path = None
    received_checksum = None # Store received checksum

    try:
        print(f"[{username}] Starting file upload process...")
        # Receive metadata using prefixing
        filename = recv_msg(clientSocket)
        if not filename: return "ERROR_FILENAME"
        print(f"[{username}] Received filename: {filename}")

        file_size_str = recv_msg(clientSocket)
        if not file_size_str: return "ERROR_SIZE"
        file_size = int(file_size_str)
        print(f"[{username}] Received file_size: {file_size}")
        if file_size <= 0: return "ERROR_SIZE"

        # --- FIX: Receive checksum (prefixed) ---
        received_checksum = recv_msg(clientSocket)
        if not received_checksum: return "ERROR_CHECKSUM"
        elif len(received_checksum) != 32: # Basic check for MD5 hex length
             print(f"Warning: Received potentially invalid checksum format from client: {received_checksum}")
             return "ERROR_CHECKSUM_FORMAT"
        print(f"[{username}] Received client checksum: {received_checksum}")

        # --- Construct server-side path ---
        user_dir = os.path.join(SERVER_BASE_DIR, username)
        os.makedirs(user_dir, exist_ok=True)
        secure_fname = os.path.basename(filename)
        server_file_path = os.path.join(user_dir, secure_fname)
        print(f"[{username}] Saving file to: {server_file_path}")

        # --- Receive file data (Raw, NOT prefixed) ---
        try:
            with open(server_file_path, 'wb') as file:
                bytes_received = 0
                while bytes_received < file_size:
                    chunk_size_to_read = min(4096, file_size - bytes_received)
                    chunk = recv_all(clientSocket, chunk_size_to_read)
                    if chunk is None:
                        print(f"[{username}] Error: Connection lost during file data transfer.")
                        if os.path.exists(server_file_path): os.remove(server_file_path)
                        return "ERROR_TRANSFER"
                    file.write(chunk)
                    bytes_received += len(chunk)
            print(f"[{username}] File received completely.")
        except OSError as e:
             print(f"[{username}] Error writing file to disk: {e}")
             if os.path.exists(server_file_path): os.remove(server_file_path)
             return "ERROR_DISK_WRITE"
        except Exception as e:
            print(f"[{username}] Unexpected error during file write: {e}")
            if os.path.exists(server_file_path): os.remove(server_file_path)
            return "ERROR_SERVER"

        # --- FIX: Calculate and Verify checksum ---
        print(f"[{username}] Calculating checksum for received file...")
        backend_checksum = getChecksum(server_file_path)
        if backend_checksum is None:
             print(f"[{username}] Error calculating checksum for received file.")
             if os.path.exists(server_file_path): os.remove(server_file_path)
             return "ERROR_CHECKSUM_CALC" # Server-side calc error

        print(f"[{username}] Server calculated checksum: {backend_checksum}")

        if backend_checksum == received_checksum:
             print(f"[{username}] Checksum verification SUCCESSFUL!")
        else:
             print(f"!!! [{username}] CHECKSUM MISMATCH !!!")
             print(f"  Client Sent: {received_checksum}")
             print(f"  Server Calc: {backend_checksum}")
             # Delete corrupted file and return specific error
             if os.path.exists(server_file_path):
                 try:
                     os.remove(server_file_path)
                     print(f"[{username}] Deleted corrupted upload: {server_file_path}")
                 except OSError as e:
                     print(f"[{username}] Error deleting corrupted upload {server_file_path}: {e}")
             return "ERROR_CHECKSUM_MISMATCH" # Specific error for client


        # --- Add file entry to database ---
        db_filename = secure_fname
        db_version = 1
        print(f"[{username}] Attempting to add file record to DB: Name='{db_filename}', Version={db_version}")
        db_success = db.addfileDir(db_connection, db_filename, db_version, server_file_path, backend_checksum) # Store backend checksum

        if db_success:
            print(f"[{username}] Database record added/updated successfully.")
            Logger.log(secure_fname, username, "Uploaded")
            return "SUCCESS"
        else:
            print(f"[{username}] FAILED to add database record.")
            # Maybe don't delete file if DB fails, but log error? Optional.
            # if os.path.exists(server_file_path): os.remove(server_file_path)
            return "ERROR_DB_INSERT"


    except ValueError:
        print(f"Error: Invalid file size received.")
        if server_file_path and os.path.exists(server_file_path): os.remove(server_file_path)
        return "ERROR_SIZE"
    except OSError as e: # Catch socket errors during metadata/checksum recv
        print(f"Socket error during upload metadata/checksum recv: {e}")
        if server_file_path and os.path.exists(server_file_path): os.remove(server_file_path)
        return "ERROR_SOCKET"
    except Exception as e:
        print(f"Error during file upload setup: {e}")
        if server_file_path and os.path.exists(server_file_path): os.remove(server_file_path)
        return "ERROR_SERVER"


def downloadFile(clientSocket, db_connection):
    """Handles sending a requested file, sending checksum first."""
    try:
        # Receive filename using prefixing
        filename_to_download = recv_msg(clientSocket)
        if not filename_to_download: return
        print(f"Received download request for: {filename_to_download}")

        # Retrieve file PATH and EXPECTED checksum from DB
        file_path, expected_checksum_from_db = db.getFileDir(db_connection, filename_to_download)

        # Check if path is valid and file exists on disk
        if not file_path or not os.path.exists(file_path):
            print(f"File not found (path invalid or file missing on disk): {file_path or filename_to_download}")
            send_msg(clientSocket, "FILE_NOT_FOUND")
            return

        # --- Optional: Re-calculate checksum before sending to ensure file hasn't changed ---
        # current_checksum = getChecksum(file_path)
        # if current_checksum is None:
        #      print(f"Error calculating checksum for file before download: {file_path}")
        #      send_msg(clientSocket, "ERROR_SERVER_CHECKSUM")
        #      return
        # if current_checksum != expected_checksum_from_db:
        #       print(f"WARNING: Checksum mismatch for {filename_to_download} between DB ({expected_checksum_from_db}) and current file ({current_checksum}). Sending current file checksum.")
        #       checksum_to_send = current_checksum
        # else:
        #       checksum_to_send = expected_checksum_from_db
        # Use the checksum stored in DB for consistency unless re-calc needed
        checksum_to_send = expected_checksum_from_db
        if not checksum_to_send:
            print(f"Warning: No checksum found in DB for {filename_to_download}. Cannot send checksum.")
            # Decide how to handle - maybe send an empty string or a specific code?
            # For now, try sending empty - client needs to handle this.
            checksum_to_send = ""


        # --- Send file size (Prefixed) ---
        file_size = os.path.getsize(file_path)
        if not send_msg(clientSocket, str(file_size)): return
        print(f"Sent file size: {file_size}")

        # --- FIX: Send checksum (Prefixed) ---
        if not send_msg(clientSocket, checksum_to_send): return
        print(f"Sent checksum: {checksum_to_send}")

        # --- Send file content (Raw, from file path, NOT prefixed) ---
        try:
            with open(file_path, 'rb') as file:
                bytes_sent = 0
                while bytes_sent < file_size:
                    chunk = file.read(4096)
                    if not chunk:
                        print(f"Error reading file chunk during download: {file_path}")
                        return
                    clientSocket.sendall(chunk)
                    bytes_sent += len(chunk)
            print("File content sent from path.")
            # --- Optional: Wait for client checksum confirmation ---
            # client_confirm = recv_msg(clientSocket)
            # print(f"Client checksum confirmation: {client_confirm}")

        except OSError as e:
             print(f"Socket error during file content send from path: {e}")
        except Exception as e:
             print(f"Error reading/sending file content from path: {e}")


    # Error handling remains largely the same
    except FileNotFoundError:
         print(f"Error: File not found on server disk during getsize/open: {file_path}")
         try: send_msg(clientSocket, "FILE_NOT_FOUND_DISK")
         except: pass
    except db.Error as db_e:
         print(f"Database error during download: {db_e}")
         try: send_msg(clientSocket, "DB_ERROR")
         except: pass
    except OSError as e:
         print(f"Socket error during download metadata exchange: {e}")
    except Exception as e:
        print(f"Error during file download setup: {e}")
        try: send_msg(clientSocket, "SERVER_ERROR")
        except: pass


def deleteFile(clientSocket, db_connection, isAdmin, username): # Added db_connection
    """Handles deleting a file based on client request using prefixing."""
    try:
        # Receive filename using prefixing
        filename_to_delete = recv_msg(clientSocket)
        if not filename_to_delete: return "ERROR_SOCKET" # Let clientHandler send prefixed
        print(f"[{username}] Received delete request for: {filename_to_delete}")

        # --- Authorization ---
        if not isAdmin:
            print(f"[{username}] Delete denied for '{filename_to_delete}': Not an admin.")
            return "ERROR_PERMISSION" # Sent prefixed by clientHandler

        # --- Retrieve file path from DB ---
        file_path, _ = db.getFileDir(db_connection, filename_to_delete)

        # --- Delete from Database ---
        delete_success_db = db.delFileDir(db_connection, filename_to_delete)

        if delete_success_db:
             print(f"[{username}] Deleted '{filename_to_delete}' record from DB.")
             # --- Delete from Filesystem ---
             if file_path and os.path.exists(file_path):
                 try:
                     os.remove(file_path)
                     print(f"[{username}] Deleted file from disk: {file_path}")
                 except OSError as e:
                     print(f"[{username}] Error deleting file from disk {file_path}: {e}")
             else:
                  print(f"[{username}] File path not found or file missing on disk for {filename_to_delete}. DB record deleted.")

             Logger.log(filename_to_delete, username, "Deleted")
             return "SUCCESS" # Sent prefixed by clientHandler
        else:
             print(f"[{username}] Failed to delete '{filename_to_delete}' from DB (not found or error).")
             return "ERROR_NOT_FOUND_DB" # Sent prefixed by clientHandler

    except OSError as e: # Catch socket errors during recv
         print(f"Socket error during delete recv: {e}")
         return "ERROR_SOCKET"
    except Exception as e:
        print(f"Error during file delete: {e}")
        return "ERROR_SERVER"


def listAvailableFiles(clientSocket, db_connection):
    """Gets file details (name, size, timestamp) and sends them to the client.""" # Updated docstring
    try:
        # db.listAllFiles now returns tuples of (file_name, file_path)
        files_data = db.listAllFiles(db_connection)
        file_details_list = []

        for file_name, file_path in files_data:
            try:
                if file_path and os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    mtime = os.path.getmtime(file_path)
                    # Convert timestamp to a readable string (e.g., YYYY-MM-DD HH:MM:SS)
                    timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
                    # Append details as a formatted string (tab-separated)
                    file_details_list.append(f"{file_name}\t{file_size}\t{timestamp_str}")
                else:
                    # Handle cases where path is missing or file doesn't exist on disk
                    file_details_list.append(f"{file_name}\tN/A\tN/A")
            except Exception as e:
                print(f"Error getting details for file {file_name} at {file_path}: {e}")
                file_details_list.append(f"{file_name}\tError\tError")


        file_nb = len(file_details_list)
        print(f"Sending file count: {file_nb}")
        # Send count using prefixing
        if not send_msg(clientSocket, str(file_nb)): return

        # Send each detail string using prefixing
        for details_str in file_details_list:
            print(f"Sending details: {details_str}")
            if not send_msg(clientSocket, details_str): return # Stop if send fails
        print("Finished sending file details list.")

    except OSError as e: # Catch socket errors
        print(f"Socket error listing files: {e}")
        # Cannot reliably send error back
    except Exception as e:
        print(f"Error listing files: {e}")
        # Cannot reliably send error back


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


def login(clientSocket, db_connection): # Added db_connection
    """Authenticates user with the database using length-prefixed messages."""
    # Note: The "Login" command is received by the main loop now.
    # This function now only needs to receive username and password using prefixing.
    try:
        print("Waiting for username (prefixed)...")
        username = recv_msg(clientSocket)
        if username is None: return False, "ERROR_SOCKET", "", "" # Error receiving username
        print(f"Received username: {username}")

        print("Waiting for password (prefixed)...")
        password = recv_msg(clientSocket)
        print("UP : ", username, password)
        if password is None: return False, "ERROR_SOCKET", "", "" # Error receiving password
        # Avoid printing password

        # Use the passed db_connection
        if db.userExists(db_connection, username, password):
            isAdmin = db.isAdmin(db_connection, username, password)
            print(f"Login successful for '{username}'. Admin: {isAdmin}")
            Logger.log("", username, "Logged in") # Log with empty filename for login action
            # Response (SUCCESS/FAILURE) will be sent by the clientHandler loop using send_msg
            return isAdmin, "SUCCESS", username, password
        else:
            print(f"Login failed for '{username}'.")
            Logger.log("", username, "Login Failed") # Log failed attempt
            return False, "FAILURE", "", "" # Response sent by clientHandler

    except OSError as e: # Catch socket errors during recv
        print(f"Socket error during login recv: {e}")
        return False, "ERROR_SOCKET", "", ""
    except Exception as e:
        print(f"Error during login process: {e}")
        return False, "ERROR_SERVER", "", ""


"""
------------------------------------
MAIN THREAD: FOR CONNECTION INITIATION
------------------------------------
"""
def startServer():
    """Initializes the server socket and enters the main accept loop."""
    serverPort = 12344
    # Use socket.socket() explicitly
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Allow address reuse quickly after server restart
        serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serverSocket.bind(('', serverPort))
        serverSocket.listen(5) # Increase backlog queue slightly
        print(f'Server started on port {serverPort}. Waiting for connections...')

        while True:
            try:
                clientSocket, addr = serverSocket.accept()
                print(f"\nConnection accepted from {addr}")

                # Create and start a new thread for each client
                thread = threading.Thread(target=clientHandler, args=(clientSocket, addr), daemon=True)
                thread.start()

            except Exception as e:
                 print(f"Error accepting connection: {e}")


    except KeyboardInterrupt:
        print("\nServer is shutting down due to KeyboardInterrupt...")
    except Exception as e:
        print(f"\nServer encountered critical error: {e}")
    finally:
        print("Closing server socket.")
        serverSocket.close()
        print("Server shut down complete.")


if __name__ == "__main__":
    startServer()