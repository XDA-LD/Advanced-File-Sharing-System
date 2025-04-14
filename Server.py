import socket
import threading
import db_handler

# Configuration
HOST = '127.0.0.1'
PORT = 65432
active_connections = []


def handle_client_connection(client_socket, address):
    """Manages communication with a single connected client."""
    print(f"Connection from {address} established.")
    # session_key = None # Optional: For session management

    try:
        while True:
            choice = receive_message(client_socket)
            if not choice:
                break

            print(f"Client {address} command: {choice}")

            if choice == "UploadFile":
                upload_file(client_socket, address)
            elif choice == "DownloadFile":
                download_file(client_socket, address)
            elif choice == "ListFiles":
                list_available_files(client_socket, address)
            # --- Add other command handlers ---
            elif choice == "Disconnect":
                break
            else:
                send_message(client_socket, "Error: Unknown command")

    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        print(f"Closing connection for {address}.")
        if client_socket in active_connections:
            active_connections.remove(client_socket)
        client_socket.close()


def upload_file(client_socket, address):
    """Handles receiving a file upload from a client."""
    pass


def download_file(client_socket, address):
    """Handles sending a requested file to a client."""
    pass


def list_available_files(client_socket, address):
    """Sends the list of available files to the client."""
    pass


def file_integrity_check(file_path, expected_checksum):
    """Verifies file integrity using a checksum."""
    pass


def receive_message(client_socket):
    """Reliably receives a message from the socket."""
    pass


def send_message(client_socket, message):
    """Reliably sends a message to the socket."""
    pass


def start_server(host=HOST, port=PORT):
    """Initializes the server socket and enters the main accept loop."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}...")

        while True:
            client_socket, address = server_socket.accept()
            active_connections.append(client_socket)

            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket, address))
            client_thread.daemon = True
            client_thread.start()

    except KeyboardInterrupt:
        print("Server shutting down...")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        for sock in active_connections:
            try:
                sock.close()
            except:
                pass
        server_socket.close()
        print("Server socket closed.")


if __name__ == "__main__":
    # db_connection = db_handler.create_connection()
    start_server()