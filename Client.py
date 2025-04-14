import socket
import threading
import hashlib
import os
# import tkinter as tk

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

# Global State
client_socket = None
is_connected = False


def connect_to_server(host=SERVER_HOST, port=SERVER_PORT):
    """Establishes connection to the server."""
    global client_socket, is_connected
    pass


def send_choice(choice):
    """Sends a command string to the server."""
    pass


def receive_message():
    """Receives a message string from the server."""
    pass


def disconnect_from_server():
    """Closes the client socket connection."""
    global client_socket, is_connected
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


def calculate_checksum(file_path, algorithm='sha256'):
    """Calculates a checksum for file integrity checks."""
    pass


def console_ui_loop():
    """Basic console interface for client actions."""
    pass


if __name__ == "__main__":
    console_ui_loop()
    # Or initialize GUI