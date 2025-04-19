# Recommendation: Choose ONE library and use it consistently.
# mysql-connector-python is generally recommended over PyMySQL for new projects.
# import pymysql  # Remove if using mysql.connector
import os
import mysql.connector
from mysql.connector import Error  # Use Error from the chosen library

# Recommendation: Load credentials from environment variables or a config file, not hardcoded.
DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', '@U*G72fHN=LM')  # Replace or use env var
DB_NAME = os.getenv('DB_DATABASE', 'Storage')


def create_connection():
    """Creates and returns a database connection."""
    connection = None
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        print("Connection to MySQL DB successful")
        return connection
    except Error as e:
        print(f"Error connecting to MySQL Database: {e}")
        # Recommendation: Raise the error or handle it more gracefully depending on context
        # raise e # Or return None and let caller handle
        return None  # Return None to indicate failure


# Recommendation: Use the connection object consistently (passed as argument)
# Recommendation: Add error handling (try...except) to all DB operations
# Recommendation: Use parameterized queries exclusively to prevent SQL injection

def isAdmin(connection, userName, passWord):
    """Checks if a user is an admin."""
    if not connection: return False  # Check if connection is valid
    try:
        with connection.cursor() as cursor:
            # Use parameterized query
            sql = "SELECT is_admin FROM Users WHERE user_name = %s and user_password = %s"
            cursor.execute(sql, (userName, passWord))
            result = cursor.fetchone()  # Fetch one row
            # Check if result is found and is_admin is True (1)
            return bool(result and result[0] == 1)
    except Error as e:
        print(f"Error in isAdmin check for user '{userName}': {e}")
        return False  # Return False on error


def userExists(connection, userName, passWord):
    """Checks if a user exists with the given credentials."""
    if not connection: return False
    try:
        with connection.cursor() as cursor:
            # Use parameterized query
            sql = "SELECT EXISTS(SELECT 1 FROM Users WHERE user_name = %s and user_password = %s)"
            cursor.execute(sql, (userName, passWord))
            result = cursor.fetchone()
            return bool(result and result[0] == 1)  # Check if result is found and EXISTS is 1
    except Error as e:
        print(f"Error in userExists check for user '{userName}': {e}")
        return False  # Return False on error


def userCreateAccount(connection, userName, passWord, is_admin=False):
    """Creates a new user account."""
    if not connection: return False
    try:
        with connection.cursor() as cursor:
            # Use parameterized query
            sql = "INSERT INTO Users(user_name, user_password, is_admin) VALUES (%s, %s, %s)"
            # Convert boolean is_admin to 0 or 1 for DB
            admin_flag = 1 if is_admin else 0
            cursor.execute(sql, (userName, passWord, admin_flag))
            connection.commit()  # Commit the transaction
            print(f"User '{userName}' created successfully.")
            return True
    except Error as e:
        # Handle specific errors like duplicate entry if needed
        if e.errno == mysql.connector.errorcode.ER_DUP_ENTRY:
            print(f"Error creating user: Username '{userName}' already exists.")
        else:
            print(f"Error in userCreateAccount for user '{userName}': {e}")
        return False  # Return False on error


# --- Functions related to Files table ---
# Recommendation: Review the Files table schema in DB.sql.
# It seems to store file_data as longblob, file_version as int, checksum info.
# The Python code often refers to file_path. Decide if you store paths or blobs.
# The following functions assume you might store metadata including path. Adapt as needed.

# In db_handler.py

# ... (other functions remain the same) ...

# In db_handler.py
import mysql.connector
from mysql.connector import Error
import os

# --- Assume DB_HOST, DB_USER, DB_PASSWORD, DB_NAME are defined ---
# ... (create_connection, isAdmin, userExists, userCreateAccount, checkFileExists, addfileDir, getFileDir, delFileDir remain the same) ...

def listAllFiles(connection):
    """Lists all file names and their paths.""" # Updated docstring
    if not connection: return []
    try:
        with connection.cursor() as cursor:
            # Select file_name and file_path. Adjust columns if your schema differs.
            # Using DISTINCT on file_name might be needed if you store versions,
            # but let's assume name/version is unique or we list all entries.
            # Order by name for consistency.
            sql = "SELECT file_name, file_path FROM Files ORDER BY file_name"
            cursor.execute(sql)
            result = cursor.fetchall()  # Fetch all results (tuples of name, path)
            return result if result else []  # Return list of tuples or empty list
    except Error as e:
        print(f"Error in listAllFiles: {e}")
        return []  # Return empty list on error

# ... (rest of the file, including userCreateAccount example, remains the same) ...


def checkFileExists(connection, fileName, fileVersion):
    """Checks if a specific file name and version exist."""
    if not connection: return False
    try:
        with connection.cursor() as cursor:
            sql = "SELECT EXISTS(SELECT 1 FROM Files WHERE file_name = %s AND file_version = %s)"
            cursor.execute(sql, (fileName, fileVersion))
            result = cursor.fetchone()
            return bool(result and result[0] == 1)
    except Error as e:
        print(f"Error in checkFileExists for '{fileName}' V{fileVersion}: {e}")
        return False


# In db_handler.py

def addfileDir(connection, fileName, fileVersion, fileDir, fileCheckSum):
    """Adds or updates a file record (storing file path) in the database."""
    # Assumes schema: file_name, file_version, file_path, file_checksum_type, file_checksum_value
    if not connection: return False
    try:
        with connection.cursor() as cursor:
            # Reverted: Insert fileDir into file_path column
            sql = """
                INSERT INTO Files (file_name, file_version, file_path, file_checksum_type, file_checksum_value)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    file_path = VALUES(file_path), -- Update path
                    file_checksum_value = VALUES(file_checksum_value),
                    file_checksum_type = VALUES(file_checksum_type)
            """
            checksum_type = "MD5" # Assuming MD5
            # Pass the fileDir (path string) and integer fileVersion
            cursor.execute(sql, (fileName, fileVersion, fileDir, checksum_type, fileCheckSum))
            connection.commit()
            # Corrected Log Format
            print(f"File record added/updated for '{fileName}' Version={fileVersion} using PATH.")
            return True
    except Error as e:
        connection.rollback() # Rollback on error
        # --- FIX: Corrected f-string for error message ---
        print(f"Error in addFileDir (PATH) for '{fileName}' Version={fileVersion}: {e}")
        return False
    except Exception as e:
        connection.rollback()
        # --- FIX: Corrected f-string for error message ---
        print(f"Unexpected error in addFileDir (PATH) for '{fileName}' Version={fileVersion}: {e}")
        return False


# In db_handler.py

def getFileDir(connection, fileName, fileVersion=1): # Use integer default version
    """Gets file path and checksum for a specific file version."""
    # Selects file_path column
    if not connection: return None, None
    try:
        with connection.cursor() as cursor:
            # Select file_path and checksum
            sql = "SELECT file_path, file_checksum_value FROM Files WHERE file_name = %s AND file_version = %s"
            # Pass integer fileVersion
            cursor.execute(sql, (fileName, fileVersion))
            result = cursor.fetchone()
            if result:
                 path = result[0] # This is the file path string
                 checksum = result[1]
                 # print(f"DEBUG: Retrieved path={path}, checksum={checksum}")
                 return path, checksum
            else:
                 print(f"File record not found for '{fileName}' Version={fileVersion}")
                 return None, None # Not found
    except Error as e:
        print(f"Error in getFileDir (PATH) for '{fileName}' Version={fileVersion}: {e}")
        return None, None # Return None on error
    except Exception as e:
        print(f"Unexpected error in getFileDir (PATH) for '{fileName}' Version={fileVersion}: {e}")
        return None, None


def delFileDir(connection, fileName, fileVersion=1): # Use integer default
    """Deletes a file record from the database."""
    if not connection: return False
    try:
        with connection.cursor() as cursor:
            sql = "DELETE FROM Files WHERE file_name = %s AND file_version = %s"
            # --- Ensure correct parameters (string, integer) are passed ---
            cursor.execute(sql, (fileName, fileVersion))
            deleted_count = cursor.rowcount # Check how many rows were affected
            connection.commit()
            if deleted_count > 0:
                 # --- FIX: Corrected Log Message ---
                 print(f"Deleted {deleted_count} file record(s) for '{fileName}' Version={fileVersion}")
                 return True
            else:
                 # --- FIX: Corrected Log Message ---
                 print(f"No file record found to delete for '{fileName}' Version={fileVersion}")
                 return False # Indicate not found or nothing deleted
    except Error as e:
        connection.rollback() # Rollback on error
        # --- FIX: Corrected f-string for error message ---
        print(f"Error in delFileDir for '{fileName}' Version={fileVersion}: {e}")
        return False
    except Exception as e:
        connection.rollback()
        # --- FIX: Corrected f-string for error message ---
        print(f"Unexpected error in delFileDir for '{fileName}' Version={fileVersion}: {e}")
        return False


print("--- Create New User Account ---")
db_conn = create_connection()

if db_conn and db_conn.is_connected():
    try:
        # Get new user details from input
        new_username = "admin"
        new_password = "admin"
        is_admin_input = "yes".lower()
        make_admin = is_admin_input == 'yes'

        if not new_username or not new_password:
            print("Username and password cannot be empty.")
        else:
            # Call the function to create the account
            success = userCreateAccount(db_conn, new_username, new_password, make_admin)
            success = userCreateAccount(db_conn, "na", "na", False)

            if success:
                print(f"Account for '{new_username}' created successfully.")
            else:
                print(
                    f"Failed to create account for '{new_username}'. It might already exist or there was a DB error.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the connection is closed
        if db_conn and db_conn.is_connected():
            db_conn.close()
            print("Database connection closed.")
else:
    print("Could not connect to the database.")
