#This file is the combined work of Enzo Lindauer Lui-ji Daou,and Olexandr Ghanem


import os
import mysql.connector
from mysql.connector import Error
DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
DB_USER = os.getenv('DB_USER', 'DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'DB_PASSWORD')
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
        return None  # Return None to indicate failure



def isAdmin(connection, userName, passWord):
    """Checks if a user is an admin."""
    if not connection: return False
    try:
        with connection.cursor() as cursor:

            sql = "SELECT is_admin FROM Users WHERE user_name = %s and user_password = %s"
            cursor.execute(sql, (userName, passWord))
            result = cursor.fetchone()

            return bool(result and result[0] == 1)
    except Error as e:
        print(f"Error in isAdmin check for user '{userName}': {e}")
        return False  # Return False on error


def userExists(connection, userName, passWord):
    """Checks if a user exists with the given credentials."""
    if not connection: return False
    try:
        with connection.cursor() as cursor:

            sql = "SELECT EXISTS(SELECT 1 FROM Users WHERE user_name = %s and user_password = %s)"
            cursor.execute(sql, (userName, passWord))
            result = cursor.fetchone()
            return bool(result and result[0] == 1)
    except Error as e:
        print(f"Error in userExists check for user '{userName}': {e}")
        return False  # Return False on error


def userCreateAccount(connection, userName, passWord, is_admin=False):
    """Creates a new user account."""
    if not connection: return False
    try:
        with connection.cursor() as cursor:

            sql = "INSERT INTO Users(user_name, user_password, is_admin) VALUES (%s, %s, %s)"
            # Convert boolean is_admin to 0 or 1 for DB
            admin_flag = 1 if is_admin else 0
            cursor.execute(sql, (userName, passWord, admin_flag))
            connection.commit()
            print(f"User '{userName}' created successfully.")
            return True
    except Error as e:
        #Handles duplicates
        if e.errno == mysql.connector.errorcode.ER_DUP_ENTRY:
            print(f"Error creating user: Username '{userName}' already exists.")
        else:
            print(f"Error in userCreateAccount for user '{userName}': {e}")
        return False  # Return False on error


import mysql.connector
from mysql.connector import Error
import os


def listAllFiles(connection):
    """Lists all file names and their paths.""" # Updated docstring
    if not connection: return []
    try:
        with connection.cursor() as cursor:
            sql = "SELECT file_name, file_path FROM Files ORDER BY file_name"
            cursor.execute(sql)
            result = cursor.fetchall()
            return result if result else []  # Return list of tuples or empty list
    except Error as e:
        print(f"Error in listAllFiles: {e}")
        return []




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




def addfileDir(connection, fileName, fileVersion, fileDir, fileCheckSum):
    """Adds or updates a file record (storing file path) in the database."""

    try:
        with connection.cursor() as cursor:
            # Reverted: Insert fileDir into file_path column
            sql = """
                INSERT INTO Files (file_name, file_version, file_path, file_checksum)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    file_path = VALUES(file_path), -- Update path,
                    file_checksum = VALUES(file_checksum)
            """
            checksum_type = "MD5"

            cursor.execute(sql, (fileName, fileVersion, fileDir, fileCheckSum))
            connection.commit()
            #
            print(f"File record added/updated for '{fileName}' Version={fileVersion} using PATH.")
            return True
    except Error as e:
        connection.rollback()

        print(f"Error in addFileDir (PATH) for '{fileName}' Version={fileVersion}: {e}")
        return False
    except Exception as e:
        connection.rollback()

        print(f"Unexpected error in addFileDir (PATH) for '{fileName}' Version={fileVersion}: {e}")
        return False




def getFileDir(connection, fileName, fileVersion=1):
    """Gets file path and checksum for a specific file version."""

    if not connection: return None, None
    try:
        with connection.cursor() as cursor:

            sql = "SELECT file_path, file_checksum FROM Files WHERE file_name = %s AND file_version = %s"

            cursor.execute(sql, (fileName, fileVersion))
            result = cursor.fetchone()
            if result:
                 path = result[0] # This is the file path string
                 checksum = result[1]
                 # print(f"DEBUG: Retrieved path={path}, checksum={checksum}")
                 return path, checksum
            else:
                 print(f"File record not found for '{fileName}' Version={fileVersion}")
                 return None, None
    except Error as e:
        print(f"Error in getFileDir (PATH) for '{fileName}' Version={fileVersion}: {e}")
        return None, None
    except Exception as e:
        print(f"Unexpected error in getFileDir (PATH) for '{fileName}' Version={fileVersion}: {e}")
        return None, None


def delFileDir(connection, fileName, fileVersion=1):
    """Deletes a file record from the database."""
    if not connection: return False
    try:
        with connection.cursor() as cursor:
            sql = "DELETE FROM Files WHERE file_name = %s AND file_version = %s"

            cursor.execute(sql, (fileName, fileVersion))
            deleted_count = cursor.rowcount
            connection.commit()
            if deleted_count > 0:

                 print(f"Deleted {deleted_count} file record(s) for '{fileName}' Version={fileVersion}")
                 return True
            else:

                 print(f"No file record found to delete for '{fileName}' Version={fileVersion}")
                 return False
    except Error as e:
        connection.rollback()

        print(f"Error in delFileDir for '{fileName}' Version={fileVersion}: {e}")
        return False
    except Exception as e:
        connection.rollback()

        print(f"Unexpected error in delFileDir for '{fileName}' Version={fileVersion}: {e}")
        return False


print("--- Create New User Account ---")
db_conn = create_connection()

if db_conn and db_conn.is_connected():
    try:

        new_username = "admin"
        new_password = "admin"
        is_admin_input = "yes".lower()
        make_admin = is_admin_input == 'yes'

        if not new_username or not new_password:
            print("Username and password cannot be empty.")
        else:

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

        if db_conn and db_conn.is_connected():
            db_conn.close()
            print("Database connection closed.")
else:
    print("Could not connect to the database.")
