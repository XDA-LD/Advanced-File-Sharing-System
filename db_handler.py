import mysql.connector
import pymysql
from mysql.connector import Error


def create_connection():
    connectioner = None
    try:
        connectioner = mysql.connector.connect(
            host='127.0.0.1',
            user='root',
            password='gasanchik',
            database='Storage'
        )
        print("Connection to MySQL DB successful")
    except Error as e:
        print(f"The error '{e}' occurred")

    return connectioner


def isAdmin(connection: pymysql.connections.Connection, userName, passWord):
    # returns boolean , true: admin, false: normal user
    try:
        with connection.cursor() as cursor:
            sql = "SELECT is_admin FROM Users WHERE user_name = %s and user_password = %s"
            cursor.execute(sql, (userName, passWord))
            result = cursor.fetchone()[0]
            return True if result == 1 else False
    except Error as e:
        print(f"Error in isAdmin : Error {e}")
        return


def userExists(connection: pymysql.connections.Connection, userName, passWord):
    # checks if user is in Database
    try:
        with connection.cursor() as cursor:
            sql = "SELECT EXISTS( SELECT * FROM Users WHERE user_name = %s and user_password = %s)"
            cursor.execute(sql, (userName, passWord))
            result = cursor.fetchone()[0]
            return True if result == 1 else False
    except Error as e:
        print(f"Error in userExists : Error {e}")
        return False


def userCreateAccount(connection: pymysql.connections.Connection, userName, passWord):
    try:  # creates account if user doesnt exist
        with connection.cursor() as cursor:
            sql = "INSERT INTO Users(user_name, user_password,is_admin) VALUES (%s,%s,%s)"
            cursor.execute(sql, (userName, passWord, "0"))
            connection.commit()
            # print("created user")
            return
    except Error as e:
        print(f"Error in userCreateAccount : Error {e}")
        return


def userCheck(connection: pymysql.connections.Connection, userName, passWord):
    if userExists(connection, userName, passWord):
        print("User exists")
    else:
        userCreateAccount(connection, userName, passWord)
        print("User created")


def deleteUser(connection: pymysql.connections.Connection, userName, passWord):
    if isAdmin(connection, userName, passWord):
        print("Cant delete an Administrator.")

    else:
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM Users WHERE user_name = %s AND user_password = %s"
                cursor.execute(sql, (userName, passWord))
                connection.commit()
                print("User deleted")
        except Error as e:
            print(f"Error in deleteUser : Error {e}")


def listAllFiles(connection: pymysql.connections.Connection):
    try:
        with connection.cursor() as cursor:
            sql = "SELECT file_name FROM Files"
            cursor.execute(sql)
            result = cursor.fetchall()
            return result
    except Error as e:
        print(f"Error in listAllFiles: Error {e}")


def checkFileExists(connection: pymysql.connections.Connection, fileName, fileVersion):
    try:
        with connection.cursor() as cursor:
            sql = "SELECT EXISTS ( SELECT * FROM Files WHERE file_name = %s AND file_version = %s)"
            cursor.execute(sql, (fileName, fileVersion))
            result = cursor.fetchone()[0]
            return True if result == 1 else False
    except Error as e:
        print(f"Error in checkFilesExists: Error {e}")
        return False


def getFileVersion(connection: pymysql.connections.Connection, fileName):
    # used only if file already exists
    try:

        with connection.cursor() as cursor:
            sql = "SELECT file_version FROM Files WHERE file_name = %s"
            cursor.execute(sql, (fileName,))
            result = cursor.fetchone()[0]
            return result
    except Error as e:
        print(f"Error in getFileVersion : Error {e}")


def getFileDir(connection: pymysql.connections.Connection, fileName, fileVersion):
    try:
        with connection.cursor() as cursor:
            sql = "SELECT file_path , file_checksum FROM Files WHERE file_name = %s AND file_version = %s"
            cursor.execute(sql, (fileName, fileVersion))
            result = cursor.fetchone()
            path = result[0]
            checksum = result[1]
            return path, checksum

    except Error as e:
        print(f"Error in getFileDir : Error {e}")


def addfileDir(connection: pymysql.connections.Connection, fileName, fileVersion, fileDir, fileCheckSum):
    try:
        with connection.cursor() as cursor:
            sql = "INSERT INTO Files(file_name, file_path, file_version, file_checksum) VALUES (%s,%s,%s,%s)"
            cursor.execute(sql, (fileName, fileDir, fileVersion, fileCheckSum))
            cursor.fetchone()
            connection.commit()
    except Error as e:
        print(f"Error in addFileDir : Error {e}")


def delFileDir(connection: pymysql.connections.Connection, fileName, fileVersion):
    try:
        with connection.cursor() as cursor:
            sql = "DELETE FROM Files WHERE file_name = %s AND file_version = %s"
            cursor.execute(sql, (fileName, fileVersion))
            cursor.fetchone()
    except Error as e:
        print(f"Error in delFileDir: Error {e}")


def promptuUser():
    user = input("Username: ")
    passw = input("Password: ")
    return user, passw


connections = create_connection()
user, passw = promptuUser()
