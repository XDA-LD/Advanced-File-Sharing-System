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
    with connection.cursor() as cursor:
        sql = "SELECT is_admin FROM Users WHERE user_name = %s and user_password = %s"
        cursor.execute(sql, (userName, passWord))
        result = cursor.fetchone()[0]
        return True if result == 1 else False


def userExists(connection: pymysql.connections.Connection, userName, passWord):
    # checks if user is in Database
    with connection.cursor() as cursor:
        sql = "SELECT EXISTS( SELECT * FROM Users WHERE user_name = %s and user_password = %s)"
        cursor.execute(sql, (userName, passWord))
        result = cursor.fetchone()[0]
        return True if result == 1 else False


def userCreateAccount(connection: pymysql.connections.Connection, userName, passWord):
    # creates account if user doesnt exist
    with connection.cursor() as cursor:
        sql = "INSERT INTO Users(user_name, user_password,is_admin) VALUES (%s,%s,%s)"
        cursor.execute(sql, (userName, passWord, "0"))
        # print("created user")
        return


def userCheck(connection: pymysql.connections.Connection, userName, passWord):
    if userExists(connection, userName, passWord):
        print("User exists")
    else:
        userCreateAccount(connection, userName, passWord)
        print("User created")


def promptUser():
    userName = input("Please enter a username:\n")
    password = input("Please enter the password:\n")
    return userName, password


def listAllFiles(connection: pymysql.connections.Connection):
    with connection.cursor() as cursor:
        sql = "SELECT file_name FROM Files"
        cursor.execute(sql)
        result = cursor.fetchall()
        return result


def checkFileExists(connection: pymysql.connections.Connection, fileName):
    with connection.cursor() as cursor:
        sql = "SELECT EXISTS ( SELECT * FROM Files WHERE file_name = %s)"
        cursor.execute(sql, (fileName))
        result = cursor.fetchone()[0]
        return True if result == 1 else False


def getFileVersion(connection: pymysql.connections.Connection, fileName):
    # used only if file already exists
    with connection.cursor() as cursor:
        sql = "SELECT file_version FROM Files WHERE file_name = %s"
        cursor.execute(sql, (fileName))
        result = cursor.fetchone()
        return result


def postFile(connection: pymysql.connections.Connection, fileName, fileVersion, file, checksumType, checkSum,
             WillOvewrite):
    with connection.cursor() as cursor:
        sql = ("INSERT INTO FILES(file_name, file_data, file_version, file_checksum_type, file_checksum_value) VALUES"
               "%s,%,%s,%s,%s")
        cursor.execute(sql, (fileName, file, fileVersion, checksumType, checkSum))
        return


def uploadFile(connection: pymysql.connections.Connection, fileName, fileData, checkSum, exists, willOvewrite):
    checkSumType = "MD5"
    if exists:
        ver = getFileVersion(connection, fileName)
        postFile(connection, fileName, ver, fileData, checkSumType, checkSum, willOvewrite)
    else:
        postFile(connection, fileName, 0, fileData, checkSumType, checkSum, willOvewrite)


connections = create_connection()


