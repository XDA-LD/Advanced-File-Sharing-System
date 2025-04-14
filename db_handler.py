import mysql.connector
import pymysql
from mysql.connector import Error

def create_connection():
    connection = None
    try:
        connection = mysql.connector.connect(
            host='127.0.0.1',
            user='root',
            password='gasanchik',
            database='Storage'
        )
        print("Connection to MySQL DB successful")
    except Error as e:
        print(f"The error '{e}' occurred")

    return connection

def isAdmin(connection:pymysql.connections.Connection,userName, passWord):
    # returns boolean , true: admin, false: normal user
    with connection.cursor() as cursor:
        sql = "SELECT is_admin FROM Users WHERE user_name = %s and user_password = %s"
        cursor.execute(sql, (userName,passWord))
        result = cursor.fetchone()
        return result

def userExists(connection:pymysql.connections.Connection,userName, passWord):
    #checks if user is in Database
    with connection.cursor() as cursor:
        sql = "SELECT EXISTS( SELECT * FROM Users WHERE user_name = %s and user_password = %s)"
        cursor.execute(sql,(userName,passWord))
        result = cursor.fetchone()
        return result

def userCreateAccount(connection:pymysql.connections.Connection,userName, passWord):
    #creates account if user doesnt exist
    with connection.cursor() as cursor:
        sql = "INSERT INTO Users(user_name, user_password,is_admin) VALUES (%s,%s,%s)"
        cursor.execute(sql,(userName, passWord, "FALSE"))
        return




```python
def uploadFile(socket):
	name = reqName(socket...)
	size = reqSize(socket...)
	chuncks = reqSize(socket...)
	chunck_checksums = reqSize(socket...)
	SQLWriteFile(name)
	return None
```

```python
def downloadFile(socket):
	name = reqName(socket...)
	checksum = reqChecksum(socket...)
	file = SQLReqFile(name)
	sendFile(file)
	sendFile(checksum)
	return None
```

```python
def listAvailableFiles(
	socket
) return None
```
