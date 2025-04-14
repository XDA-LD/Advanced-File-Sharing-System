
def create_connection():
    connection = None
    try:
        connection = mysql.connector.connect(
            host='127.0.0.1',
            user='root',
            password='gasanchik',
            database='assDB'
        )
        print("Connection to MySQL DB successful")
    except Error as e:
        print(f"The error '{e}' occurred")

    return connection

```python
def createAccount(name, pwd):
	if notAlreadyInDB(...)
		SQLCreateAccount(...)
		return True
	else:
		return False
```

returns role if logged in, "none" if not
```python
def isAdmin(Name, Pwd):
	return queryRole(Name, Pwd)
```

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