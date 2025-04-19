CREATE database Storage;

use Storage;

CREATE TABLE Users(
user_name varchar(30) UNIQUE NOT NULL,
user_password varchar(30) NOT NULL,
is_admin boolean default false,
PRIMARY KEY (user_name, user_password)
);

CREATE TABLE Files(
file_name varchar(255) NOT NULL,
file_path varchar(4096) NOT NULL,
file_version int DEFAULT 0,
file_checksum char(32) NOT NULL,
PRIMARY KEY (file_name, file_version)
);

