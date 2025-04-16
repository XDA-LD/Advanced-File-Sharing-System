CREATE database Storage;

use Storage;

CREATE TABLE Users(
user_name varchar(30) UNIQUE NOT NULL,
user_password varchar(30) NOT NULL,
is_admin boolean default false,
PRIMARY KEY (user_name, user_password)
);

CREATE TABLE Files(
file_name varchar(100),
file_path varchar(150),
file_version int DEFAULT 0,
file_checksum_type varchar(20) NOT NULL,
file_checksum_value varchar(256) NOT NULL,
PRIMARY KEY (file_name, file_version)
);
