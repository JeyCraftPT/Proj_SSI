import sqlite3

path_DB = "rightHereWaiting.db"


def connectDB ():
    return sqlite3.connect(path_DB)


def initializeDB ():

    connection = connectDB
    cursor = connection.cursor()

    cursor.execute(""" CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        salt TEXT UNIQUE NOT NULL,
                        id_val INTEGER NOT NULL,
                        iterations INTEGER NOT NULL,
                        last_nonce BLOB NOT NULL,
                        passwordD_hash TEXT NOT NULL
                        );""")
    

    cursor.execute(""" CREATE TABLE IF NOT EXISTS signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        public_key TEXT NOT NULL,
                        private_key_path TEXT NOT NULL,
                        pk_name TEXT NOT NULL, 
                        FOREIGN KEY (user_id) REFERENCES users(id)
                        );""")
    
    
    cursor.execute(""" CREATE TABLE IF NOT EXISTS enc_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        filename TEXT NOT NULL,
                        iv TEXT,
                        hmac TEXT,
                        file_path TEXT NOT NULL,
                        cipher_type TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id) 
                        );""")
    
    connection.commit()
    connection.close()