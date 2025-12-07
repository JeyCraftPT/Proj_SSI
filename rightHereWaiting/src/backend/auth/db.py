import sqlite3
import os


os.makedirs("data", exist_ok=True)
path_DB = "data/users.db"


def connectDB():
    return sqlite3.connect(path_DB)


def initializeDB():
    connection = connectDB()
    cursor = connection.cursor()

    # Tabela "users":
    # - id: id de cada user (chave primária)
    # - username: nome do user (único)
    # - salt: valor único e aleatório usado na derivação da password 
    # - id_val: id da autenticação usado no processo de login 
    # - iterations: número de iterações utilizadas para derivar a password
    # - last_nonce: último valor de nonce utilizado no processo de login 
    # - passwordD_hash: Hash da password derivada 
    cursor.execute(""" CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        salt TEXT UNIQUE NOT NULL,
                        id_val INTEGER NOT NULL,
                        iterations INTEGER NOT NULL,
                        last_nonce BLOB NOT NULL,
                        passwordD_hash TEXT NOT NULL
                        );""")

    connection.commit()
    connection.close()