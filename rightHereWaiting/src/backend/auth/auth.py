import os
import hmac
from .db import connectDB
from src.backend.auth.auth_operations import random_nonce_CHAP, derived_Password_PBKDF2, chap_HASH

def registerUser(username : str, password : str) -> bool:

    """
    Função para registar um user na base de dados
    Devolve True se for um sucesso e False se ele já existir
    """
    connection = connectDB()
    cursor = connection.cursor()

    # Gerar salt aleatório para proteger a password do user
    salt = os.urandom(16)
    salt_tohex = salt.hex()
    iterations = 300000

    # Derivar password a colocar na db
    passwordD_hash = derived_Password_PBKDF2(salt, password, iterations)
    passwordD_hash_tohex = passwordD_hash.hex()

    try:
        # id_val -> id da autenticação, 1 inicialmente para todos os utilizadores
        cursor.execute(""" 
            INSERT INTO users(username, salt, id_val, iterations, passwordD_hash, last_nonce)
            VALUES (?,?,?,?,?,?) 
        """, (username, salt_tohex, 1, iterations, passwordD_hash_tohex, os.urandom(16)))
        connection.commit()
        return True
    
    except Exception as exception:
        print(f"Erro ao registrar user!!: {exception}")
        return False
    
    finally:
        connection.close()



# --- CHAP LOGIN FUNCTIONS ---

def chap_obtainFieldsDBbyUser(username : str):
    connection = connectDB()
    cursor = connection.cursor()

    # Recuperar salt, id_autenticação e nº iterações para enviar para o user
    cursor.execute(""" SELECT salt, id_val, iterations FROM users WHERE username = ? """, (username,))
    row = cursor.fetchone()

    if not row:
        connection.close()
        return None

    salt_hex, id_val, iterations = row

    # Gera um nonce para uma tentativa de login
    nonce = random_nonce_CHAP()

    # Atualizar nonce na db para podermos verificar o challenge recebido posteriormente
    cursor.execute("UPDATE users SET last_nonce=? WHERE username=?", (nonce, username))
    connection.commit()
    connection.close()

    return {
        "salt": salt_hex,
        "id": id_val,
        "iterations": iterations,
        "nonce": nonce
    }



def chap_UserValChallenge(username : str, password : str) -> bytes:


    # Função para calcular o hash enviado pelo user como resposta ao challenge da aplicação

    fields = chap_obtainFieldsDBbyUser(username)
    
    if not fields:
        return None

    salt = bytes.fromhex(fields["salt"])
    id_val = fields["id"]
    iterations = fields["iterations"]
    nonce = fields["nonce"]

    # Derivar a password através dos elementos enviados pela aplicação e a password inserida pelo user
    derived_password = derived_Password_PBKDF2(salt, password, iterations)
    
    # Calcular a resposta ao challenge da aplicação   
    challengeHash = chap_HASH(nonce, id_val, derived_password)

    return challengeHash



def verifyChallengeBD(username : str, challenge_client : bytes) -> bool:
    
    # Função que verifica a resposta do user, calculando o challenge do lado da aplicação
    
    connection = connectDB()
    cursor = connection.cursor()

    cursor.execute(""" SELECT id_val, last_nonce, passwordD_hash FROM users WHERE username = ? """, (username,))
    row = cursor.fetchone()

    if not row:
        connection.close()
        return False

    id_val, last_nonce, passwordD_hash = row
    passwordHash = bytes.fromhex(passwordD_hash)

    # Calcular o valor de hash esperado para o challenge
    challenge_BD = chap_HASH(last_nonce, id_val, passwordHash)

    # Comparar os valores obtidos
    if hmac.compare_digest(challenge_client, challenge_BD):
        # Se for igual, incrementar o id_autenticação para a próxima tentativa de login
        new_id = id_val + 1  
        cursor.execute("UPDATE users SET id_val=? WHERE username=?", (new_id, username))
        connection.commit()
        connection.close()
        return True 
    else:
        connection.close()
        return False