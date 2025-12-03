import os
import hmac
from db import *
from .auth_operations import aleatory_nonce_CHAP,derived_Password_PBKDF2,chap_HASH


# Registar User
def registerUser (username, password):

    connection = connectDB
    cursor = connection.cursor()

    # gerar salt para user
    salt = os.urandom(16)
    salt_tohex = salt.hex()

    iterations = 300000

    # gerar derivação da password através do salt e nº iterações
    passwordD_hash = derived_Password_PBKDF2(salt, password, iterations)
    passwordD_hash_tohex = passwordD_hash.hex()

    try:
        cursor.execute(""" INSERT INTO users(username, salt, id_val, iterations, passwordD_hash)
                           VALUES (?,?,?,?,?) 
                        """, (username,salt_tohex,1,iterations,passwordD_hash_tohex))
        connection.commit()
    except:
        # Fazer parte ligada ao frontend para mensagem de aviso    
        return False
    finally:
        connection.close()

    # Fazer parte ligada ao frontend para mensagem de aviso
    return True




# Login com CHAP (Challenge Handshake Authentication Protocol)


def chap_obtainFieldsDBbyUser (username):

    connection = connectDB
    cursor = connection.cursor()

    cursor.execute(""" SELECT salt,id_val,iterations,last_nonce FROM users WHERE username = ?""", (username))
    row =  cursor.fetchone()

    if not row:
        # Fazer parte ligada ao frontend para mensagem de aviso
        return None

    salt_hex,id_val,iterations,last_nonce = row

    nonce = aleatory_nonce_CHAP()

    cursor.execute("UPDATE users SET last_nonce=? WHERE username=?", (nonce, username))
    connection.commit()

    connection.close()

    obtained_fields = {
        "salt" : salt_hex,
        "id" : id_val,
        "iterations" : iterations,
        "nonce" : nonce
    }

    return obtained_fields




def chap_UserValChallenge (username, password):

    fields = chap_obtainFieldsDBbyUser(username)

    salt_hex = fields["salt"]
    salt = bytes.fromhex(salt_hex)
    id_val = fields["id"]
    iterations = fields["iterations"]
    nonce = fields["nonce"]

    derived_password = derived_Password_PBKDF2(salt,password,iterations)

    challengeHash = chap_HASH(nonce, id_val, derived_password)

    return challengeHash




def verifyChallengeBD (username, challenge_client):

    connection = connectDB
    cursor = connection.cursor()

    cursor.execute(""" SELECT id_val,last_nonce,passwordD_hash FROM users WHERE username = ?""", (username))
    row =  cursor.fetchone()

    id_val,last_nonce,passwordD_hash = row
    passwordHash = bytes.fromhex(passwordD_hash)

    challenge_BD = chap_HASH(last_nonce,id_val,passwordHash)

    if hmac.compare_digest(challenge_client, challenge_BD):
        new_id = id_val + 1  
        cursor.execute("UPDATE users SET id_val=? WHERE username=?", (new_id, username))
        connection.commit()
        connection.close()
        return True 
    else :
        # Fazer parte ligada ao frontend para mensagem de aviso
        connection.close()
        return False