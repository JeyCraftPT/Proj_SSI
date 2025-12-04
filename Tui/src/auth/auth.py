import os
import hmac
from .db import connectDB
from .auth_operations import aleatory_nonce_CHAP, derived_Password_PBKDF2, chap_HASH

def registerUser(username, password):
    """
    Registers a new user in the database.
    Returns True if successful, False if user already exists.
    """
    connection = connectDB()
    cursor = connection.cursor()

    # Generate random salt
    salt = os.urandom(16)
    salt_tohex = salt.hex()
    iterations = 300000

    # Derive password
    passwordD_hash = derived_Password_PBKDF2(salt, password, iterations)
    passwordD_hash_tohex = passwordD_hash.hex()

    try:
        # Default id_val to 1 for new users
        cursor.execute(""" 
            INSERT INTO users(username, salt, id_val, iterations, passwordD_hash, last_nonce)
            VALUES (?,?,?,?,?,?) 
        """, (username, salt_tohex, 1, iterations, passwordD_hash_tohex, os.urandom(16)))
        connection.commit()
        return True
    except Exception as e:
        # Usually triggers if username is not unique
        print(f"Register Error: {e}")
        return False
    finally:
        connection.close()

def create_user_if_not_exists(username, password):
    """
    Helper function to ensure a user exists. 
    Does not complain if the user is already there.
    """
    if registerUser(username, password):
        print(f"User '{username}' created.")
    else:
        print(f"User '{username}' already exists.")

# --- CHAP LOGIN FUNCTIONS ---

def chap_obtainFieldsDBbyUser(username):
    connection = connectDB()
    cursor = connection.cursor()

    cursor.execute(""" SELECT salt, id_val, iterations, last_nonce FROM users WHERE username = ? """, (username,))
    row = cursor.fetchone()

    if not row:
        connection.close()
        return None

    salt_hex, id_val, iterations, last_nonce = row

    # Generate new nonce for this login attempt
    nonce = aleatory_nonce_CHAP()

    # Update nonce in DB so we can verify the response later
    cursor.execute("UPDATE users SET last_nonce=? WHERE username=?", (nonce, username))
    connection.commit()
    connection.close()

    return {
        "salt": salt_hex,
        "id": id_val,
        "iterations": iterations,
        "nonce": nonce
    }

def chap_UserValChallenge(username, password):
    """
    Calculates the Challenge Response (Client Side Logic simulation).
    """
    fields = chap_obtainFieldsDBbyUser(username)
    
    if not fields:
        return None

    salt = bytes.fromhex(fields["salt"])
    id_val = fields["id"]
    iterations = fields["iterations"]
    nonce = fields["nonce"]

    # 1. Derive the password (simulating what the client app would do)
    derived_password = derived_Password_PBKDF2(salt, password, iterations)
    
    # 2. Calculate the Hash of the Challenge
    challengeHash = chap_HASH(nonce, id_val, derived_password)

    return challengeHash

def verifyChallengeBD(username, challenge_client):
    """
    Verifies the Challenge Response (Server Side Logic).
    """
    connection = connectDB()
    cursor = connection.cursor()

    cursor.execute(""" SELECT id_val, last_nonce, passwordD_hash FROM users WHERE username = ? """, (username,))
    row = cursor.fetchone()

    if not row:
        connection.close()
        return False

    id_val, last_nonce, passwordD_hash = row
    passwordHash = bytes.fromhex(passwordD_hash)

    # Calculate what the hash SHOULD be
    challenge_BD = chap_HASH(last_nonce, id_val, passwordHash)

    # Secure comparison
    if hmac.compare_digest(challenge_client, challenge_BD):
        # Increment ID to prevent replay attacks
        new_id = id_val + 1  
        cursor.execute("UPDATE users SET id_val=? WHERE username=?", (new_id, username))
        connection.commit()
        connection.close()
        return True 
    else:
        connection.close()
        return False