import os
import hashlib

def aleatory_nonce_CHAP():
    # 128 bits
    nonce = os.urandom(16)
    return nonce 

# Derivar a password num valor de hash seguro, através do salt (na bd) e de um número de iterações
def derived_Password_PBKDF2(salt, password, iterations):
    # salt is expected to be bytes. password is str.
    passwordDerived_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return passwordDerived_hash

# H(id || nonce || S)
def chap_HASH(nonce, id_val, password_derived):
    # id_val is int, nonce is bytes, password_derived is bytes
    id_to_bytes = id_val.to_bytes(8, "big")
    hash_challenge = id_to_bytes + nonce + password_derived
    return hashlib.sha256(hash_challenge).digest()