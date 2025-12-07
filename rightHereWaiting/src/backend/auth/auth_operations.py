import secrets
import hashlib

def random_nonce_CHAP() -> bytes:
    # Gerar um nonce para a tentativa de login de 128 bits
    nonce = secrets.token_bytes(16)
    return nonce 

# Derivar a password num valor de hash seguro, através do salt (na bd) e de um número de iterações
def derived_Password_PBKDF2(salt : bytes, password : str, iterations : int) -> bytes:

    passwordDerived_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return passwordDerived_hash

# Challenge -> H(id || nonce || S)
def chap_HASH(nonce : bytes, id_val : int, password_derived : bytes) -> bytes:

    id_to_bytes = id_val.to_bytes(8, "big")
    hash_challenge = id_to_bytes + nonce + password_derived
    return hashlib.sha256(hash_challenge).digest()