import secrets, hashlib, json

def generate_keypair():
    private = [[secrets.token_bytes(32), secrets.token_bytes(32)] for _ in range(256)]
    public = [[hashlib.sha512(p[0]).digest(),
               hashlib.sha512(p[1]).digest()] for p in private]
    return private, public

def sign(private_key, message_bytes):
    hashed = hashlib.sha512(message_bytes).digest()
    signature = []
    for bit_index, byte in enumerate(hashed):
        for bit_pos in range(8):
            bit = (byte >> bit_pos) & 1
            signature.append(private_key[8*bit_index + bit_pos][bit])
    return signature

def verify(public_key, message_bytes, signature):
    hashed = hashlib.sha512(message_bytes).digest()
    for i in range(256):
        bit = (hashed[i//8] >> (i % 8)) & 1
        if hashlib.sha512(signature[i]).digest() != public_key[i][bit]:
            return False
    return True
