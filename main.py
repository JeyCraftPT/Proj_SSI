# https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes
# pip install pycryptodome
# ------------------------------------------------------------- #   


# encrypt and decrypt with authentication using AES and HMAC

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

data = "secret data to transmit".encode()

key = get_random_bytes(16)  # AES-
hmac_key = get_random_bytes(16)  # HMAC key

cipher = AES.new(key, AES.MODE_CBC)
ciphertext = cipher.encrypt(data)

hmac = HMAC.new(hmac_key,digestmod=SHA256)
tag = hmac.update(cipher.nonce + ciphertextt).digest()

with open("output.bin", "wb") as f:
    f.write(tag)
    f.write(cipher.nonce)
    f.write(ciphertext)

# ------------------------------------------------------------- #

import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

with open("output.bin", "rb") as f:
    tag = f.read(32)  # SHA256 produces a 32-byte tag
    nonce = f.read(16)  # AES block size is 16 bytes
    ciphertext = f.read()

try:
    hmac = HMAC.new(hmac_key,digestmod=SHA256)
    hmac.update(nonce + ciphertext)
    hmac.verify(tag)
    print("HMAC verification succeeded.")
except ValueError:
    print("HMAC verification failed.")
    sys.exit(1)

cipher = AES.new(key, AES.MODE_CBC, nonce=nonce)
message = cipher.decrypt(ciphertext)
print("Decrypted message:", message.decode())

# ------------------------------------------------------------- #
# ------------------------------------------------------------- #

# encrypt and decrypt RSA private key with passphrase

from Crypto.PublicKey import RSA

secret_code = "Unguessable"
key = RSA.generate(2048)

encrypted_key = key,export_key(passphrase=secret_code, pkcs=8,
                               protection="scryptAndAES128-CBC"
                               prot_params={'interation_count':131072})
with open("private.pem", "wb") as f:
    f.write(encrypted_key)

print(key,publickey().export_key())

# ------------------------------------------------------------- #

from Crypto.PublicKey import RSA

secret_code = "Unguessable"
encoded_key = open("private.pem", "rb").read()
key = RSA.import_key(encoded_key, passphrase=secret_code)

print(key.public_key().export_key())

