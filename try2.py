from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Read key
with open("key.bin", "rb") as f:
    key = f.read()

# Read encrypted data
with open("data.enc", "rb") as f:
    iv = f.read(16)
    ciphertext = f.read()

# Decrypt
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
data = unpad(cipher.decrypt(ciphertext), AES.block_size)

# Write to file
with open("data_decrypted.txt", "w") as f:
    f.write(data.decode())

print("Decryption done. Output saved in data_decrypted.txt")
