from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Read data
with open("data.txt", "r") as f:
    data = f.read()

# Generate key and cipher
key = get_random_bytes(16)  # AES-128 key
cipher = AES.new(key, AES.MODE_CBC)
iv = cipher.iv

# Encrypt
ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))

# Save ciphertext + iv
with open("data.enc", "wb") as f:
    f.write(iv)
    f.write(ciphertext)

# Save key securely (for demo purposes only)
with open("key.bin", "wb") as f:
    f.write(key)

print("Encryption done. Key saved in key.bin")
