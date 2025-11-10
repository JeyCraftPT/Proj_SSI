from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


print("What do you want to choose")
print("1: Encrypt a phrase and save to file")
print("2: Decrypt a phrase from file")
choice = input("Enter 1 or 2: ")

if choice == "1":
    userint = input("Enter a phrase: ")

    # Generate key and cipher
    key = get_random_bytes(16)  # AES-128 key
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    # Encrypt
    ciphertext = cipher.encrypt(pad(userint.encode(), AES.block_size))

    # Save ciphertext + iv
    with open("inputest.enc", "wb") as f:
        f.write(iv)
        f.write(ciphertext) 
    print("Encryption done.")

    # Save key securely (for demo purposes only)
    with open("inputest_key.bin", "wb") as f:
        f.write(key)
    print("Key saved in inputest_key.bin")

if choice == "2":
    from Crypto.Util.Padding import unpad

    # Read key
    with open("inputest_key.bin", "rb") as f:
        key = f.read()

    # Read encrypted data
    with open("inputest.enc", "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)

    print("Decrypted phrase:", data.decode())
