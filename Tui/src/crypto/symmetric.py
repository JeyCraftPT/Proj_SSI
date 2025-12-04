import os
import re
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def keygen(username):
    """
    Gera uma chave aleatória de 32 bytes (256 bits) para AES-256.
    Salva em ficheiro e retorna o caminho.
    """
    key_bytes = get_random_bytes(32) # AES-256

    key_dir = "data/keys"
    os.makedirs(key_dir, exist_ok=True)

    # Lógica para encontrar o próximo n livre (key_user_n.pem)
    max_n = -1
    pattern = re.compile(rf"^key_{re.escape(username)}_(\d+)\.pem$")
    
    if os.path.exists(key_dir):
        files = os.listdir(key_dir)
    else:
        files = []

    for filename in files:
        match = pattern.match(filename)
        if match:
            current_n = int(match.group(1))
            if current_n > max_n:
                max_n = current_n
    
    new_n = max_n + 1
    filename = os.path.join(key_dir, f"key_{username}_{new_n}.pem")

    with open(filename, "wb") as f:
        f.write(key_bytes)
    
    return filename

def encrypt(pathfile, algorithm, pathkey, iv=None):
    """
    Cifra um ficheiro. Retorna (output_path, iv).
    """
    if not os.path.exists(pathkey):
        raise FileNotFoundError(f"Key file not found: {pathkey}")
    
    with open(pathkey, "rb") as f:
        key = f.read() # 32 bytes para AES-256
    
    with open(pathfile, "rb") as f:
        plaintext = f.read()

    ciphertext = b""
    
    if "aes" in algorithm.lower():
        # AES-CBC
        if iv is None:
            iv = get_random_bytes(16) # Bloco AES é sempre 16 bytes
        
        # Garante que a chave tem tamanho correto (32 bytes para AES-256)
        # Se o enunciado pede estritamente 512 bits de chave, teríamos de cortar.
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
    elif "chacha" in algorithm.lower():
        if iv is None:
            iv = get_random_bytes(12)
        else:
            iv = iv[:12]
            
        cipher = ChaCha20.new(key=key, nonce=iv)
        ciphertext = cipher.encrypt(plaintext)
    else:
        raise ValueError("Algoritmo não suportado (use 'aes' ou 'chacha20')")

    output_path = pathfile + ".enc"
    with open(output_path, "wb") as f:
        f.write(ciphertext)
    
    return output_path, iv

def decrypt(pathfile, algorithm, pathkey, iv):
    """
    Decifra um ficheiro usando AES-CBC ou ChaCha20.
    Requisito: "A aplicação permite a decifra... assumindo que lhe é fornecida a chave"
    """
    if not os.path.exists(pathkey):
        raise FileNotFoundError(f"Key file not found: {pathkey}")

    with open(pathkey, "rb") as f:
        key = f.read()
    
    with open(pathfile, "rb") as f:
        ciphertext = f.read()

    plaintext = b""
    
    try:
        if "aes" in algorithm.lower():
            # AES-CBC Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
            
        elif "chacha" in algorithm.lower():
            nonce = iv[:12]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
        else:
            raise ValueError("Algoritmo não suportado")
            
    except (ValueError, KeyError) as e:
        raise ValueError("Falha na decifra. Chave errada, IV errado ou ficheiro corrompido.") from e

    # Define nome do ficheiro de saída
    if pathfile.endswith(".enc"):
        output_path = pathfile[:-4] # Remove .enc
    else:
        output_path = pathfile + ".dec"
        
    with open(output_path, "wb") as f:
        f.write(plaintext)
        
    return output_path