import os
import secrets
from pathlib import Path
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def keygen(username : str) -> str:
    
    # Função que gera uma chave aleatória de 32 bytes (256 bits) para AES-256
    # A chave gerada é guardada num ficheiro
    
    key_bytes = secrets.token_bytes(32) # AES-256

    key_dir = "data/keys"
    os.makedirs(key_dir, exist_ok=True)

    # Verificar se a diretoria existe e guardar todos os seus ficheiros na variável files
    if os.path.exists(key_dir):
        files = os.listdir(key_dir)
    else:
        files = []

    files_id = []
    # Percorrer todos os ficheiros que têm o formato "username_id.pem" (caso existam) e guardar os seus ids
    for filename in files:
        if filename.startswith(username) and filename.endswith('.pem'):
            file_id = filename[len(username) + 1:-4]

            try:
                files_id.append(int(file_id))
            except ValueError:
                print("Erro ao obter id do ficheiro na diretoria key_dir!!")
    
    # Calcular o valor do id do novo ficheiro 
    # Se não existir nenhum ficheiro, começa com o id = 1
    new_id = max(files_id, default=0) + 1

    filename = os.path.join(key_dir, f"{username}_{new_id}.pem")

    # Guardar a chave no ficheiro
    with open(filename, "wb") as f:
        f.write(key_bytes)
    
    return filename




def encrypt(pathfile : str, algorithm : str, pathkey : str) -> str:

    # Função que cifra um ficheiro segundo um algoritmo e o path de uma chave e retorna (file_enc_path, iv)

    # Diretoria para armazenar o ficheiro cifrado
    enc_dir = "data/enc_files"
    os.makedirs(enc_dir, exist_ok=True)


    file_algorithm_name = "aes256"
    file_name = Path(pathfile).name
    
    if not os.path.exists(pathkey):
        raise FileNotFoundError(f"Chave não foi encontrada: {pathkey}")

    if not os.path.exists(pathfile):
        raise FileNotFoundError(f"Ficheiro não foi encontrado: {pathfile}")
    
    # Ler chave de cifra do ficheiro
    with open(pathkey, "rb") as f:
        key = f.read() 
    
    # Ler conteúdo do ficheiro e colocar na variável de texto-limpo
    with open(pathfile, "rb") as f:
        plaintext = f.read()

    ciphertext = b""

    # AES-CBC
    if "aes-256-cbc" in algorithm.lower():    
        
        iv = get_random_bytes(16) 
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
    
    # ChaCha20
    elif "chacha20" in algorithm.lower():
        
        file_algorithm_name = "chacha20"
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    else:
        raise ValueError("Algoritmo não suportado. (Use 'aes-256-cbc' ou 'chacha20')")


    file_enc_path = os.path.join(enc_dir, f"{file_name}_{file_algorithm_name}.enc")

    with open(file_enc_path, "wb") as f:
        # Escrever o IV no início do ficheiro
        if algorithm == "chacha20":
            f.write(nonce)
            f.write(ciphertext)
            f.write(tag)
        else:
            f.write(iv)
            f.write(ciphertext)
    
    return file_enc_path




def decrypt(pathfile: str, pathkey: str) -> str:
    # Diretoria para armazenar o ficheiro decifrado
    dec_dir = "data/dec_files"
    os.makedirs(dec_dir, exist_ok=True)

    file_name = Path(pathfile).name
    file_nameWithoutExt = Path(file_name).stem
    algorithm = file_nameWithoutExt.split("_")[-1]
    original_name = file_nameWithoutExt.rsplit("_", 1)[0]


    if not os.path.exists(pathkey):
        raise FileNotFoundError(f"Chave não foi encontrada: {pathkey}")
    
    if not os.path.exists(pathfile):
        raise FileNotFoundError(f"Ficheiro não foi encontrado: {pathfile}")
    
    if not pathfile.endswith(".enc"):
        raise ValueError("Só é possível decifrar ficheiros cifrados (.enc)")

    # Ler chave de cifra do ficheiro
    with open(pathkey, "rb") as f:
        key = f.read()

    # Ler conteúdo do ficheiro cifrado
    with open(pathfile, "rb") as f:
        if algorithm == "aes256":
            iv = f.read(16)
            ciphertext = f.read()
        elif algorithm == "chacha20":
            nonce = f.read(12)
            rest = f.read()       
            tag = rest[-16:]
            ciphertext = rest[:-16]
        else:
            raise ValueError("Algoritmo não suportado")

    plaintext = b""
    try:
        if algorithm == "aes256":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
        elif algorithm == "chacha20":
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            raise ValueError("Algoritmo não suportado")
    except (ValueError, KeyError) as e:
        raise ValueError("Falha na decifra. Chave errada ou ficheiro corrompido.") from e

    file_dec_path = os.path.join(dec_dir, original_name)

    # Escrever no ficheiro o texto-limpo
    with open(file_dec_path, "wb") as f:
        f.write(plaintext)

    return file_dec_path
