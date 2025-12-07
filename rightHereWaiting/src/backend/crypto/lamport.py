import os
import hashlib
import json
import secrets
from pathlib import Path

from src.backend.utils.file_handler import delete_sk_lamport


def generate_keys(user_id : int):

    # Função que gera um par de chaves privada,pública para as assinaturas digitais 
    # Usa a função de hash SHA-256

    key_dir = "data/keys"
    os.makedirs(key_dir, exist_ok=True)

    # Gerar chave privada 
    # Chave privada contém pares de números aleatórios de 256 bits (32 bytes)
    private_key = []
    for i in range(256):
        private_key.append([secrets.token_bytes(32).hex(), secrets.token_bytes(32).hex()])

    # Gerar chave pública
    # Chave pública contém o hash (SHA-256) dos pares de números aleatórios da chave privada

    public_key = []
    for list in private_key:
        public_key.append([hashlib.sha256(bytes.fromhex(list[0])).hexdigest(), hashlib.sha256(bytes.fromhex(list[1])).hexdigest()])

    # Criar caminho único para a chave privada no formato: user_id_lamport_count
    count = 0
    while True:
        priv_path = os.path.join(key_dir, f"{user_id}_lamport_{count}.priv")
        if not os.path.exists(priv_path):
            break
        count += 1

    # A chave pública tem o mesmo caminho que a privada, com .pub em vez de .priv
    pub_path = priv_path.replace(".priv", ".pub")

    # Escrever a chave privada para o ficheiro
    with open(priv_path, "w") as f:
        json.dump(private_key, f)

    # Escrever a chave pública para o ficheiro
    with open(pub_path, "w") as f:
        json.dump(public_key, f)


    return priv_path, pub_path



def generate_bits_from_hash(hash : bytes) -> str:

    # Função que gera o código binário do hash recebido

    bits = ""
    for byte in hash:
        bits += format(byte, '08b')

    return bits


    
def sign(pathfile : str, private_key_path : str) -> str:

    # Função que assina um ficheiro usando uma chave privada, segundo o esquema de Lamport
    # A chave é destruída após ser utilizada, visto que a mesma já não é segura

    # Criar diretoria para armazenar as assinaturas de ficheiros
    sig_dir = "data/signatures"
    os.makedirs(sig_dir, exist_ok=True)

    file_name = Path(pathfile).name

    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Ficheiro com chave privada não foi encontrado: {private_key_path}")
    
    if not private_key_path.endswith(".priv"):
        raise ValueError("Só é possível assinar ficheiros com chave privada (.priv)")

    # Ler chave privada do ficheiro
    with open(private_key_path, "r") as f:
        private_key = json.load(f)

    # Ler o conteúdo do ficheiro a assinar para a variável msg
    with open(pathfile, "rb") as f:
        msg = f.read()

    # Calcular o hash (SHA-256) do ficheiro a assinar
    hash_msg = hashlib.sha256(msg).digest()

    bits = generate_bits_from_hash(hash_msg)

    # A assinatura do ficheiro é composta pelos elementos da chave privada
    # Se o bit do hash for 0 então escolhemos o primeiro elemento do par atual da chave, caso contrário escolhemos o segundo
    signature = []
    for i,bit in enumerate(bits):
        bit_i = int(bit)   # Converter o bit de string para int
        signature.append(private_key[i][bit_i])

    # Eliminar a chave privada de forma segura
    delete_sk_lamport(private_key_path)

    # Path para a assinatura
    sig_path = os.path.join(sig_dir, file_name + ".sig")

    # Escrever a assinatura para o ficheiro
    with open(sig_path, "w") as f:
        json.dump(signature, f)

    return sig_path



def verify(pathfile : str, signature_path : str, public_key_path : str) -> bool:

    # Função que verifica uma assinatura Lamport através da chave pública da assinatura e do ficheiro

    if not public_key_path.endswith(".pub"):
        raise ValueError("Só é possível verificar ficheiros com chave pública (.pub)")

    try:
        # Ler assinatura do ficheiro
        with open(signature_path, "r") as f:
            signature = json.load(f)
        
        # Ler a chave pública do ficheiro
        with open(public_key_path, "r") as f:
            public_key = json.load(f)

    except (json.JSONDecodeError, TypeError):
        return False

    # Se o tamanho da assinatura não for 256, descartar
    # Estamos a usar SHA-256, tamanho do hash da mensagem = tamanho da assinatura
    if len(signature) != 256:
        return False

   # Ler o conteúdo do ficheiro a assinar para a variável msg
    with open(pathfile, "rb") as f:
        msg = f.read()

    # Calcular o hash (SHA-256) do ficheiro a assinar
    hash_msg = hashlib.sha256(msg).digest()

    bits = generate_bits_from_hash(hash_msg)

    # Vericar a assinatura com a chave pública
    # Calcular o hash de cada valor da assinatura e compará-lo com o valor correspondente da chave pública, com base no bit do hash do ficheiro original.
    # Se algum dos elementos falhar a assinatura é inválida
    for i,bit in enumerate(bits):
        bit_i = int(bit)   # Converter o bit de string para int
        sig_hash = hashlib.sha256(bytes.fromhex(signature[i])).hexdigest()

        if sig_hash != public_key[i][bit_i]:
            return False
  
    return True