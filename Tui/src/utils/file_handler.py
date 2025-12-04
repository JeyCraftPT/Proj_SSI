import os
import secrets

def secure_delete(file_path, passes=3):
    """
    Sobrescreve um ficheiro com dados aleatórios várias vezes antes de o apagar.
    Isto é CRITICO para cumprir o requisito de destruir a chave privada Lamport.
    
    Args:
        file_path (str): Caminho do ficheiro a destruir.
        passes (int): Número de vezes que sobrescrevemos (padrão 3).
    """
    if not os.path.exists(file_path):
        return

    # Obter o tamanho do ficheiro para saber quanto escrever
    length = os.path.getsize(file_path)

    with open(file_path, "wb") as f:
        for i in range(passes):
            # Voltar ao início do ficheiro
            f.seek(0)
            # Escrever bytes aleatórios
            f.write(secrets.token_bytes(length))
            # Forçar a escrita física no disco
            f.flush()
            os.fsync(f.fileno())
    
    # Finalmente apagar o ficheiro do sistema
    os.remove(file_path)
    print(f"Ficheiro eliminado de forma segura: {file_path}")

def ensure_directory(directory_path):
    """
    Garante que uma pasta existe. Se não, cria-a.
    """
    if directory_path and not os.path.exists(directory_path):
        os.makedirs(directory_path, exist_ok=True)

def read_file_chunks(file_path, chunk_size=4096):
    """
    Lê um ficheiro em pedaços (chunks).
    Útil para hashing/cifra de ficheiros grandes sem encher a RAM.
    """
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk