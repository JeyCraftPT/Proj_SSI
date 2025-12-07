import os
import secrets


def delete_sk_lamport(pathfile : str) -> None:

    """
    Função para escrever por cima dos dados da chave privada Lamport antes de a apagar
    Objetivo é tornar inviável a recuperação da chave privada
    """
    # Verificar se o ficheiro existe
    if not os.path.exists(pathfile):
        return

    # Obter o tamanho do ficheiro
    length = os.path.getsize(pathfile)

    with open(pathfile, "wb") as f:
            # Escrever bytes aleatórios
            f.write(secrets.token_bytes(length))
            # Forçar a escrita 
            f.flush()
    
    # Apagar o ficheiro
    os.remove(pathfile)
    print(f"Ficheiro eliminado de forma segura: {pathfile}")
