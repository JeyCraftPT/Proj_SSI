import os
from pathlib import Path
from Crypto.Hash import HMAC, SHA512, SHA256

def calculate_hmac(pathfile : str, pathkey : str, algorithm : str) -> str:
    
    # Função para calcular o HMAC de um ficheiro segundo uma chave de integridade e uma função de hash
    # Funções de hash disponíveis: SHA-512, SHA-256
    # A chave de integridade a usar é a chave usada para cifrar o ficheiro 

    # Criar diretoria para armazenar o HMAC de ficheiros 
    hmac_dir = "data/hmac"

    file_name = Path(pathfile).name
    file_nameWithoutExt = Path(file_name).stem

    if not os.path.exists(pathkey):
        raise FileNotFoundError(f"Chave não foi encontrada: {pathkey}")
    
    if not os.path.exists(pathfile):
        raise FileNotFoundError(f"Ficheiro não foi encontrado: {pathfile}")

    # Ler chave de integridade do ficheiro
    with open(pathkey, "rb") as f:
        key = f.read()

    # Aplicar HMAC consoante o algoritmo escolhido
    if algorithm == "SHA-256":
        hmac = HMAC.new(key, digestmod=SHA256)
        algorithm_dir = "sha256"
    elif algorithm == "SHA-512":
        hmac = HMAC.new(key, digestmod=SHA512)
        algorithm_dir = "sha512"
    else:
        raise ValueError("Algoritmo não suportado. (Use SHA-256 or SHA-512).")

    subdir = os.path.join(hmac_dir, algorithm_dir)
    os.makedirs(subdir, exist_ok=True)

    # Ler dados do ficheiro que vamos calcular o HMAC
    with open(pathfile, "rb") as f:
        file_data = f.read()
        hmac.update(file_data)

    # Calcular o hmac em hexadecimal
    hmac_result = hmac.hexdigest()

    hmac_file_path = os.path.join(subdir, file_nameWithoutExt + ".hmac")

    # Escrever o hmac no ficheiro correspondente
    with open(hmac_file_path, "w") as f:
        f.write(hmac_result)
    
    return hmac_file_path





def verify_hmac(pathfile : str, pathkey : str, hmac_expected_pathfile : str) -> bool:

    # Função que verifica se o HMAC do ficheiro coincide com o esperado
    # Desta forma é possível saber se a integridade ou autenticidade dos dados no ficheiro foi alterada

    if not os.path.exists(pathkey):
        raise FileNotFoundError(f"Chave não foi encontrada: {pathkey}")
    
    if not os.path.exists(pathfile):
        raise FileNotFoundError(f"Ficheiro não foi encontrado: {pathfile}")
    
    if not hmac_expected_pathfile.endswith(".hmac"):
        raise ValueError("Só é possível verificar hmac se for disponibilizado o hmac (.hmac)")

    # Ler chave de integridade do ficheiro
    with open(pathkey, "rb") as f:
        key = f.read()

    # Ler o hmac esperado e guardar na variavel hmac_expected
    with open(hmac_expected_pathfile, "r") as f:
        hmac_expected = f.read() 

    # Selecionar o algoritmo de hash segundo o nome da diretoria
    subdir = os.path.basename(os.path.dirname(hmac_expected_pathfile))

    # Aplicar HMAC consoante o algoritmo escolhido
    if subdir == "sha256":
        h = HMAC.new(key, digestmod=SHA256)
    elif subdir == "sha512":
        h = HMAC.new(key, digestmod=SHA512)
    else:
        raise ValueError("Algoritmo não suportado. (Use SHA-256 or SHA-512).")

    # Ler dados do ficheiro que vamos calcular o HMAC
    with open(pathfile, "rb") as f:
        file_data = f.read()
        h.update(file_data)
    
    # Calcular o hmac em hexadecimal
    h = h.hexdigest()

    # Verificar o HMAC, através da comparação do calculado com o presente no ficheiro .hmac
    if h == hmac_expected.strip():
        return True
    else:
        return False