import os
from Crypto.Hash import HMAC, SHA512

def calculate_hmac(file_path, key_path):
    """
    Calculates the HMAC-SHA512 of a file using the key at key_path.
    
    Args:
        file_path (str): Path to the file to check integrity for.
        key_path (str): Path to the key file (used for both cipher and integrity).
        
    Returns:
        str: The HMAC digest as a hexadecimal string.
    """
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    # 1. Read the Key
    with open(key_path, "rb") as f:
        key = f.read()

    # 2. Initialize HMAC-SHA512
    h = HMAC.new(key, digestmod=SHA512)

    # 3. Read file in chunks to handle large files efficiently
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    
    return h.hexdigest()

def verify_hmac(file_path, key_path, expected_hmac_hex):
    """
    Verifies if the file content matches the provided HMAC-SHA512.
    
    Args:
        file_path (str): Path to the file.
        key_path (str): Path to the key file.
        expected_hmac_hex (str): The HMAC string provided for verification.
        
    Returns:
        bool: True if valid, False otherwise.
    """
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    # 1. Read the Key
    with open(key_path, "rb") as f:
        key = f.read()

    # 2. Initialize HMAC
    h = HMAC.new(key, digestmod=SHA512)

    # 3. Process file
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
            
    # 4. Verify securely (hexverify prevents timing attacks)
    try:
        h.hexverify(expected_hmac_hex)
        return True
    except ValueError:
        # Signature mismatch
        return False