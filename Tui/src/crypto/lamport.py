import os
import hashlib
import json
import secrets

from src.utils.file_handler import secure_delete

class LamportSigner:
    """
    Implementation of Lamport One-Time Signature Scheme.
    Adapted to use 'secrets' and SHA-256 for 256-bit security.
    """

    @staticmethod
    def generate_keys(output_dir="data/keys", user_id="anon"):
        """
        Generates a Lamport key pair.
        Uses SHA-256 (256 bits) requiring 256 key pairs.
        
        Returns:
            tuple: (private_key_path, public_key_as_json_string)
        """
        # 1. Generate 256 pairs of random numbers (32 bytes each)
        # We store them as HEX strings to make them JSON/DB friendly
        private_key = [
            [secrets.token_bytes(32).hex(), secrets.token_bytes(32).hex()] 
            for _ in range(256)
        ]

        # 2. Derive Public Key (Hash of private parts)
        public_key = [
            [
                hashlib.sha256(bytes.fromhex(p[0])).hexdigest(),
                hashlib.sha256(bytes.fromhex(p[1])).hexdigest()
            ]
            for p in private_key
        ]

        # 3. Save Private Key to Disk
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        count = 0
        while True:
            priv_path = os.path.join(output_dir, f"{user_id}_lamport_{count}.priv")
            if not os.path.exists(priv_path):
                break
            count += 1

        with open(priv_path, "w") as f:
            json.dump(private_key, f)

        return priv_path, json.dumps(public_key)

    @staticmethod
    def sign(file_path, private_key_path):
        """
        Signs a file using the private key, then DESTROYS the private key.
        """
        if not os.path.exists(private_key_path):
            raise FileNotFoundError("Private key not found or already used.")

        # 1. Load Private Key
        with open(private_key_path, "r") as f:
            private_key = json.load(f)

        # 2. Hash the Document (SHA-256 to match the 256 key pairs)
        with open(file_path, "rb") as f:
            message_bytes = f.read()
        hashed = hashlib.sha256(message_bytes).digest()

        # 3. Create Signature
        signature = []
        for bit_index, byte in enumerate(hashed):
            for bit_pos in range(8):
                # MSB first logic (standard)
                bit = (byte >> (7 - bit_pos)) & 1
                signature.append(private_key[8 * bit_index + bit_pos][bit])

        # 4. DESTROY Private Key (Secure Deletion Simulation)
        with open(private_key_path, "w") as f:
            f.write("0" * 1000)
        secure_delete(private_key_path)

        return json.dumps(signature)

    @staticmethod
    def verify(file_path, signature_json, public_key_json):
        """
        Verifies a Lamport signature.
        """
        try:
            signature = json.loads(signature_json)
            public_key = json.loads(public_key_json)
        except (json.JSONDecodeError, TypeError):
            return False

        if len(signature) != 256:
            return False

        # 1. Hash the Document
        with open(file_path, "rb") as f:
            message_bytes = f.read()
        hashed = hashlib.sha256(message_bytes).digest()

        # 2. Verify
        for i in range(256):
            # Extract bit from message hash
            byte_val = hashed[i // 8]
            bit = (byte_val >> (7 - (i % 8))) & 1
            
            # Hash the signature element provided
            sig_hash = hashlib.sha256(bytes.fromhex(signature[i])).hexdigest()
            
            # Check against public key
            if sig_hash != public_key[i][bit]:
                return False

        return True