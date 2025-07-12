import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class EncryptorPlugin:
    def __init__(self):
        self.name = "RSA"
        self.key_length = "Variable" # Depends on generation
        self.nonce_length = "N/A" # Asymmetric, no IV/Nonce for direct encryption
        self.cipher_mode = "OAEP" # Common padding mode for RSA encryption
        self.padding_scheme = "OAEP"
        self.compression_supported = False
        self.integrity_supported = True # OAEP provides some integrity, but often combined with signatures
        self.kdf_supported = False
        self.key_derivation_functions = []
        self.salt_length_bytes = "N/A"
        self.key_usage_options = ["Encryption", "Decryption", "Signing", "Key Exchange"]

    def generate_key(self, length=2048, kdf=None, salt_len=None, key_usage=None): # Accept new args
        if length not in [1024, 2048, 3072, 4096]:
            logging.warning(f"RSA key generation: Unsupported key length {length}. Defaulting to 2048.")
            length = 2048

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=length,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize keys to PEM format for storage/display
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {"private_key": private_pem.decode(), "public_key": public_pem.decode()}

    def encrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=None, compression=None, integrity_check=None):
        # Key here is the public key (PEM string)
        public_key = serialization.load_pem_public_key(key.encode(), backend=default_backend())

        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                plaintext = infile.read()
                # Max bytes RSA can encrypt directly is key_size_in_bytes - 42 (for OAEP padding)
                max_chunk_size = (public_key.key_size // 8) - 42

                if len(plaintext) > max_chunk_size:
                    raise ValueError(f"File too large for direct RSA encryption. Max {max_chunk_size} bytes. "
                                     f"Consider a hybrid encryption approach for large files.")

                encrypted_data = public_key.encrypt(
                    plaintext,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                outfile.write(encrypted_data)
                if progress_callback:
                    progress_callback(len(plaintext), len(plaintext))
            logging.info(f"RSA: Encrypted '{input_filepath}' to '{output_filepath}'")
        except Exception as e:
            logging.error(f"RSA encryption failed for '{input_filepath}': {e}")
            raise

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=None, decompression=None, integrity_check=None):
        # Key here is the private key (PEM string)
        private_key = serialization.load_pem_private_key(key.encode(), password=None, backend=default_backend())

        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                encrypted_data = infile.read()
                decrypted_data = private_key.decrypt(
                    encrypted_data,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                outfile.write(decrypted_data)
                if progress_callback:
                    progress_callback(len(encrypted_data), len(encrypted_data))
            logging.info(f"RSA: Decrypted '{input_filepath}' to '{output_filepath}'")
        except Exception as e:
            logging.error(f"RSA decryption failed for '{input_filepath}': {e}")
            raise
