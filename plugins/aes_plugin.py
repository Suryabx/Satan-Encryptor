import os
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class EncryptorPlugin:
    def __init__(self):
        self.name = "AES-256-CBC"

    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # 256 bits
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None):
        if password:
            salt = os.urandom(16)
            derived_key = self._derive_key(password, salt)
        else:
            derived_key = key # Assume key is already 32 bytes for AES-256
            salt = b'' # No salt if using direct key

        iv = os.urandom(16) # 128-bit IV for AES
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                # Write salt and IV to the beginning of the file
                outfile.write(salt)
                outfile.write(iv)

                total_size = os.path.getsize(input_filepath)
                processed_bytes = 0
                chunk_size = 65536 # 64 KB

                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    padded_chunk = padder.update(chunk)
                    encrypted_chunk = encryptor.update(padded_chunk)
                    outfile.write(encrypted_chunk)
                    processed_bytes += len(chunk)
                    if progress_callback:
                        progress_callback(processed_bytes, total_size)

                final_padded_chunk = padder.finalize()
                final_encrypted_chunk = encryptor.update(final_padded_chunk) + encryptor.finalize()
                outfile.write(final_encrypted_chunk)
                processed_bytes += len(final_padded_chunk) # Approximation for progress
                if progress_callback:
                    progress_callback(total_size, total_size) # Ensure 100%

            logging.info(f"AES-256-CBC: Encrypted '{input_filepath}' to '{output_filepath}'")
        except Exception as e:
            logging.error(f"AES-256-CBC encryption failed for '{input_filepath}': {e}")
            raise

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None):
        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                # Read salt and IV from the beginning of the file
                salt = infile.read(16)
                iv = infile.read(16)

                if password:
                    derived_key = self._derive_key(password, salt)
                else:
                    derived_key = key # Assume key is already 32 bytes for AES-256

                cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

                total_size = os.path.getsize(input_filepath) - 32 # Subtract salt and IV
                processed_bytes = 0
                chunk_size = 65536

                buffer = b'' # To handle partial blocks for unpadding

                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    decrypted_chunk = decryptor.update(chunk)
                    buffer += decrypted_chunk

                    # Try to unpad if we have enough data for a full block
                    while len(buffer) >= algorithms.AES.block_size:
                        block = buffer[:algorithms.AES.block_size]
                        try:
                            unpadded_block = unpadder.update(block)
                            outfile.write(unpadded_block)
                            processed_bytes += len(unpadded_block)
                            buffer = buffer[algorithms.AES.block_size:]
                        except ValueError: # Not a full block yet or padding error
                            break
                    if progress_callback:
                        progress_callback(infile.tell() - 32, total_size) # Approximate progress

                final_decrypted_chunk = decryptor.finalize()
                buffer += final_decrypted_chunk
                final_unpadded_chunk = unpadder.update(buffer) + unpadder.finalize()
                outfile.write(final_unpadded_chunk)
                processed_bytes += len(final_unpadded_chunk)
                if progress_callback:
                    progress_callback(total_size, total_size) # Ensure 100%

            logging.info(f"AES-256-CBC: Decrypted '{input_filepath}' to '{output_filepath}'")
        except Exception as e:
            logging.error(f"AES-256-CBC decryption failed for '{input_filepath}': {e}")
            raise

    def generate_key(self, length=256): # Key length in bits
        if length != 256:
            logging.warning("AES-256-CBC plugin only supports 256-bit keys for direct use.")
        return os.urandom(32) # 32 bytes = 256 bits