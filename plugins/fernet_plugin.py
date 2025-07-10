from cryptography.fernet import Fernet
import os
import logging
from base64 import urlsafe_b64encode

class EncryptorPlugin:
    def __init__(self):
        self.name = "Fernet"

    def encrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None):
        f = Fernet(key)
        try:
            with open(input_filepath, 'rb') as infile:
                original_data = infile.read()
            encrypted_data = f.encrypt(original_data)
            with open(output_filepath, 'wb') as outfile:
                outfile.write(encrypted_data)
            logging.info(f"Fernet: Encrypted '{input_filepath}' to '{output_filepath}'")
            if progress_callback:
                progress_callback(len(original_data), len(original_data))
        except Exception as e:
            logging.error(f"Fernet encryption failed for '{input_filepath}': {e}")
            raise

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None):
        f = Fernet(key)
        try:
            with open(input_filepath, 'rb') as infile:
                encrypted_data = infile.read()
            decrypted_data = f.decrypt(encrypted_data)
            with open(output_filepath, 'wb') as outfile:
                outfile.write(decrypted_data)
            logging.info(f"Fernet: Decrypted '{input_filepath}' to '{output_filepath}'")
            if progress_callback:
                progress_callback(len(encrypted_data), len(encrypted_data))
        except Exception as e:
            logging.error(f"Fernet decryption failed for '{input_filepath}': {e}")
            raise

    def generate_key(self, length=None):
        return Fernet.generate_key()