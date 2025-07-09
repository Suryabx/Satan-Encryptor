# crypto_engine.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

BLOCK_SIZE = 64 * 1024
KEY_SIZE = 32

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_file(input_path, key, output_path=None):
    key = key.ljust(KEY_SIZE)[:KEY_SIZE].encode()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    if not output_path:
        output_path = input_path + ".enc"

    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(iv)
        while chunk := f_in.read(BLOCK_SIZE):
            if len(chunk) % 16 != 0:
                chunk = pad(chunk)
            f_out.write(cipher.encrypt(chunk))

    return output_path

def decrypt_file(input_path, key, output_path=None):
    key = key.ljust(KEY_SIZE)[:KEY_SIZE].encode()

    if not output_path:
        output_path = input_path.replace(".enc", ".dec")

    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        iv = f_in.read(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        while chunk := f_in.read(BLOCK_SIZE):
            decrypted = cipher.decrypt(chunk)
            if f_in.tell() == os.fstat(f_in.fileno()).st_size:
                decrypted = unpad(decrypted)
            f_out.write(decrypted)

    return output_path

def encrypt_folder(folder_path, key):
    encrypted_files = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            encrypted = encrypt_file(full_path, key)
            encrypted_files.append(encrypted)
    return encrypted_files

def decrypt_folder(folder_path, key):
    decrypted_files = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".enc"):
                full_path = os.path.join(root, file)
                decrypted = decrypt_file(full_path, key)
                decrypted_files.append(decrypted)
    return decrypted_files
