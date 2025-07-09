# utils.py

import base64
import os
from Crypto.Random import get_random_bytes

KEY_SIZE = 32

def generate_secure_key():
    """Generate a 256-bit secure key, base64 encoded, truncated to 32 chars."""
    return base64.urlsafe_b64encode(get_random_bytes(KEY_SIZE)).decode()[:KEY_SIZE]

def is_file(path):
    return os.path.isfile(path)

def is_folder(path):
    return os.path.isdir(path)

def get_filename(path):
    return os.path.basename(path)

def get_file_extension(path):
    return os.path.splitext(path)[1].lower()

def ensure_output_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def format_size(bytes_size):
    """Convert bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.2f} TB"
