"""
Encryption Plugins Module
Plugin-based encryption system for Satan Encryptor Suite
"""

import hashlib
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class EncryptionPlugin:
    """Base class for encryption plugins"""
    
    def __init__(self, name, display_name, description, key_size):
        self.name = name
        self.display_name = display_name
        self.description = description
        self.key_size = key_size
        
    def encrypt(self, data, password):
        """Encrypt data with password"""
        raise NotImplementedError
        
    def decrypt(self, encrypted_data, password):
        """Decrypt data with password"""
        raise NotImplementedError
        
    def generate_key(self):
        """Generate a random key"""
        raise NotImplementedError

class AES256Plugin(EncryptionPlugin):
    """AES-256 encryption plugin using Fernet (simplified)"""
    
    def __init__(self):
        super().__init__("aes256", "AES-256", "Advanced Encryption Standard with 256-bit key", 256)
        
    def _derive_key(self, password, salt):
        """Derive key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
        
    def encrypt(self, data, password):
        """Encrypt data using AES-256"""
        try:
            salt = os.urandom(16)
            key = self._derive_key(password, salt)
            f = Fernet(key)
            
            if isinstance(data, str):
                data = data.encode()
                
            encrypted = f.encrypt(data)
            return base64.b64encode(salt + encrypted).decode()
        except Exception as e:
            raise Exception(f"AES encryption failed: {str(e)}")
            
    def decrypt(self, encrypted_data, password):
        """Decrypt data using AES-256"""
        try:
            encrypted_data = base64.b64decode(encrypted_data.encode())
            salt = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            
            key = self._derive_key(password, salt)
            f = Fernet(key)
            
            decrypted = f.decrypt(encrypted)
            return decrypted.decode()
        except Exception as e:
            raise Exception(f"AES decryption failed: {str(e)}")
            
    def generate_key(self):
        """Generate AES key"""
        return base64.b64encode(os.urandom(32)).decode()

class SimpleXORPlugin(EncryptionPlugin):
    """Simple XOR encryption plugin (for demonstration)"""
    
    def __init__(self):
        super().__init__("xor", "XOR Cipher", "Simple XOR encryption (demo only)", 128)
        
    def _generate_key_stream(self, password, length):
        """Generate key stream from password"""
        key_stream = []
        password_bytes = password.encode()
        for i in range(length):
            key_stream.append(password_bytes[i % len(password_bytes)])
        return bytes(key_stream)
        
    def encrypt(self, data, password):
        """Encrypt using XOR"""
        try:
            if isinstance(data, str):
                data = data.encode()
                
            key_stream = self._generate_key_stream(password, len(data))
            encrypted = bytes(a ^ b for a, b in zip(data, key_stream))
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            raise Exception(f"XOR encryption failed: {str(e)}")
            
    def decrypt(self, encrypted_data, password):
        """Decrypt using XOR"""
        try:
            encrypted_data = base64.b64decode(encrypted_data.encode())
            key_stream = self._generate_key_stream(password, len(encrypted_data))
            decrypted = bytes(a ^ b for a, b in zip(encrypted_data, key_stream))
            return decrypted.decode()
        except Exception as e:
            raise Exception(f"XOR decryption failed: {str(e)}")
            
    def generate_key(self):
        """Generate XOR key"""
        return base64.b64encode(os.urandom(16)).decode()

class ROT13Plugin(EncryptionPlugin):
    """ROT13 encryption plugin (for demonstration)"""
    
    def __init__(self):
        super().__init__("rot13", "ROT13", "Simple ROT13 cipher (demo only)", 0)
        
    def encrypt(self, data, password):
        """Encrypt using ROT13"""
        try:
            result = ""
            for char in data:
                if 'a' <= char <= 'z':
                    result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                elif 'A' <= char <= 'Z':
                    result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
                else:
                    result += char
            return base64.b64encode(result.encode()).decode()
        except Exception as e:
            raise Exception(f"ROT13 encryption failed: {str(e)}")
            
    def decrypt(self, encrypted_data, password):
        """Decrypt using ROT13 (same as encrypt)"""
        try:
            data = base64.b64decode(encrypted_data.encode()).decode()
            return self.encrypt(data, password)  # ROT13 is symmetric
        except Exception as e:
            raise Exception(f"ROT13 decryption failed: {str(e)}")
            
    def generate_key(self):
        """Generate ROT13 key (not applicable)"""
        return "ROT13-NO-KEY-NEEDED"

class PluginManager:
    """Manages encryption plugins"""
    
    def __init__(self):
        self.plugins = {}
        self._load_plugins()
        
    def _load_plugins(self):
        """Load available plugins"""
        # Try to load AES plugin (requires cryptography library)
        try:
            self.plugins["aes256"] = AES256Plugin()
        except ImportError:
            print("Warning: cryptography library not available, AES plugin disabled")
            
        # Load simple plugins (no dependencies)
        self.plugins["xor"] = SimpleXORPlugin()
        self.plugins["rot13"] = ROT13Plugin()
        
    def get_plugin(self, name):
        """Get plugin by name"""
        return self.plugins.get(name)
        
    def get_plugin_names(self):
        """Get list of available plugin names"""
        return list(self.plugins.keys())
        
    def list_plugins(self):
        """List all available plugins"""
        return list(self.plugins.values())