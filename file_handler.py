"""
File Handler Module
Handles file operations for encryption and decryption
"""

import os
import shutil
from pathlib import Path

class FileHandler:
    """Handles file operations for the encryption suite"""
    
    def __init__(self):
        self.supported_extensions = ['.txt', '.doc', '.pdf', '.jpg', '.png', '.mp4', '.zip']
        
    def get_files_in_directory(self, directory_path, recursive=True):
        """Get all files in a directory"""
        files = []
        directory = Path(directory_path)
        
        if recursive:
            for file_path in directory.rglob('*'):
                if file_path.is_file():
                    files.append(str(file_path))
        else:
            for file_path in directory.iterdir():
                if file_path.is_file():
                    files.append(str(file_path))
                    
        return files
        
    def read_file(self, file_path, mode='rb'):
        """Read file content"""
        try:
            with open(file_path, mode) as file:
                return file.read()
        except Exception as e:
            raise Exception(f"Failed to read file {file_path}: {str(e)}")
            
    def write_file(self, file_path, content, mode='wb'):
        """Write content to file"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, mode) as file:
                file.write(content)
        except Exception as e:
            raise Exception(f"Failed to write file {file_path}: {str(e)}")
            
    def backup_file(self, file_path):
        """Create a backup of the file"""
        try:
            backup_path = file_path + '.backup'
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception as e:
            raise Exception(f"Failed to backup file {file_path}: {str(e)}")
            
    def encrypt_file(self, file_path, password, plugin):
        """Encrypt a single file"""
        try:
            # Read file content
            if self._is_text_file(file_path):
                content = self.read_file(file_path, 'r')
            else:
                # For binary files, read as bytes and encode to base64
                import base64
                content = base64.b64encode(self.read_file(file_path, 'rb')).decode()
                
            # Encrypt content
            encrypted_content = plugin.encrypt(content, password)
            
            # Write encrypted file
            encrypted_path = file_path + '.enc'
            self.write_file(encrypted_path, encrypted_content.encode(), 'wb')
            
            return True
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return False
            
    def decrypt_file(self, file_path, password, plugin):
        """Decrypt a single file"""
        try:
            # Read encrypted content
            encrypted_content = self.read_file(file_path, 'r')
            
            # Decrypt content
            decrypted_content = plugin.decrypt(encrypted_content, password)
            
            # Determine output path
            if file_path.endswith('.enc'):
                output_path = file_path[:-4]  # Remove .enc extension
            else:
                output_path = file_path + '.decrypted'
                
            # Check if it was a binary file (base64 encoded)
            try:
                import base64
                binary_content = base64.b64decode(decrypted_content)
                self.write_file(output_path, binary_content, 'wb')
            except:
                # It's a text file
                self.write_file(output_path, decrypted_content.encode(), 'wb')
                
            return True
            
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return False
            
    def _is_text_file(self, file_path):
        """Check if file is a text file"""
        text_extensions = ['.txt', '.py', '.js', '.html', '.css', '.json', '.xml', '.csv']
        return any(file_path.lower().endswith(ext) for ext in text_extensions)
        
    def get_file_info(self, file_path):
        """Get file information"""
        try:
            stat = os.stat(file_path)
            return {
                'name': os.path.basename(file_path),
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'extension': os.path.splitext(file_path)[1]
            }
        except Exception as e:
            return None
            
    def is_encrypted_file(self, file_path):
        """Check if file appears to be encrypted"""
        return file_path.endswith('.enc')
        
    def validate_file_path(self, file_path):
        """Validate if file path exists and is accessible"""
        return os.path.exists(file_path) and os.path.isfile(file_path)
        
    def get_safe_filename(self, filename):
        """Get a safe filename by removing invalid characters"""
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        return filename
        
    def ensure_directory_exists(self, directory_path):
        """Ensure directory exists, create if necessary"""
        try:
            os.makedirs(directory_path, exist_ok=True)
            return True
        except Exception as e:
            print(f"Failed to create directory {directory_path}: {str(e)}")
            return False