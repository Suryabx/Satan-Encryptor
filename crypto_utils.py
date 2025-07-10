"""
Cryptographic Utilities
Helper functions for encryption operations
"""

import os
import random
import string
import hashlib

class CryptoUtils:
    """Utility class for cryptographic operations"""
    
    @staticmethod
    def generate_random_password(length=16):
        """Generate a random secure password"""
        if length < 4:
            length = 4
            
        # Ensure password has at least one character from each category
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Start with one character from each category
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(symbols)
        ]
        
        # Fill the rest randomly
        all_chars = lowercase + uppercase + digits + symbols
        for _ in range(length - 4):
            password.append(random.choice(all_chars))
            
        # Shuffle the password
        random.shuffle(password)
        return ''.join(password)
        
    @staticmethod
    def calculate_password_strength(password):
        """Calculate password strength and return feedback"""
        if not password:
            return {'score': 0, 'feedback': 'No password', 'color': 'red'}
            
        score = 0
        feedback = ""
        
        # Length scoring
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 20
        if len(password) >= 16:
            score += 10
            
        # Character variety scoring
        if any(c.islower() for c in password):
            score += 10
        if any(c.isupper() for c in password):
            score += 10
        if any(c.isdigit() for c in password):
            score += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 20
            
        # Determine feedback
        if score < 30:
            feedback = "Very Weak"
            color = "red"
        elif score < 50:
            feedback = "Weak"
            color = "orange"
        elif score < 70:
            feedback = "Fair"
            color = "yellow"
        elif score < 90:
            feedback = "Good"
            color = "lightgreen"
        else:
            feedback = "Excellent"
            color = "green"
            
        return {'score': score, 'feedback': feedback, 'color': color}
        
    @staticmethod
    def generate_salt(length=16):
        """Generate a random salt"""
        return os.urandom(length)
        
    @staticmethod
    def hash_password(password, salt=None):
        """Hash a password with salt"""
        if salt is None:
            salt = CryptoUtils.generate_salt()
            
        # Use PBKDF2 for password hashing
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt + dk
        
    @staticmethod
    def verify_password(password, hashed):
        """Verify a password against its hash"""
        salt = hashed[:16]
        key = hashed[16:]
        return CryptoUtils.hash_password(password, salt)[16:] == key
        
    @staticmethod
    def secure_random_bytes(length):
        """Generate secure random bytes"""
        return os.urandom(length)
        
    @staticmethod
    def secure_random_string(length, charset=None):
        """Generate secure random string"""
        if charset is None:
            charset = string.ascii_letters + string.digits
            
        return ''.join(random.choice(charset) for _ in range(length))