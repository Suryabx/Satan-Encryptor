import customtkinter as ctk
import os
import json
import logging
import importlib.util
import sys
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
from base64 import urlsafe_b64encode, b64encode, b64decode
import hashlib
import threading
import time
from PIL import Image, ImageTk # Import Pillow for image handling

# --- Configuration and Global Settings ---
APP_NAME = "Satan Encryptor Suite"
APP_VERSION = "1.0.0"
DEVELOPER_NAME = "Surya B"
GITHUB_URL = "https://github.com/Suryabx"
PLUGINS_DIR = "plugins"
ASSETS_DIR = "assets" # New directory for assets
ICON_FILENAME = "icon.png" # Filename of your icon
LOG_FILE = "satan_encryptor_suite.log"

# Hacker Theme Colors
HACKER_BG_DARK = "#1A1A1A" # Very dark grey
HACKER_ACCENT_GREEN = "#00FF00" # Vibrant green
HACKER_ACCENT_GREEN_HOVER = "#00CC00" # Slightly darker green for hover
HACKER_TEXT_COLOR = "#E0E0E0" # Light grey for text
HACKER_WIDGET_BG = "#2A2A2A" # Darker grey for widget backgrounds
HACKER_WIDGET_BORDER = "#444444" # Subtle border for widgets

# Set up logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE,
                    filemode='a')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

# --- Plugin Management System ---
class PluginManager:
    def __init__(self):
        self.encryption_plugins = {}
        self.load_plugins()

    def load_plugins(self):
        """Discovers and loads encryption plugins from the PLUGINS_DIR."""
        self.encryption_plugins = {}
        if not os.path.exists(PLUGINS_DIR):
            os.makedirs(PLUGINS_DIR)
            logging.info(f"Created plugins directory: {PLUGINS_DIR}")

        for filename in os.listdir(PLUGINS_DIR):
            if filename.endswith("_plugin.py"):
                plugin_name = filename[:-10] # Remove '_plugin.py'
                filepath = os.path.join(PLUGINS_DIR, filename)
                try:
                    spec = importlib.util.spec_from_file_location(plugin_name, filepath)
                    if spec is None:
                        logging.warning(f"Could not load spec for plugin: {filename}")
                        continue
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[plugin_name] = module
                    spec.loader.exec_module(module)

                    # Check if the module has the required interface
                    if hasattr(module, 'EncryptorPlugin') and callable(getattr(module, 'EncryptorPlugin')):
                        plugin_instance = module.EncryptorPlugin()
                        if hasattr(plugin_instance, 'name') and \
                           hasattr(plugin_instance, 'encrypt_file') and callable(getattr(plugin_instance, 'encrypt_file')) and \
                           hasattr(plugin_instance, 'decrypt_file') and callable(getattr(plugin_instance, 'decrypt_file')) and \
                           hasattr(plugin_instance, 'generate_key') and callable(getattr(plugin_instance, 'generate_key')):
                            self.encryption_plugins[plugin_instance.name] = plugin_instance
                            logging.info(f"Loaded encryption plugin: {plugin_instance.name}")
                        else:
                            logging.warning(f"Plugin '{plugin_name}' does not conform to the EncryptorPlugin interface.")
                    else:
                        logging.warning(f"Module '{filename}' does not contain an 'EncryptorPlugin' class.")
                except Exception as e:
                    logging.error(f"Failed to load plugin '{filename}': {e}")
        if not self.encryption_plugins:
            logging.warning("No encryption plugins found. Please add plugins to the 'plugins' directory.")

    def get_plugin_names(self):
        return list(self.encryption_plugins.keys())

    def get_plugin(self, name):
        return self.encryption_plugins.get(name)

# --- Abstract Plugin Interface (for type hinting and consistency) ---
class AbstractEncryptorPlugin:
    def __init__(self):
        self.name = "Abstract" # Must be overridden by concrete plugins

    def encrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None):
        """Encrypts a file.
        Args:
            input_filepath (str): Path to the file to encrypt.
            output_filepath (str): Path where the encrypted file will be saved.
            key (bytes): Encryption key.
            password (str, optional): Password for key derivation (if applicable).
            progress_callback (callable, optional): Callback for progress updates (current_bytes, total_bytes).
        Raises:
            NotImplementedError: If not implemented by the plugin.
        """
        raise NotImplementedError

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None):
        """Decrypts a file.
        Args:
            input_filepath (str): Path to the file to decrypt.
            output_filepath (str): Path where the decrypted file will be saved.
            key (bytes): Decryption key.
            password (str, optional): Password for key derivation (if applicable).
            progress_callback (callable, optional): Callback for progress updates (current_bytes, total_bytes).
        Raises:
            NotImplementedError: If not implemented by the plugin.
        """
        raise NotImplementedError

    def generate_key(self, length=None):
        """Generates a key suitable for the encryption algorithm.
        Args:
            length (int, optional): Desired key length in bits or bytes, if applicable.
        Returns:
            bytes: The generated key.
        Raises:
            NotImplementedError: If not implemented by the plugin.
        """
        raise NotImplementedError


# Create dummy plugin files if they don't exist
def create_dummy_plugins():
    if not os.path.exists(PLUGINS_DIR):
        os.makedirs(PLUGINS_DIR)
    if not os.path.exists(ASSETS_DIR): # Ensure assets directory exists for icon
        os.makedirs(ASSETS_DIR)

    fernet_plugin_code = """
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
"""
    aes_plugin_code = """
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
"""

    rsa_plugin_code = """
import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class EncryptorPlugin:
    def __init__(self):
        self.name = "RSA"

    def generate_key(self, length=2048):
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

    def encrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None):
        # Key here is the public key (PEM string)
        public_key = serialization.load_pem_public_key(key.encode(), backend=default_backend())

        try:
            with open(input_filepath, 'rb') as infile, open(output_filepath, 'wb') as outfile:
                plaintext = infile.read()
                # Max bytes RSA can encrypt directly is key_size_in_bytes - 42 (for OAEP padding)
                max_chunk_size = (public_key.key_size // 8) - 42

                if len(plaintext) > max_chunk_size:
                    raise ValueError(f"File too large for direct RSA encryption. Max {max_chunk_size} bytes. "
                                     "Consider a hybrid encryption approach for large files.")

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

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None):
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
"""

    plugins_to_create = {
        "fernet_plugin.py": fernet_plugin_code,
        "aes_plugin.py": aes_plugin_code,
        "rsa_plugin.py": rsa_plugin_code,
    }

    for filename, content in plugins_to_create.items():
        filepath = os.path.join(PLUGINS_DIR, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write(content)
            logging.info(f"Created dummy plugin: {filepath}")

# Call this function once at the start of the application
create_dummy_plugins()


# --- UI Frames for each Tab ---

class EncryptTab(ctk.CTkFrame):
    def __init__(self, master, plugin_manager, app_settings, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.plugin_manager = plugin_manager
        self.app_settings = app_settings
        self.log_callback = log_callback
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(6, weight=1) # For the log textbox

        self.setup_ui()
        self.update_plugin_options()

    def setup_ui(self):
        # Input File/Folder
        self.input_label = ctk.CTkLabel(self, text="Input File/Folder:", text_color=HACKER_TEXT_COLOR)
        self.input_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.input_path_entry = ctk.CTkEntry(self, placeholder_text="Select file or folder to encrypt",
                                             fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                             border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.input_path_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.browse_input_button = ctk.CTkButton(self, text="Browse", command=self.browse_input,
                                                 fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                                 text_color="black", corner_radius=8)
        self.browse_input_button.grid(row=0, column=2, padx=10, pady=5)

        # Output Folder
        self.output_label = ctk.CTkLabel(self, text="Output Folder:", text_color=HACKER_TEXT_COLOR)
        self.output_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.output_path_entry = ctk.CTkEntry(self, placeholder_text="Select output folder",
                                              fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                              border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.output_path_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        self.browse_output_button = ctk.CTkButton(self, text="Browse", command=self.browse_output,
                                                  fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                                  text_color="black", corner_radius=8)
        self.browse_output_button.grid(row=1, column=2, padx=10, pady=5)

        # Encryption Algorithm
        self.algo_label = ctk.CTkLabel(self, text="Encryption Algorithm:", text_color=HACKER_TEXT_COLOR)
        self.algo_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown = ctk.CTkComboBox(self, values=self.algo_options, command=self.on_algo_selected,
                                             fg_color=HACKER_WIDGET_BG, button_color=HACKER_ACCENT_GREEN,
                                             button_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             border_color=HACKER_WIDGET_BORDER, text_color=HACKER_TEXT_COLOR,
                                             dropdown_fg_color=HACKER_WIDGET_BG, dropdown_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             dropdown_text_color=HACKER_TEXT_COLOR, corner_radius=8)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
        else:
            self.algo_dropdown.set("No Plugins Loaded")
            self.algo_dropdown.configure(state="disabled")
        self.algo_dropdown.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        # Key/Password Input
        self.key_label = ctk.CTkLabel(self, text="Key / Password:", text_color=HACKER_TEXT_COLOR)
        self.key_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.key_input_entry = ctk.CTkEntry(self, placeholder_text="Enter key or password",
                                            fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                            border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.key_input_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        self.show_key_checkbox = ctk.CTkCheckBox(self, text="Show", command=self.toggle_key_visibility,
                                                 fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                                 hover_color=HACKER_ACCENT_GREEN_HOVER, corner_radius=8)
        self.show_key_checkbox.grid(row=3, column=2, padx=10, pady=5, sticky="w")
        self.key_input_entry.configure(show="*") # Start with hidden password

        # Password Strength Meter (Placeholder)
        self.strength_label = ctk.CTkLabel(self, text="Password Strength: N/A", text_color="gray")
        self.strength_label.grid(row=4, column=1, padx=10, pady=0, sticky="w")
        self.key_input_entry.bind("<KeyRelease>", self.update_password_strength)

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal",
                                               fg_color=HACKER_WIDGET_BG, progress_color=HACKER_ACCENT_GREEN,
                                               corner_radius=8)
        self.progress_bar.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.progress_bar.set(0)

        # Encrypt Button
        self.encrypt_button = ctk.CTkButton(self, text="Encrypt File(s)", command=self.start_encryption_thread,
                                            fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                            text_color="black", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.encrypt_button.grid(row=6, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                          border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=7, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

    def update_plugin_options(self):
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown.configure(values=self.algo_options)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
            self.algo_dropdown.configure(state="normal")
        else:
            self.algo_dropdown.set("No Plugins Loaded")
            self.algo_dropdown.configure(state="disabled")

    def browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_path_entry.delete(0, ctk.END)
            self.input_path_entry.insert(0, file_path)
        else:
            # If no file selected, try folder
            folder_path = filedialog.askdirectory()
            if folder_path:
                self.input_path_entry.delete(0, ctk.END)
                self.input_path_entry.insert(0, folder_path)

    def browse_output(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.output_path_entry.delete(0, ctk.END)
            self.output_path_entry.insert(0, folder_path)

    def toggle_key_visibility(self):
        if self.show_key_checkbox.get() == 1:
            self.key_input_entry.configure(show="")
        else:
            self.key_input_entry.configure(show="*")

    def update_password_strength(self, event=None):
        password = self.key_input_entry.get()
        strength = self.calculate_password_strength(password)
        if strength < 30:
            self.strength_label.configure(text="Strength: Weak", text_color="red")
        elif strength < 60:
            self.strength_label.configure(text="Strength: Medium", text_color="orange")
        else:
            self.strength_label.configure(text="Strength: Strong", text_color="green")

    def calculate_password_strength(self, password):
        # Simple strength calculation (can be improved)
        length_score = min(len(password) * 4, 40)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        complexity_score = 0
        if has_upper: complexity_score += 10
        if has_lower: complexity_score += 10
        if has_digit: complexity_score += 10
        if has_symbol: complexity_score += 15

        return length_score + complexity_score

    def on_algo_selected(self, choice):
        logging.info(f"Encryption algorithm selected: {choice}")
        # You might want to adjust UI elements based on selected algorithm (e.g., key input type)
        if choice == "RSA":
            self.key_input_entry.configure(placeholder_text="Enter Public Key (PEM)")
            self.key_label.configure(text="Public Key:")
        else:
            self.key_input_entry.configure(placeholder_text="Enter key or password")
            self.key_label.configure(text="Key / Password:")


    def start_encryption_thread(self):
        input_path = self.input_path_entry.get()
        output_folder = self.output_path_entry.get()
        algo_name = self.algo_dropdown.get()
        key_or_password = self.key_input_entry.get()

        if not input_path or not output_folder or not algo_name or not key_or_password:
            messagebox.showerror("Input Error", "All fields must be filled.")
            return

        if not os.path.exists(input_path):
            messagebox.showerror("Input Error", "Input file or folder does not exist.")
            return

        if not os.path.isdir(output_folder):
            messagebox.showerror("Input Error", "Output folder does not exist or is not a directory.")
            return

        self.encrypt_button.configure(state="disabled", text="Encrypting...")
        self.progress_bar.set(0)

        # Determine if it's a file or folder
        if os.path.isfile(input_path):
            target_paths = [input_path]
        elif os.path.isdir(input_path):
            target_paths = []
            for root, _, files in os.walk(input_path):
                for file in files:
                    target_paths.append(os.path.join(root, file))
        else:
            messagebox.showerror("Input Error", "Invalid input path.")
            self.encrypt_button.configure(state="normal", text="Encrypt File(s)")
            return

        threading.Thread(target=self._perform_encryption, args=(target_paths, output_folder, algo_name, key_or_password)).start()

    def _perform_encryption(self, input_paths, output_folder, algo_name, key_or_password):
        plugin = self.plugin_manager.get_plugin(algo_name)
        if not plugin:
            messagebox.showerror("Encryption Error", f"Encryption plugin '{algo_name}' not found.")
            self.after(0, lambda: self.encrypt_button.configure(state="normal", text="Encrypt File(s)"))
            return

        total_files = len(input_paths)
        if total_files == 0:
            messagebox.showinfo("Encryption Info", "No files found to encrypt.")
            self.after(0, lambda: self.encrypt_button.configure(state="normal", text="Encrypt File(s)"))
            return

        overall_progress_per_file = 1.0 / total_files

        try:
            for i, input_path in enumerate(input_paths):
                relative_path = os.path.relpath(input_path, os.path.dirname(input_paths[0]) if len(input_paths) > 1 else os.path.dirname(input_path))
                output_filepath = os.path.join(output_folder, relative_path + ".enc")
                os.makedirs(os.path.dirname(output_filepath), exist_ok=True)

                if os.path.exists(output_filepath) and not self.app_settings.get("overwrite_files", False):
                    response = messagebox.askyesno("Confirm Overwrite",
                                                   f"'{output_filepath}' already exists. Overwrite?")
                    if not response:
                        logging.info(f"Skipping encryption of '{input_path}' due to overwrite prevention.")
                        continue

                def file_progress_callback(current, total):
                    # Update progress bar for the current file, scaled to overall progress
                    file_progress = current / total if total > 0 else 0
                    overall_progress = (i * overall_progress_per_file) + (file_progress * overall_progress_per_file)
                    self.after(0, lambda: self.progress_bar.set(overall_progress))

                # Determine if key_or_password is a direct key (bytes) or a password (string)
                # This logic depends on how your plugins handle keys vs passwords
                if algo_name == "Fernet" or algo_name == "AES-256-CBC": # Fernet expects b64 key, AES expects bytes
                    try:
                        key_bytes = key_or_password.encode() # Try encoding as bytes
                        # For Fernet, it must be URL-safe base64
                        if algo_name == "Fernet":
                            try:
                                Fernet(key_bytes) # Validate if it's a valid Fernet key
                            except ValueError:
                                raise ValueError("Invalid Fernet key format. Must be URL-safe base64.")
                        # For AES, it must be 32 bytes if used directly
                        elif algo_name == "AES-256-CBC" and len(key_bytes) != 32:
                             # If not 32 bytes, treat as password for derivation
                            plugin.encrypt_file(input_path, output_filepath, key=None, password=key_or_password, progress_callback=file_progress_callback)
                            logging.info(f"Used password for AES-256-CBC encryption.")
                            continue # Skip the direct key path below
                        key_arg = key_bytes
                        password_arg = None
                    except Exception:
                        # If encoding fails or key is not valid, treat as password
                        key_arg = None
                        password_arg = key_or_password
                elif algo_name == "RSA": # RSA expects PEM string for public key
                    key_arg = key_or_password
                    password_arg = None
                else: # Default to treating as password if not explicitly handled
                    key_arg = None
                    password_arg = key_or_password

                plugin.encrypt_file(input_path, output_filepath, key=key_arg, password=password_arg, progress_callback=file_progress_callback)
                self.log_callback.log(f"Successfully encrypted: {input_path}")

            self.after(0, lambda: self.progress_bar.set(1.0))
            messagebox.showinfo("Encryption Complete", "File(s) encrypted successfully!")
        except ValueError as ve:
            messagebox.showerror("Encryption Error", f"Input Error: {ve}")
            self.log_callback.log(f"Encryption failed: {ve}", level="error")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"An error occurred during encryption: {e}")
            self.log_callback.log(f"Encryption failed: {e}", level="error")
        finally:
            self.after(0, lambda: self.encrypt_button.configure(state="normal", text="Encrypt File(s)"))


class DecryptTab(ctk.CTkFrame):
    def __init__(self, master, plugin_manager, app_settings, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.plugin_manager = plugin_manager
        self.app_settings = app_settings
        self.log_callback = log_callback
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(6, weight=1) # For the log textbox

        self.setup_ui()
        self.update_plugin_options()

    def setup_ui(self):
        # Input Encrypted File/Folder
        self.input_label = ctk.CTkLabel(self, text="Input Encrypted File/Folder:", text_color=HACKER_TEXT_COLOR)
        self.input_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.input_path_entry = ctk.CTkEntry(self, placeholder_text="Select encrypted file or folder",
                                             fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                             border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.input_path_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.browse_input_button = ctk.CTkButton(self, text="Browse", command=self.browse_input,
                                                 fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                                 text_color="black", corner_radius=8)
        self.browse_input_button.grid(row=0, column=2, padx=10, pady=5)

        # Output Folder
        self.output_label = ctk.CTkLabel(self, text="Output Folder:", text_color=HACKER_TEXT_COLOR)
        self.output_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.output_path_entry = ctk.CTkEntry(self, placeholder_text="Select output folder for decrypted files",
                                              fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                              border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.output_path_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        self.browse_output_button = ctk.CTkButton(self, text="Browse", command=self.browse_output,
                                                  fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                                  text_color="black", corner_radius=8)
        self.browse_output_button.grid(row=1, column=2, padx=10, pady=5)

        # Decryption Algorithm
        self.algo_label = ctk.CTkLabel(self, text="Decryption Algorithm:", text_color=HACKER_TEXT_COLOR)
        self.algo_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown = ctk.CTkComboBox(self, values=self.algo_options, command=self.on_algo_selected,
                                             fg_color=HACKER_WIDGET_BG, button_color=HACKER_ACCENT_GREEN,
                                             button_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             border_color=HACKER_WIDGET_BORDER, text_color=HACKER_TEXT_COLOR,
                                             dropdown_fg_color=HACKER_WIDGET_BG, dropdown_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             dropdown_text_color=HACKER_TEXT_COLOR, corner_radius=8)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
        else:
            self.algo_dropdown.set("No Plugins Loaded")
            self.algo_dropdown.configure(state="disabled")
        self.algo_dropdown.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        # Key/Password Input
        self.key_label = ctk.CTkLabel(self, text="Key / Password:", text_color=HACKER_TEXT_COLOR)
        self.key_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.key_input_entry = ctk.CTkEntry(self, placeholder_text="Enter key or password for decryption",
                                            fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                            border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.key_input_entry.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        self.show_key_checkbox = ctk.CTkCheckBox(self, text="Show", command=self.toggle_key_visibility,
                                                 fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                                 hover_color=HACKER_ACCENT_GREEN_HOVER, corner_radius=8)
        self.show_key_checkbox.grid(row=3, column=2, padx=10, pady=5, sticky="w")
        self.key_input_entry.configure(show="*") # Start with hidden password

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal",
                                               fg_color=HACKER_WIDGET_BG, progress_color=HACKER_ACCENT_GREEN,
                                               corner_radius=8)
        self.progress_bar.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.progress_bar.set(0)

        # Decrypt Button
        self.decrypt_button = ctk.CTkButton(self, text="Decrypt File(s)", command=self.start_decryption_thread,
                                            fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                            text_color="black", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.decrypt_button.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                          border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=6, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

    def update_plugin_options(self):
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown.configure(values=self.algo_options)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
            self.algo_dropdown.configure(state="normal")
        else:
            self.algo_dropdown.set("No Plugins Loaded")
            self.algo_dropdown.configure(state="disabled")

    def browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_path_entry.delete(0, ctk.END)
            self.input_path_entry.insert(0, file_path)
        else:
            # If no file selected, try folder
            folder_path = filedialog.askdirectory()
            if folder_path:
                self.input_path_entry.delete(0, ctk.END)
                self.input_path_entry.insert(0, folder_path)

    def browse_output(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.output_path_entry.delete(0, ctk.END)
            self.output_path_entry.insert(0, folder_path)

    def toggle_key_visibility(self):
        if self.show_key_checkbox.get() == 1:
            self.key_input_entry.configure(show="")
        else:
            self.key_input_entry.configure(show="*")

    def on_algo_selected(self, choice):
        logging.info(f"Decryption algorithm selected: {choice}")
        if choice == "RSA":
            self.key_input_entry.configure(placeholder_text="Enter Private Key (PEM)")
            self.key_label.configure(text="Private Key:")
        else:
            self.key_input_entry.configure(placeholder_text="Enter key or password for decryption")
            self.key_label.configure(text="Key / Password:")

    def start_decryption_thread(self):
        input_path = self.input_path_entry.get()
        output_folder = self.output_path_entry.get()
        algo_name = self.algo_dropdown.get()
        key_or_password = self.key_input_entry.get()

        if not input_path or not output_folder or not algo_name or not key_or_password:
            messagebox.showerror("Input Error", "All fields must be filled.")
            return

        if not os.path.exists(input_path):
            messagebox.showerror("Input Error", "Input file or folder does not exist.")
            return

        if not os.path.isdir(output_folder):
            messagebox.showerror("Input Error", "Output folder does not exist or is not a directory.")
            return

        self.decrypt_button.configure(state="disabled", text="Decrypting...")
        self.progress_bar.set(0)

        # Determine if it's a file or folder
        if os.path.isfile(input_path):
            target_paths = [input_path]
        elif os.path.isdir(input_path):
            target_paths = []
            for root, _, files in os.walk(input_path):
                for file in files:
                    target_paths.append(os.path.join(root, file))
        else:
            messagebox.showerror("Input Error", "Invalid input path.")
            self.decrypt_button.configure(state="normal", text="Decrypt File(s)")
            return

        threading.Thread(target=self._perform_decryption, args=(target_paths, output_folder, algo_name, key_or_password)).start()

    def _perform_decryption(self, input_paths, output_folder, algo_name, key_or_password):
        plugin = self.plugin_manager.get_plugin(algo_name)
        if not plugin:
            messagebox.showerror("Decryption Error", f"Decryption plugin '{algo_name}' not found.")
            self.after(0, lambda: self.decrypt_button.configure(state="normal", text="Decrypt File(s)"))
            return

        total_files = len(input_paths)
        if total_files == 0:
            messagebox.showinfo("Decryption Info", "No files found to decrypt.")
            self.after(0, lambda: self.decrypt_button.configure(state="normal", text="Decrypt File(s)"))
            return

        overall_progress_per_file = 1.0 / total_files

        try:
            for i, input_path in enumerate(input_paths):
                # Remove .enc extension if present
                if input_path.endswith(".enc"):
                    original_filename = os.path.basename(input_path[:-4])
                else:
                    original_filename = os.path.basename(input_path)

                relative_path = os.path.relpath(input_path, os.path.dirname(input_paths[0]) if len(input_paths) > 1 else os.path.dirname(input_path))
                # Adjust relative path to remove .enc if it was added
                if relative_path.endswith(".enc"):
                    relative_path = relative_path[:-4]

                output_filepath = os.path.join(output_folder, relative_path)
                os.makedirs(os.path.dirname(output_filepath), exist_ok=True)

                if os.path.exists(output_filepath) and not self.app_settings.get("overwrite_files", False):
                    response = messagebox.askyesno("Confirm Overwrite",
                                                   f"'{output_filepath}' already exists. Overwrite?")
                    if not response:
                        logging.info(f"Skipping decryption of '{input_path}' due to overwrite prevention.")
                        continue

                def file_progress_callback(current, total):
                    file_progress = current / total if total > 0 else 0
                    overall_progress = (i * overall_progress_per_file) + (file_progress * overall_progress_per_file)
                    self.after(0, lambda: self.progress_bar.set(overall_progress))

                # Determine if key_or_password is a direct key (bytes) or a password (string)
                if algo_name == "Fernet" or algo_name == "AES-256-CBC": # Fernet expects b64 key, AES expects bytes
                    try:
                        key_bytes = key_or_password.encode()
                        if algo_name == "Fernet":
                            try:
                                Fernet(key_bytes) # Validate if it's a valid Fernet key
                            except ValueError:
                                raise ValueError("Invalid Fernet key format. Must be URL-safe base64.")
                        elif algo_name == "AES-256-CBC" and len(key_bytes) != 32:
                            plugin.decrypt_file(input_path, output_filepath, key=None, password=key_or_password, progress_callback=file_progress_callback)
                            logging.info(f"Used password for AES-256-CBC decryption.")
                            continue
                        key_arg = key_bytes
                        password_arg = None
                    except Exception:
                        key_arg = None
                        password_arg = key_or_password
                elif algo_name == "RSA": # RSA expects PEM string for private key
                    key_arg = key_or_password
                    password_arg = None
                else:
                    key_arg = None
                    password_arg = key_or_password

                plugin.decrypt_file(input_path, output_filepath, key=key_arg, password=password_arg, progress_callback=file_progress_callback)
                self.log_callback.log(f"Successfully decrypted: {input_path}")

            self.after(0, lambda: self.progress_bar.set(1.0))
            messagebox.showinfo("Decryption Complete", "File(s) decrypted successfully!")
        except ValueError as ve:
            messagebox.showerror("Decryption Error", f"Key/Input Error: {ve}")
            self.log_callback.log(f"Decryption failed: {ve}", level="error")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during decryption: {e}")
            self.log_callback.log(f"Decryption failed: {e}", level="error")
        finally:
            self.after(0, lambda: self.decrypt_button.configure(state="normal", text="Decrypt File(s)"))


class GenerateKeysTab(ctk.CTkFrame):
    def __init__(self, master, plugin_manager, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.plugin_manager = plugin_manager
        self.log_callback = log_callback
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(5, weight=1) # For the log textbox

        self.setup_ui()
        self.update_plugin_options()

    def setup_ui(self):
        # Algorithm Selection
        self.algo_label = ctk.CTkLabel(self, text="Algorithm for Key Generation:", text_color=HACKER_TEXT_COLOR)
        self.algo_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown = ctk.CTkComboBox(self, values=self.algo_options, command=self.on_algo_selected,
                                             fg_color=HACKER_WIDGET_BG, button_color=HACKER_ACCENT_GREEN,
                                             button_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             border_color=HACKER_WIDGET_BORDER, text_color=HACKER_TEXT_COLOR,
                                             dropdown_fg_color=HACKER_WIDGET_BG, dropdown_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             dropdown_text_color=HACKER_TEXT_COLOR, corner_radius=8)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
        else:
            self.algo_dropdown.set("No Plugins Loaded")
            self.algo_dropdown.configure(state="disabled")
        self.algo_dropdown.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        # Key Length (Optional, for RSA)
        self.key_length_label = ctk.CTkLabel(self, text="Key Length (bits, for RSA):", text_color=HACKER_TEXT_COLOR)
        self.key_length_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.key_length_entry = ctk.CTkEntry(self, placeholder_text="e.g., 2048, 4096 (for RSA)",
                                             fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                             border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.key_length_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        self.key_length_entry.insert(0, "2048") # Default for RSA

        # Generate Button
        self.generate_button = ctk.CTkButton(self, text="Generate Key(s)", command=self.generate_key,
                                             fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             text_color="black", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.generate_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        # Generated Key Output
        self.output_label = ctk.CTkLabel(self, text="Generated Key(s):", text_color=HACKER_TEXT_COLOR)
        self.output_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.key_output_textbox = ctk.CTkTextbox(self, height=150, state="disabled", wrap="word",
                                                 fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                                 border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.key_output_textbox.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

        self.copy_key_button = ctk.CTkButton(self, text="Copy Key(s) to Clipboard", command=self.copy_key,
                                             fg_color=HACKER_WIDGET_BG, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             text_color=HACKER_TEXT_COLOR, border_color=HACKER_WIDGET_BORDER,
                                             corner_radius=8)
        self.copy_key_button.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                          border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

    def update_plugin_options(self):
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown.configure(values=self.algo_options)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
            self.algo_dropdown.configure(state="normal")
        else:
            self.algo_dropdown.set("No Plugins Loaded")
            self.algo_dropdown.configure(state="disabled")

    def on_algo_selected(self, choice):
        if choice == "RSA":
            self.key_length_entry.configure(state="normal")
        else:
            self.key_length_entry.configure(state="disabled")
            self.key_length_entry.delete(0, ctk.END) # Clear for non-RSA

    def generate_key(self):
        algo_name = self.algo_dropdown.get()
        plugin = self.plugin_manager.get_plugin(algo_name)

        if not plugin:
            messagebox.showerror("Error", f"Plugin '{algo_name}' not found.")
            return

        self.generate_button.configure(state="disabled", text="Generating...")
        self.key_output_textbox.configure(state="normal")
        self.key_output_textbox.delete("1.0", ctk.END)
        self.key_output_textbox.insert(ctk.END, "Generating key(s)...")
        self.key_output_textbox.configure(state="disabled")

        threading.Thread(target=self._perform_key_generation, args=(plugin, algo_name)).start()

    def _perform_key_generation(self, plugin, algo_name):
        try:
            key_length = None
            if algo_name == "RSA":
                try:
                    key_length = int(self.key_length_entry.get())
                    if key_length not in [1024, 2048, 3072, 4096]: # Common RSA key sizes
                        raise ValueError("Invalid RSA key length. Must be 1024, 2048, 3072, or 4096.")
                except ValueError as e:
                    self.after(0, lambda: messagebox.showerror("Input Error", f"Invalid key length: {e}"))
                    self.after(0, lambda: self.generate_button.configure(state="normal", text="Generate Key(s)"))
                    self.after(0, lambda: self.key_output_textbox.configure(state="normal"))
                    self.after(0, lambda: self.key_output_textbox.delete("1.0", ctk.END))
                    self.after(0, lambda: self.key_output_textbox.configure(state="disabled"))
                    return

            generated_key = plugin.generate_key(length=key_length)

            self.after(0, lambda: self.key_output_textbox.configure(state="normal"))
            self.after(0, lambda: self.key_output_textbox.delete("1.0", ctk.END))

            if isinstance(generated_key, dict): # For RSA, returns dict with public/private
                self.after(0, lambda: self.key_output_textbox.insert(ctk.END, "--- Public Key ---\n"))
                self.after(0, lambda: self.key_output_textbox.insert(ctk.END, generated_key.get("public_key", "N/A") + "\n\n"))
                self.after(0, lambda: self.key_output_textbox.insert(ctk.END, "--- Private Key ---\n"))
                self.after(0, lambda: self.key_output_textbox.insert(ctk.END, generated_key.get("private_key", "N/A") + "\n"))
            elif isinstance(generated_key, bytes):
                self.after(0, lambda: self.key_output_textbox.insert(ctk.END, f"{generated_key.decode('utf-8', errors='ignore')}\n"))
                self.after(0, lambda: self.key_output_textbox.insert(ctk.END, f"(Base64 Encoded: {urlsafe_b64encode(generated_key).decode()})\n"))
            else:
                self.after(0, lambda: self.key_output_textbox.insert(ctk.END, str(generated_key) + "\n"))

            self.after(0, lambda: self.key_output_textbox.configure(state="disabled"))
            self.log_callback.log(f"Generated {algo_name} key(s).")
            self.after(0, lambda: messagebox.showinfo("Key Generation", f"{algo_name} key(s) generated successfully!"))

        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Key Generation Error", f"Failed to generate key: {e}"))
            self.log_callback.log(f"Key generation failed: {e}", level="error")
            self.after(0, lambda: self.key_output_textbox.configure(state="normal"))
            self.after(0, lambda: self.key_output_textbox.delete("1.0", ctk.END))
            self.after(0, lambda: self.key_output_textbox.insert(ctk.END, f"Error: {e}"))
            self.after(0, lambda: self.key_output_textbox.configure(state="disabled"))
        finally:
            self.after(0, lambda: self.generate_button.configure(state="normal", text="Generate Key(s)"))

    def copy_key(self):
        key_text = self.key_output_textbox.get("1.0", ctk.END).strip()
        if key_text:
            self.clipboard_clear()
            self.clipboard_append(key_text)
            messagebox.showinfo("Copy to Clipboard", "Key(s) copied to clipboard!")
            self.log_callback.log("Key(s) copied to clipboard.")
        else:
            messagebox.showwarning("Copy to Clipboard", "No key to copy.")


class SettingsTab(ctk.CTkFrame):
    def __init__(self, master, app_settings, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.app_settings = app_settings
        self.log_callback = log_callback
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(5, weight=1) # For the log textbox

        self.setup_ui()
        self.load_settings()

    def setup_ui(self):
        # Theme Selector
        self.theme_label = ctk.CTkLabel(self, text="Theme:", text_color=HACKER_TEXT_COLOR)
        self.theme_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.theme_options = ["Dark", "Light", "System"]
        self.theme_dropdown = ctk.CTkComboBox(self, values=self.theme_options, command=self.change_theme,
                                             fg_color=HACKER_WIDGET_BG, button_color=HACKER_ACCENT_GREEN,
                                             button_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             border_color=HACKER_WIDGET_BORDER, text_color=HACKER_TEXT_COLOR,
                                             dropdown_fg_color=HACKER_WIDGET_BG, dropdown_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                             dropdown_text_color=HACKER_TEXT_COLOR, corner_radius=8)
        self.theme_dropdown.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        # Auto-clear Logs Toggle
        self.auto_clear_logs_checkbox = ctk.CTkCheckBox(self, text="Auto-clear logs on startup",
                                                        command=self.toggle_auto_clear_logs,
                                                        fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                                        hover_color=HACKER_ACCENT_GREEN_HOVER, corner_radius=8)
        self.auto_clear_logs_checkbox.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        # Overwrite Files Confirmation Toggle
        self.overwrite_files_checkbox = ctk.CTkCheckBox(self, text="Confirm before overwriting files",
                                                        command=self.toggle_overwrite_files,
                                                        fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                                        hover_color=HACKER_ACCENT_GREEN_HOVER, corner_radius=8)
        self.overwrite_files_checkbox.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        # Language Selector (Placeholder)
        self.language_label = ctk.CTkLabel(self, text="Language (WIP):", text_color=HACKER_TEXT_COLOR)
        self.language_label.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.language_options = ["English", "Spanish", "French"] # Example languages
        self.language_dropdown = ctk.CTkComboBox(self, values=self.language_options, state="disabled",
                                                 fg_color=HACKER_WIDGET_BG, button_color=HACKER_WIDGET_BORDER,
                                                 button_hover_color=HACKER_WIDGET_BORDER,
                                                 border_color=HACKER_WIDGET_BORDER, text_color=HACKER_TEXT_COLOR,
                                                 dropdown_fg_color=HACKER_WIDGET_BG, dropdown_hover_color=HACKER_WIDGET_BORDER,
                                                 dropdown_text_color=HACKER_TEXT_COLOR, corner_radius=8) # Disabled for now
        self.language_dropdown.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        self.language_dropdown.set("English")

        # Export/Import Configuration
        self.export_button = ctk.CTkButton(self, text="Export Settings", command=self.export_settings,
                                           fg_color=HACKER_WIDGET_BG, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                           text_color=HACKER_TEXT_COLOR, border_color=HACKER_WIDGET_BORDER,
                                           corner_radius=8)
        self.export_button.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
        self.import_button = ctk.CTkButton(self, text="Import Settings", command=self.import_settings,
                                           fg_color=HACKER_WIDGET_BG, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                           text_color=HACKER_TEXT_COLOR, border_color=HACKER_WIDGET_BORDER,
                                           corner_radius=8)
        self.import_button.grid(row=4, column=1, padx=10, pady=10, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                          border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

    def load_settings(self):
        self.theme_dropdown.set(self.app_settings.get("theme", "System"))
        self.auto_clear_logs_checkbox.select() if self.app_settings.get("auto_clear_logs", False) else self.auto_clear_logs_checkbox.deselect()
        self.overwrite_files_checkbox.select() if self.app_settings.get("overwrite_files", False) else self.overwrite_files_checkbox.deselect()

    def change_theme(self, new_theme):
        ctk.set_appearance_mode(new_theme)
        self.app_settings["theme"] = new_theme
        self.log_callback.log(f"Theme changed to {new_theme}")

    def toggle_auto_clear_logs(self):
        self.app_settings["auto_clear_logs"] = bool(self.auto_clear_logs_checkbox.get())
        self.log_callback.log(f"Auto-clear logs on startup set to {self.app_settings['auto_clear_logs']}")

    def toggle_overwrite_files(self):
        self.app_settings["overwrite_files"] = bool(self.overwrite_files_checkbox.get())
        self.log_callback.log(f"Confirm overwrite files set to {self.app_settings['overwrite_files']}")

    def export_settings(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json")],
                                                 title="Export Settings")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.app_settings, f, indent=4)
                messagebox.showinfo("Export Settings", "Settings exported successfully!")
                self.log_callback.log(f"Settings exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export settings: {e}")
                self.log_callback.log(f"Failed to export settings: {e}", level="error")

    def import_settings(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")],
                                               title="Import Settings")
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    imported_settings = json.load(f)
                self.app_settings.update(imported_settings) # Update current settings
                self.load_settings() # Reload UI to reflect new settings
                messagebox.showinfo("Import Settings", "Settings imported successfully! Restart app for full effect.")
                self.log_callback.log(f"Settings imported from {file_path}")
            except json.JSONDecodeError:
                messagebox.showerror("Import Error", "Invalid JSON file.")
                self.log_callback.log("Failed to import settings: Invalid JSON file.", level="error")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import settings: {e}")
                self.log_callback.log(f"Failed to import settings: {e}", level="error")


class AboutTab(ctk.CTkFrame):
    def __init__(self, master, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.log_callback = log_callback
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1) # For the log textbox

        self.setup_ui()

    def setup_ui(self):
        self.app_name_label = ctk.CTkLabel(self, text=APP_NAME, font=ctk.CTkFont(size=24, weight="bold"), text_color=HACKER_TEXT_COLOR)
        self.app_name_label.grid(row=0, column=0, padx=20, pady=10, sticky="n")

        self.version_label = ctk.CTkLabel(self, text=f"Version: {APP_VERSION}", font=ctk.CTkFont(size=14), text_color=HACKER_TEXT_COLOR)
        self.version_label.grid(row=1, column=0, padx=20, pady=5, sticky="n")

        self.developer_label = ctk.CTkLabel(self, text=f"Developed by: {DEVELOPER_NAME}", font=ctk.CTkFont(size=14), text_color=HACKER_TEXT_COLOR)
        self.developer_label.grid(row=2, column=0, padx=20, pady=5, sticky="n")

        self.github_button = ctk.CTkButton(self, text="View GitHub", command=self.open_github,
                                           fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                           text_color="black", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.github_button.grid(row=3, column=0, padx=20, pady=10, sticky="n")

        self.license_label = ctk.CTkLabel(self, text="License: MIT License", font=ctk.CTkFont(size=12), text_color=HACKER_TEXT_COLOR)
        self.license_label.grid(row=4, column=0, padx=20, pady=5, sticky="n")

        self.feedback_label = ctk.CTkLabel(self, text="For feedback or contact, please visit the GitHub page.", font=ctk.CTkFont(size=12), text_color=HACKER_TEXT_COLOR)
        self.feedback_label.grid(row=5, column=0, padx=20, pady=5, sticky="n")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                          border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=6, column=0, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

    def open_github(self):
        import webbrowser
        webbrowser.open_new(GITHUB_URL)
        self.log_callback.log(f"Opened GitHub link: {GITHUB_URL}")

class PluginsTab(ctk.CTkFrame):
    def __init__(self, master, plugin_manager, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.plugin_manager = plugin_manager
        self.log_callback = log_callback
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1) # For the log textbox

        self.setup_ui()
        self.load_plugin_list()

    def setup_ui(self):
        self.title_label = ctk.CTkLabel(self, text="Loaded Encryption Plugins", font=ctk.CTkFont(size=18, weight="bold"), text_color=HACKER_TEXT_COLOR)
        self.title_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.plugin_list_frame = ctk.CTkScrollableFrame(self, height=200,
                                                        fg_color=HACKER_WIDGET_BG, border_color=HACKER_WIDGET_BORDER,
                                                        corner_radius=8)
        self.plugin_list_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.plugin_list_frame.grid_columnconfigure(0, weight=1)

        self.reload_button = ctk.CTkButton(self, text="Reload Plugins", command=self.reload_plugins,
                                           fg_color=HACKER_ACCENT_GREEN, hover_color=HACKER_ACCENT_GREEN_HOVER,
                                           text_color="black", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.reload_button.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=HACKER_WIDGET_BG, text_color=HACKER_TEXT_COLOR,
                                          border_color=HACKER_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

    def load_plugin_list(self):
        # Clear existing labels
        for widget in self.plugin_list_frame.winfo_children():
            widget.destroy()

        plugins = self.plugin_manager.get_plugin_names()
        if plugins:
            for i, plugin_name in enumerate(plugins):
                plugin_label = ctk.CTkLabel(self.plugin_list_frame, text=f"- {plugin_name}", font=ctk.CTkFont(size=14),
                                            text_color=HACKER_TEXT_COLOR)
                plugin_label.grid(row=i, column=0, padx=5, pady=2, sticky="w")
        else:
            no_plugins_label = ctk.CTkLabel(self.plugin_list_frame, text="No plugins found. Place .py files in the 'plugins' folder.",
                                            font=ctk.CTkFont(size=14, slant="italic"), text_color=HACKER_TEXT_COLOR)
            no_plugins_label.grid(row=0, column=0, padx=5, pady=10, sticky="w")

    def reload_plugins(self):
        self.log_callback.log("Reloading plugins...")
        self.plugin_manager.load_plugins()
        self.load_plugin_list()
        # Inform other tabs to update their plugin dropdowns
        self.master.master.update_plugin_dropdowns()
        self.log_callback.log("Plugins reloaded.")
        messagebox.showinfo("Plugins", "Plugins reloaded successfully!")


# --- Custom Log Handler for UI ---
class UILogHandler(logging.Handler):
    def __init__(self, master_app):
        super().__init__()
        self.master_app = master_app
        self.textbox = None
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    def set_textbox(self, textbox):
        self.textbox = textbox

    def emit(self, record):
        if self.textbox:
            msg = self.format(record)
            self.master_app.after(0, self._insert_log, msg) # Thread-safe update

    def _insert_log(self, msg):
        if self.textbox:
            self.textbox.configure(state="normal")
            self.textbox.insert(ctk.END, msg + "\n")
            self.textbox.see(ctk.END) # Scroll to end
            self.textbox.configure(state="disabled")

    def log(self, message, level="info"):
        """Convenience method to log directly to the UI and file."""
        if level == "info":
            logging.info(message)
        elif level == "warning":
            logging.warning(message)
        elif level == "error":
            logging.error(message)
        elif level == "debug":
            logging.debug(message)
        else:
            logging.info(message) # Default to info


# --- Main Application Class ---
class SatanEncryptorSuite(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_NAME)
        self.geometry("900x700")
        self.minsize(700, 600) # Minimum size
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.settings_file = "settings.json"
        self.app_settings = self.load_settings()

        # Apply initial theme
        ctk.set_appearance_mode("Dark") # Force dark mode for hacker theme
        ctk.set_default_color_theme("dark-blue") # A good dark theme base

        # Customizing colors for a "hacker/glassmorphic" feel
        self.configure(fg_color=HACKER_BG_DARK) # Main window background

        # Initialize plugin manager
        self.plugin_manager = PluginManager()

        # Initialize UI Log Handler
        self.ui_log_handler = UILogHandler(self)
        logging.getLogger().addHandler(self.ui_log_handler)

        if self.app_settings.get("auto_clear_logs", False):
            self.clear_log_file()

        self.set_window_icon() # Call the method to set the icon
        self.create_widgets()

    def create_widgets(self):
        self.tab_view = ctk.CTkTabview(self, width=800, height=600,
                                       segmented_button_fg_color=HACKER_WIDGET_BG,
                                       segmented_button_selected_color=HACKER_ACCENT_GREEN, # Hacker green for selected tab
                                       segmented_button_selected_hover_color=HACKER_ACCENT_GREEN_HOVER,
                                       segmented_button_unselected_color=HACKER_BG_DARK, # Darker unselected tab
                                       segmented_button_unselected_hover_color=HACKER_WIDGET_BG,
                                       text_color=HACKER_TEXT_COLOR, # Tab text color
                                       corner_radius=15) # Rounded tabs

        self.tab_view.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        # Create tabs
        self.encrypt_tab = self.tab_view.add("Encrypt")
        self.decrypt_tab = self.tab_view.add("Decrypt")
        self.generate_keys_tab = self.tab_view.add("Generate Keys")
        self.settings_tab = self.tab_view.add("Settings")
        self.about_tab = self.tab_view.add("About")
        self.plugins_tab = self.tab_view.add("Plugins")

        # Set background color for tab frames
        self.encrypt_tab.configure(fg_color=HACKER_BG_DARK)
        self.decrypt_tab.configure(fg_color=HACKER_BG_DARK)
        self.generate_keys_tab.configure(fg_color=HACKER_BG_DARK)
        self.settings_tab.configure(fg_color=HACKER_BG_DARK)
        self.about_tab.configure(fg_color=HACKER_BG_DARK)
        self.plugins_tab.configure(fg_color=HACKER_BG_DARK)


        # Add content to each tab
        self.encrypt_frame = EncryptTab(self.encrypt_tab, self.plugin_manager, self.app_settings, self.ui_log_handler,
                                        fg_color=HACKER_BG_DARK, corner_radius=10)
        self.encrypt_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.encrypt_tab.grid_columnconfigure(0, weight=1)
        self.encrypt_tab.grid_rowconfigure(0, weight=1)

        self.decrypt_frame = DecryptTab(self.decrypt_tab, self.plugin_manager, self.app_settings, self.ui_log_handler,
                                        fg_color=HACKER_BG_DARK, corner_radius=10)
        self.decrypt_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.decrypt_tab.grid_columnconfigure(0, weight=1)
        self.decrypt_tab.grid_rowconfigure(0, weight=1)

        self.generate_keys_frame = GenerateKeysTab(self.generate_keys_tab, self.plugin_manager, self.ui_log_handler,
                                                   fg_color=HACKER_BG_DARK, corner_radius=10)
        self.generate_keys_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.generate_keys_tab.grid_columnconfigure(0, weight=1)
        self.generate_keys_tab.grid_rowconfigure(0, weight=1)

        self.settings_frame = SettingsTab(self.settings_tab, self.app_settings, self.ui_log_handler,
                                          fg_color=HACKER_BG_DARK, corner_radius=10)
        self.settings_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.settings_tab.grid_columnconfigure(0, weight=1)
        self.settings_tab.grid_rowconfigure(0, weight=1)

        self.about_frame = AboutTab(self.about_tab, self.ui_log_handler,
                                    fg_color=HACKER_BG_DARK, corner_radius=10)
        self.about_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.about_tab.grid_columnconfigure(0, weight=1)
        self.about_tab.grid_rowconfigure(0, weight=1)

        self.plugins_frame = PluginsTab(self.plugins_tab, self.plugin_manager, self.ui_log_handler,
                                        fg_color=HACKER_BG_DARK, corner_radius=10)
        self.plugins_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.plugins_tab.grid_columnconfigure(0, weight=1)
        self.plugins_tab.grid_rowconfigure(0, weight=1)

        # Initial log message
        self.ui_log_handler.log(f"{APP_NAME} v{APP_VERSION} started.", level="info")

    def set_window_icon(self):
        """Sets the window icon using PIL (Pillow) for PNG support."""
        icon_path = os.path.join(ASSETS_DIR, ICON_FILENAME)
        if os.path.exists(icon_path):
            try:
                # Open the image using Pillow
                image = Image.open(icon_path)
                # Create a PhotoImage Tkinter object
                # Note: For some systems, you might need to resize the image
                # For example: image = image.resize((32, 32), Image.LANCZOS)
                self.icon_photo = ImageTk.PhotoImage(image)
                # Set the window icon
                self.wm_iconphoto(True, self.icon_photo)
                self.ui_log_handler.log(f"Window icon loaded from {icon_path}")
            except Exception as e:
                self.ui_log_handler.log(f"Failed to load window icon from {icon_path}: {e}", level="error")
        else:
            self.ui_log_handler.log(f"Window icon file not found at {icon_path}", level="warning")


    def update_plugin_dropdowns(self):
        """Called to update plugin lists in relevant tabs after plugin reload."""
        self.encrypt_frame.update_plugin_options()
        self.decrypt_frame.update_plugin_options()
        self.generate_keys_frame.update_plugin_options()

    def load_settings(self):
        """Loads application settings from a JSON file."""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                return settings
            except json.JSONDecodeError:
                logging.error("Error decoding settings.json. Using default settings.")
                return {}
            except Exception as e:
                logging.error(f"Error loading settings: {e}. Using default settings.")
                return {}
        return {}

    def save_settings(self):
        """Saves current application settings to a JSON file."""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.app_settings, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save settings: {e}")

    def clear_log_file(self):
        """Clears the log file if auto-clear is enabled."""
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'w') as f:
                    f.truncate(0)
                logging.info("Log file cleared on startup.")
        except Exception as e:
            logging.error(f"Failed to clear log file: {e}")

    def on_closing(self):
        """Handles actions when the application is closing."""
        self.save_settings()
        logging.info(f"{APP_NAME} closed.")
        self.destroy()

if __name__ == "__main__":
    # Create the assets directory if it doesn't exist
    if not os.path.exists(ASSETS_DIR):
        os.makedirs(ASSETS_DIR)

    app = SatanEncryptorSuite()
    app.protocol("WM_DELETE_WINDOW", app.on_closing) # Handle window close event
    app.mainloop()
