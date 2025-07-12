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
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 # For ChaCha20 plugin
from base64 import urlsafe_b64encode, b64encode, b64decode
import hashlib
import threading
import time
from PIL import Image, ImageTk

# --- Configuration and Global Settings ---
APP_NAME = "Satan Encryptor Suite"
APP_VERSION = "1.1.0"
DEVELOPER_NAME = "Surya B"
GITHUB_URL = "https://github.com/Suryabx" # Keep this URL consistent with your proprietary README
PLUGINS_DIR = "plugins" # This refers to the *installed* plugins directory
ASSETS_DIR = "assets"
ICON_FILENAME = "icon.png"

# Determine the appropriate base directory for application data based on OS
# This ensures logs and settings are written to a user-writable location.
if sys.platform == "win32":
    # On Windows, prefer LOCALAPPDATA for non-roaming data
    APP_DATA_BASE_DIR = os.environ.get("LOCALAPPDATA")
    if not APP_DATA_BASE_DIR:
        # Fallback if LOCALAPPDATA is not set (should be rare for normal users)
        APP_DATA_BASE_DIR = os.path.join(os.path.expanduser("~"), "AppData", "Local")
elif sys.platform == "darwin":
    # On macOS, use Application Support
    APP_DATA_BASE_DIR = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
else:
    # On Linux/Unix, use XDG_DATA_HOME or ~/.local/share
    APP_DATA_BASE_DIR = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")

# Define application-specific directories within the determined base directory
APP_SPECIFIC_DIR = os.path.join(APP_DATA_BASE_DIR, APP_NAME)
LOG_DIR = os.path.join(APP_SPECIFIC_DIR, "logs")
SETTINGS_DIR = APP_SPECIFIC_DIR # Settings file directly in app-specific dir
LANGUAGES_DIR = os.path.join(APP_SPECIFIC_DIR, "languages") # Languages also in app-specific dir

# Ensure the log directory exists before setting up logging
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "satan_encryptor_suite.log")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")


# Professional Dark Theme Colors (Muted Blue/Grey)
THEME_BG_DARK = "#2B2D30" # Dark grey for main background
THEME_ACCENT_BLUE = "#5865F2" # Discord-like blue for accents
THEME_ACCENT_BLUE_HOVER = "#4752C4" # Slightly darker blue for hover
THEME_TEXT_COLOR = "#DCDCDC" # Light grey for text
THEME_WIDGET_BG = "#36393F" # Slightly lighter dark grey for widget backgrounds
THEME_WIDGET_BORDER = "#4F545C" # Muted border for widgets
THEME_DISABLED_TEXT = "#808080" # Grey for disabled fields
THEME_ERROR_RED = "#FF6347" # Tomato red for errors
THEME_WARNING_ORANGE = "#FFA500" # Orange for warnings
THEME_SUCCESS_GREEN = "#7CFC00" # Lawn green for success

# Set up logging
# The logging configuration now uses the dynamically determined LOG_FILE path.
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE,
                    filemode='a')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

# --- Localization Manager ---
class LocalizationManager:
    def __init__(self):
        self.current_language = "en" # Always start with English as default
        self.translations = {}
        self._default_english_translations = { # Hardcoded default English
            "app_name": "Satan Encryptor Suite",
            "encrypt_tab": "Encrypt",
            "decrypt_tab": "Decrypt",
            "generate_keys_tab": "Generate Keys",
            "settings_tab": "Settings",
            "about_tab": "About",
            "plugins_tab": "Plugins",
            "input_file_folder": "Input File/Folder:",
            "select_file_folder_encrypt": "Select file or folder to encrypt",
            "output_folder": "Output Folder:",
            "select_output_folder": "Select output folder",
            "encryption_algorithm": "Encryption Algorithm:",
            "no_plugins_loaded": "No Plugins Loaded",
            "key_len": "Key Len:",
            "nonce_iv_len": "Nonce/IV Len:",
            "mode": "Mode:",
            "padding": "Padding:",
            "key_type": "Key Type:",
            "password_derive_key": "Password (Derive Key)",
            "direct_key_base64_pem": "Direct Key (Base64/PEM)",
            "enter_password_derivation": "Enter password for key derivation",
            "password": "Password:",
            "direct_key": "Direct Key:",
            "show_input": "Show Input",
            "password_strength": "Password Strength: ",
            "weak": "Weak",
            "medium": "Medium",
            "strong": "Strong",
            "kdf_iterations": "KDF Iterations:",
            "output_suffix": "Output Suffix:",
            "delete_original_after_encrypt": "Delete Original After Encrypt",
            "encrypt_files": "Encrypt File(s)",
            "decrypt_files": "Decrypt File(s)",
            "input_encrypted_file_folder": "Input Encrypted File/Folder:",
            "select_encrypted_file_folder": "Select encrypted file or folder",
            "decryption_algorithm": "Decryption Algorithm:",
            "input_salt": "Input Salt:",
            "input_nonce_iv": "Input Nonce/IV:",
            "algorithm_key_generation": "Algorithm for Key Generation:",
            "key_length_bits_rsa": "Key Length (bits, for RSA):",
            "output_format": "Output Format:",
            "base64_url_safe": "Base64 (URL-safe)",
            "hex": "Hex",
            "pem_rsa_only": "PEM (RSA Only)",
            "generate_keys": "Generate Key(s)", # Changed to "Generate Key(s)" for clarity
            "generated_keys": "Generated Key(s):",
            "copy_keys_clipboard": "Copy Key(s) to Clipboard",
            "theme": "Theme:",
            "dark": "Dark",
            "light": "Light",
            "system": "System",
            "auto_clear_logs_startup": "Auto-clear logs on startup",
            "confirm_overwrite_files": "Confirm before overwriting files",
            "enable_expert_mode": "Enable Expert Mode (More Options)", # This string is no longer used but kept for consistency
            "log_level": "Log Level:",
            "file_chunk_size_kb": "File Chunk Size (KB):",
            "language_wip": "Language:", # Changed from WIP
            "export_settings": "Export Settings",
            "import_settings": "Import Settings",
            "loaded_encryption_plugins": "Loaded Encryption Plugins",
            "reload_plugins": "Reload Plugins",
            "selected_plugin_details": "Selected Plugin Details:",
            "name": "Name:",
            "key_length": "Key Length:",
            "nonce_iv_length": "Nonce/IV Length:",
            "cipher_mode": "Cipher Mode:",
            "padding": "Padding:",
            "no_plugins_found": "No plugins found. Place .py files in the 'plugins' folder.",
            "view_github": "View GitHub",
            "license_proprietary": "License: Proprietary (See terms.txt)",
            "feedback_contact_github": "For feedback or contact, please visit the GitHub page.",
            "app_started": "{app_name} v{app_version} started.",
            "window_icon_loaded": "Window icon loaded from {path}",
            "failed_load_icon": "Failed to load window icon from {path}: {error}",
            "icon_not_found": "Window icon file not found at {path}",
            "input_error": "Input Error",
            "all_fields_filled": "All fields must be filled.",
            "input_path_not_exist": "Input file or folder does not exist.",
            "output_folder_not_exist": "Output folder does not exist or is not a directory.",
            "iterations_positive_integer": "KDF Iterations must be a valid positive integer.",
            "encryption_error": "Encryption Error",
            "plugin_not_found": "Encryption plugin '{algo_name}' not found.",
            "no_files_encrypt": "No files found to encrypt.",
            "confirm_overwrite_title": "Confirm Overwrite",
            "confirm_overwrite": "'{filepath}' already exists. Overwrite?",
            "skipping_overwrite": "Skipping encryption of '{path}' due to overwrite prevention.",
            "successfully_encrypted": "Successfully encrypted: {input_path} to {output_path}",
            "deleted_original": "Deleted original file: {path}",
            "failed_delete_original": "Failed to delete original file {path}: {error}",
            "encryption_complete_title": "Encryption Complete",
            "encryption_complete": "{count} file(s) encrypted successfully!",
            "encryption_info": "Encryption Info",
            "no_files_encrypted": "No files were encrypted.",
            "overall_encryption_error_title": "Overall Encryption Error",
            "overall_encryption_error": "An error occurred during encryption process: {error}",
            "decryption_error": "Decryption Error",
            "no_files_decrypt": "No files found to decrypt.",
            "successfully_decrypted": "Successfully decrypted: {input_path} to {output_path}",
            "decryption_complete_title": "Decryption Complete",
            "decryption_complete": "{count} file(s) decrypted successfully!",
            "decryption_info": "Decryption Info",
            "no_files_decrypted": "No files were decrypted.",
            "overall_decryption_error_title": "Overall Decryption Error",
            "overall_decryption_error": "An error occurred during decryption process: {error}",
            "plugin_not_found_gen": "Plugin '{algo_name}' not found.",
            "invalid_rsa_key_length": "Invalid RSA key length. Must be 1024, 2048, 3072, or 4096.",
            "pem_rsa_only_format": "PEM format is only applicable for RSA keys.",
            "generating": "Generating...",
            "generating_keys": "Generando key(s)...",
            "generated_key_format": "Generated {algo_name} key(s) in {output_format} format.",
            "key_generation": "Key Generation",
            "key_generation_success": "{algo_name} key(s) generated successfully!",
            "key_generation_error_title": "Key Generation Error",
            "key_generation_error": "Failed to generate key: {error}",
            "copy_to_clipboard": "Copy to Clipboard",
            "key_copied_clipboard": "Key(s) copied to clipboard!",
            "no_key_copy": "No key to copy.",
            "theme_changed": "Theme changed to {theme}",
            "auto_clear_logs_set": "Auto-clear logs on startup set to {state}",
            "confirm_overwrite_set": "Confirm overwrite files set to {state}",
            "expert_mode_set": "Expert Mode set to {state}. UI will update.", # This string is no longer used but kept for consistency
            "log_level_changed": "Log level changed to {level}",
            "settings_exported": "Settings exported successfully!",
            "settings_exported_to": "Settings exported to {path}",
            "export_error": "Export Error",
            "failed_export_settings": "Failed to export settings: {error}",
            "settings_imported": "Settings imported successfully! Restart app for full effect.",
            "settings_imported_from": "{path}",
            "import_error": "Import Error",
            "invalid_json_file": "Invalid JSON file.",
            "failed_import_settings_invalid_json": "Failed to import settings: Invalid JSON file.",
            "failed_import_settings": "Failed to import settings: {error}",
            "reloading_plugins": "Reloading plugins...",
            "plugins_reloaded": "Plugins reloaded.",
            "plugins_reloaded_success": "Plugins reloaded successfully!",
            "displayed_details_for_plugin": "Displayed details for plugin: {plugin_name}",
            "app_closed": "{app_name} closed.",
            "file_progress": "Processing {current_file_num}/{total_files} files: {filename}",
            "select_language": "Select Language",
            "browse": "Browse",
            "encrypting": "Encrypting...",
            "decrypting": "Decrypting...",
            "file_or_folder_not_exist": "File or folder does not exist.",
            "invalid_input_path": "Invalid input path.",
            "overall_error": "An overall error occurred:",
            "expert_mode_warning_title": "Expert Mode Enabled",
            "expert_mode_warning_message": "Expert Mode exposes advanced cryptographic options. Incorrect use may lead to data loss or insecure operations. Proceed with caution.",
            "generated_internal": "Generated (internal)",
            "read_internal": "Read (internal)",
            "compression": "Compression:",
            "none": "None",
            "gzip": "Gzip",
            "zlib": "Zlib",
            "integrity_check": "Integrity Check:",
            "sha256": "SHA256",
            "sha512": "SHA512",
            "include_subfolders": "Include Subfolders",
            "exclude_file_types": "Exclude File Types (comma-separated):",
            "only_include_file_types": "Only Include File Types (comma-separated):",
            "key_usage": "Key Usage:",
            "encryption": "Encryption",
            "signing": "Signing",
            "key_exchange": "Key Exchange",
            "key_derivation_function": "Key Derivation Function (KDF):",
            "pbkdf2_hmac": "PBKDF2HMAC",
            "scrypt": "Scrypt",
            "salt_length_bytes": "Salt Length (bytes):",
            "auto_backup_original": "Auto-backup original files before encryption",
            "security_warnings_toggle": "Show Security Warnings (e.g., for weak passwords)",
            "splash_screen_loading": "Loading Satan Encryptor Suite...",
            "splash_screen_title": "Satan Encryptor Suite - Loading",
            "language_changed_to": "Language changed to {lang}. Some UI elements may require a restart to fully update.",
            "language_change_restart": "Language changed successfully! For all UI elements to fully update, please restart the application.",
            "language_not_found": "Language '{lang}' not found. Defaulting to English.",
            "weak_password_warning": "Warning: The entered password is weak. Consider using a stronger password for better security.",
            "created_backup": "Created backup of original file: {path}",
            "failed_create_backup": "Failed to create backup for {path}: {error}",
            "encryption_failed_for": "Encryption failed for '{path}': {error}",
            "unexpected_encryption_error": "An unexpected error occurred during encryption of '{path}': {error}",
            "decryption_failed_for": "Decryption failed for '{path}': {error}",
            "unexpected_decryption_error": "An unexpected error occurred during decryption of '{path}': {error}",
            "invalid_key_length": "Invalid key length",
            "symmetric": "Symmetric",
            "asymmetric": "Asymmetric",
            "password_based": "Password-Based",
            "version": "Version: ",
            "developed_by": "Developed by: ",
            "json_files": "JSON Files",
            "created_plugins_directory": "Created plugins directory: {path}",
            "could_not_load_spec": "Could not load spec for plugin file: {filename}",
            "loaded_encryption_plugin": "Loaded encryption plugin: {plugin_name}",
            "plugin_interface_mismatch": "Plugin '{plugin_name}' does not implement the required interface.",
            "module_no_encryptor_class": "Module '{filename}' does not contain an EncryptorPlugin class.",
            "failed_load_plugin": "Failed to load plugin '{filename}': {error}",
            "no_encryption_plugins_found": "No encryption plugins found.",
            "encryption_algorithm_selected": "Encryption algorithm selected: {choice}",
            "decryption_algorithm_selected": "Decryption algorithm selected: {choice}",
            "opened_github_link": "Opened GitHub link: {url}"
        }
        self.translations["en"] = self._default_english_translations # Always load default English

        self.load_translations_from_files() # Attempt to load from files, overriding defaults
        self._ensure_default_english_file() # New method to ensure en.json exists

    def _ensure_default_english_file(self):
        """Ensures that the default English translation file exists."""
        # Ensure the LANGUAGES_DIR exists before trying to write
        os.makedirs(LANGUAGES_DIR, exist_ok=True)
        en_filepath = os.path.join(LANGUAGES_DIR, "en.json")
        if not os.path.exists(en_filepath):
            try:
                with open(en_filepath, 'w', encoding='utf-8') as f:
                    json.dump(self._default_english_translations, f, indent=4)
                logging.info(f"Created default English translation file: {en_filepath}")
            except Exception as e:
                logging.error(f"Failed to create default English translation file '{en_filepath}': {e}")

    def load_translations_from_files(self):
        """Loads translation files from the LANGUAGES_DIR."""
        if not os.path.exists(LANGUAGES_DIR):
            os.makedirs(LANGUAGES_DIR, exist_ok=True) # Ensure directory exists
            logging.info(f"Created languages directory: {LANGUAGES_DIR}")

        for filename in os.listdir(LANGUAGES_DIR):
            if filename.endswith(".json"):
                lang_code = filename[:-5] # Remove '.json'
                filepath = os.path.join(LANGUAGES_DIR, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        # Load and merge: existing 'en' will be overridden by file's 'en'
                        # Other languages will be added
                        self.translations[lang_code] = {**self.translations.get(lang_code, {}), **json.load(f)}
                    logging.info(f"Loaded language: {lang_code} from file.")
                except Exception as e:
                    logging.error(f"Failed to load language file '{filename}': {e}")

        # If after loading files, 'en' is somehow missing (e.g., en.json was empty/corrupt),
        # ensure it defaults back to the hardcoded version.
        if "en" not in self.translations or not self.translations["en"]:
            self.translations["en"] = self._default_english_translations
            logging.warning("English translation file was missing or corrupt. Using hardcoded default English.")

    def get_string(self, key, **kwargs):
        """Retrieves a localized string, with optional formatting."""
        # Try current language, then fallback to English, then fallback to key itself
        text = self.translations.get(self.current_language, {}).get(key,
                                self.translations.get("en", {}).get(key, key))
        return text.format(**kwargs)

    def get_available_languages(self):
        return list(self.translations.keys())

    def set_language(self, lang_code):
        """Sets the current language if available."""
        if lang_code in self.translations:
            self.current_language = lang_code
            logging.info(f"Language set to: {lang_code}")
            return True
        else:
            logging.warning(f"Attempted to set unknown language: {lang_code}. Sticking to {self.current_language}.")
            return False

# Initialize Localization Manager globally
loc = LocalizationManager()

# --- Plugin Management System ---
class PluginManager:
    def __init__(self):
        self.encryption_plugins = {}
        self.load_plugins()

    def load_plugins(self):
        """Discovers and loads encryption plugins from the PLUGINS_DIR."""
        self.encryption_plugins = {}
        if not os.path.exists(PLUGINS_DIR):
            # This case should ideally not happen if installer runs correctly
            # But if it does, log a warning and proceed without plugins
            logging.warning(f"Plugins directory not found: {PLUGINS_DIR}. No plugins will be loaded.")
            return

        for filename in os.listdir(PLUGINS_DIR):
            if filename.endswith("_plugin.py"):
                plugin_id = filename[:-10] # Remove '_plugin.py' for module name
                filepath = os.path.join(PLUGINS_DIR, filename)
                try:
                    spec = importlib.util.spec_from_file_location(plugin_id, filepath)
                    if spec is None:
                        logging.warning(loc.get_string("could_not_load_spec", filename=filename))
                        continue
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[plugin_id] = module
                    spec.loader.exec_module(module)

                    # Check if the module has the required interface
                    if hasattr(module, 'EncryptorPlugin') and callable(getattr(module, 'EncryptorPlugin')):
                        plugin_instance = module.EncryptorPlugin()
                        # Ensure plugin has required attributes/methods
                        if hasattr(plugin_instance, 'name') and \
                           hasattr(plugin_instance, 'encrypt_file') and callable(getattr(plugin_instance, 'encrypt_file')) and \
                           hasattr(plugin_instance, 'decrypt_file') and callable(getattr(plugin_instance, 'decrypt_file')) and \
                           hasattr(plugin_instance, 'generate_key') and callable(getattr(plugin_instance, 'generate_key')):

                            # Assign default values for new optional attributes if not present in plugin
                            plugin_instance.key_length = getattr(plugin_instance, 'key_length', 'N/A')
                            plugin_instance.nonce_length = getattr(plugin_instance, 'nonce_length', 'N/A')
                            plugin_instance.cipher_mode = getattr(plugin_instance, 'cipher_mode', 'N/A')
                            plugin_instance.padding_scheme = getattr(plugin_instance, 'padding_scheme', 'N/A')
                            plugin_instance.compression_supported = getattr(plugin_instance, 'compression_supported', False)
                            plugin_instance.integrity_supported = getattr(plugin_instance, 'integrity_supported', False)
                            plugin_instance.kdf_supported = getattr(plugin_instance, 'kdf_supported', False)
                            plugin_instance.key_derivation_functions = getattr(plugin_instance, 'key_derivation_functions', [])
                            plugin_instance.salt_length_bytes = getattr(plugin_instance, 'salt_length_bytes', 'N/A')
                            plugin_instance.key_usage_options = getattr(plugin_instance, 'key_usage_options', ["Encryption"]) # Default for generate tab

                            self.encryption_plugins[plugin_instance.name] = plugin_instance
                            logging.info(loc.get_string("loaded_encryption_plugin", plugin_name=plugin_instance.name))
                        else:
                            logging.warning(loc.get_string("plugin_interface_mismatch", plugin_name=plugin_id))
                    else:
                        logging.warning(loc.get_string("module_no_encryptor_class", filename=filename))
                except Exception as e:
                    logging.error(loc.get_string("failed_load_plugin", filename=filename, error=e))
        if not self.encryption_plugins:
            logging.warning(loc.get_string("no_encryption_plugins_found"))

    def get_plugin_names(self):
        return list(self.encryption_plugins.keys())

    def get_plugin(self, name):
        return self.encryption_plugins.get(name)

# --- Abstract Plugin Interface (for type hinting and consistency) ---
class AbstractEncryptorPlugin:
    def __init__(self):
        self.name = "Abstract"
        self.key_length = None
        self.nonce_length = None
        self.cipher_mode = "N/A"
        self.padding_scheme = "N/A"
        self.compression_supported = False
        self.integrity_supported = False
        self.kdf_supported = False
        self.key_derivation_functions = [] # e.g., ["PBKDF2HMAC", "Scrypt"]
        self.salt_length_bytes = "N/A" # For KDFs
        self.key_usage_options = ["Encryption"] # For generate tab, e.g., ["Encryption", "Signing"]

    def encrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=None, compression=None, integrity_check=None):
        raise NotImplementedError

    def decrypt_file(self, input_filepath, output_filepath, key, password=None, progress_callback=None, iterations=None, decompression=None, integrity_check=None):
        raise NotImplementedError

    def generate_key(self, length=None, kdf=None, salt_len=None, key_usage=None):
        raise NotImplementedError

# Removed create_dummy_plugins() as it was causing permission errors by writing to Program Files.
# Your NSIS installer is responsible for placing the original plugin files.


# --- UI Frames for each Tab ---

class EncryptTab(ctk.CTkFrame):
    def __init__(self, master, plugin_manager, app_settings, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.plugin_manager = plugin_manager
        self.app_settings = app_settings
        self.log_callback = log_callback
        self.grid_columnconfigure((0, 1, 2), weight=1)
        self.grid_rowconfigure(18, weight=1) # Adjusted for more options

        self.setup_ui()
        self.localize_ui() # Call localize after setup_ui
        self.update_plugin_options()
        self.update_expert_mode_ui() # Apply expert mode initially


    def localize_ui(self):
        self.input_label.configure(text=loc.get_string("input_file_folder"))
        self.input_path_entry.configure(placeholder_text=loc.get_string("select_file_folder_encrypt"))
        self.browse_input_button.configure(text=loc.get_string("browse"))
        self.output_label.configure(text=loc.get_string("output_folder"))
        self.output_path_entry.configure(placeholder_text=loc.get_string("select_output_folder"))
        self.browse_output_button.configure(text=loc.get_string("browse"))
        self.algo_label.configure(text=loc.get_string("encryption_algorithm"))
        self.key_len_label.configure(text=loc.get_string("key_len"))
        self.nonce_iv_len_label.configure(text=loc.get_string("nonce_iv_len"))
        self.cipher_mode_label.configure(text=loc.get_string("mode")) # Corrected label name
        self.padding_scheme_label.configure(text=loc.get_string("padding"))
        self.key_type_label.configure(text=loc.get_string("key_type"))
        self.key_type_dropdown.configure(values=[loc.get_string("password_derive_key"), loc.get_string("direct_key_base64_pem")])
        self.password_entry.configure(placeholder_text=loc.get_string("enter_password_derivation"))
        self.password_label.configure(text=loc.get_string("password"))
        self.direct_key_entry.configure(placeholder_text=loc.get_string("direct_key_base64_pem"))
        self.direct_key_label.configure(text=loc.get_string("direct_key"))
        self.show_key_checkbox.configure(text=loc.get_string("show_input")) # Corrected checkbox name
        self.strength_label.configure(text=loc.get_string("password_strength") + "N/A")
        self.iterations_label.configure(text=loc.get_string("kdf_iterations"))
        # self.generated_salt_label.configure(text=loc.get_string("generated_salt")) # This label doesn't exist in setup_ui
        # self.generated_nonce_iv_label.configure(text=loc.get_string("generated_nonce_iv")) # This label doesn't exist in setup_ui
        self.output_suffix_label.configure(text=loc.get_string("output_suffix"))
        self.delete_original_checkbox.configure(text=loc.get_string("delete_original_after_encrypt"))
        self.encrypt_button.configure(text=loc.get_string("encrypt_files"))
        self.compression_label.configure(text=loc.get_string("compression"))
        self.compression_dropdown.configure(values=[loc.get_string("none"), loc.get_string("gzip"), loc.get_string("zlib")])
        self.integrity_label.configure(text=loc.get_string("integrity_check"))
        self.integrity_dropdown.configure(values=[loc.get_string("none"), loc.get_string("sha256"), loc.get_string("sha512")])
        self.include_subfolders_checkbox.configure(text=loc.get_string("include_subfolders"))
        self.exclude_file_types_label.configure(text=loc.get_string("exclude_file_types"))
        self.only_include_file_types_label.configure(text=loc.get_string("only_include_file_types"))
        self.auto_backup_checkbox.configure(text=loc.get_string("auto_backup_original"))
        if not self.algo_options: # Only update dropdown default if no plugins
            self.algo_dropdown.set(loc.get_string("no_plugins_loaded"))

    def setup_ui(self):
        # Input File/Folder
        self.input_label = ctk.CTkLabel(self, text="Input File/Folder:", text_color=THEME_TEXT_COLOR)
        self.input_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.input_path_entry = ctk.CTkEntry(self, placeholder_text="Select file or folder to encrypt",
                                             fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                             border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.input_path_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.browse_input_button = ctk.CTkButton(self, text="Browse", command=self.browse_input,
                                                 fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 text_color="white", corner_radius=8)
        self.browse_input_button.grid(row=0, column=2, padx=10, pady=5)

        # Output Folder
        self.output_label = ctk.CTkLabel(self, text="Output Folder:", text_color=THEME_TEXT_COLOR)
        self.output_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.output_path_entry = ctk.CTkEntry(self, placeholder_text="Select output folder",
                                              fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                              border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.output_path_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        self.browse_output_button = ctk.CTkButton(self, text="Browse", command=self.browse_output,
                                                  fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  text_color="white", corner_radius=8)
        self.browse_output_button.grid(row=1, column=2, padx=10, pady=5)

        # Encryption Algorithm
        self.algo_label = ctk.CTkLabel(self, text="Encryption Algorithm:", text_color=THEME_TEXT_COLOR)
        self.algo_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown = ctk.CTkComboBox(self, values=self.algo_options, command=self.on_algo_selected,
                                             fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                             button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                             border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                             dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                             dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
        else:
            self.algo_dropdown.set(loc.get_string("no_plugins_loaded"))
            self.algo_dropdown.configure(state="disabled")
        self.algo_dropdown.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        # Algorithm Details Frame (Expert Mode)
        self.algo_details_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.algo_details_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.key_len_label = ctk.CTkLabel(self.algo_details_frame, text="Key Len:", text_color=THEME_DISABLED_TEXT)
        self.key_len_label.grid(row=0, column=0, sticky="w", padx=5)
        self.key_len_value = ctk.CTkLabel(self.algo_details_frame, text="N/A", text_color=THEME_TEXT_COLOR)
        self.key_len_value.grid(row=0, column=1, sticky="w", padx=0)

        self.cipher_mode_label = ctk.CTkLabel(self.algo_details_frame, text="Mode:", text_color=THEME_DISABLED_TEXT)
        self.cipher_mode_label.grid(row=1, column=0, sticky="w", padx=5)
        self.cipher_mode_value = ctk.CTkLabel(self.algo_details_frame, text="N/A", text_color=THEME_TEXT_COLOR)
        self.cipher_mode_value.grid(row=1, column=1, sticky="w", padx=0)

        self.nonce_iv_len_label = ctk.CTkLabel(self.algo_details_frame, text="Nonce/IV Len:", text_color=THEME_DISABLED_TEXT)
        self.nonce_iv_len_label.grid(row=0, column=2, sticky="w", padx=5)
        self.nonce_iv_len_value = ctk.CTkLabel(self.algo_details_frame, text="N/A", text_color=THEME_TEXT_COLOR)
        self.nonce_iv_len_value.grid(row=0, column=3, sticky="w", padx=0)

        self.padding_scheme_label = ctk.CTkLabel(self.algo_details_frame, text="Padding:", text_color=THEME_DISABLED_TEXT)
        self.padding_scheme_label.grid(row=1, column=2, sticky="w", padx=5)
        self.padding_scheme_value = ctk.CTkLabel(self.algo_details_frame, text="N/A", text_color=THEME_TEXT_COLOR)
        self.padding_scheme_value.grid(row=1, column=3, sticky="w", padx=0)

        # Key / Password Input
        self.key_type_label = ctk.CTkLabel(self, text="Key Type:", text_color=THEME_TEXT_COLOR)
        self.key_type_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")
        self.key_type_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("password_derive_key"), loc.get_string("direct_key_base64_pem")],
                                                 command=self.on_key_type_selected,
                                                 fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                 button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                 dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.key_type_dropdown.set(loc.get_string("password_derive_key"))
        self.key_type_dropdown.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

        self.password_entry = ctk.CTkEntry(self, placeholder_text="Enter password for key derivation",
                                           fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                           border_color=THEME_WIDGET_BORDER, corner_radius=8, show="*")
        self.password_entry.grid(row=5, column=1, padx=10, pady=5, sticky="ew")
        self.password_label = ctk.CTkLabel(self, text="Password:", text_color=THEME_TEXT_COLOR)
        self.password_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)

        self.direct_key_entry = ctk.CTkEntry(self, placeholder_text="Enter direct key (Base64 or PEM)",
                                             fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                             border_color=THEME_WIDGET_BORDER, corner_radius=8, show="*")
        self.direct_key_label = ctk.CTkLabel(self, text="Direct Key:", text_color=THEME_TEXT_COLOR)

        self.show_key_checkbox = ctk.CTkCheckBox(self, text="Show Input", command=self.toggle_key_visibility,
                                                 fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                 hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)
        self.show_key_checkbox.grid(row=5, column=2, padx=10, pady=5, sticky="w")

        self.strength_label = ctk.CTkLabel(self, text="Password Strength: N/A", text_color="gray")
        self.strength_label.grid(row=6, column=1, padx=10, pady=0, sticky="w")

        # Expert Mode: Iterations
        self.iterations_label = ctk.CTkLabel(self, text="KDF Iterations:", text_color=THEME_TEXT_COLOR)
        self.iterations_entry = ctk.CTkEntry(self, placeholder_text="e.g., 100000",
                                             fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                             border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.iterations_entry.insert(0, "100000") # Default

        # Expert Mode: Generated Salt/Nonce/IV Display
        self.generated_salt_label = ctk.CTkLabel(self, text="Generated Salt:", text_color=THEME_DISABLED_TEXT)
        self.generated_salt_value = ctk.CTkEntry(self, state="readonly", fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR, border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.generated_nonce_iv_label = ctk.CTkLabel(self, text="Generated Nonce/IV:", text_color=THEME_DISABLED_TEXT)
        self.generated_nonce_iv_value = ctk.CTkEntry(self, state="readonly", fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR, border_color=THEME_WIDGET_BORDER, corner_radius=8)

        # Advanced File Selection Options (Expert Mode)
        self.file_selection_options_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.file_selection_options_frame.grid_columnconfigure((0, 1), weight=1)

        self.include_subfolders_checkbox = ctk.CTkCheckBox(self.file_selection_options_frame, text="Include Subfolders",
                                                            fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                            hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)
        self.exclude_file_types_label = ctk.CTkLabel(self.file_selection_options_frame, text="Exclude File Types (comma-separated):", text_color=THEME_TEXT_COLOR)
        self.exclude_file_types_entry = ctk.CTkEntry(self.file_selection_options_frame, placeholder_text="e.g., txt, log",
                                                     fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                     border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.only_include_file_types_label = ctk.CTkLabel(self.file_selection_options_frame, text="Only Include File Types (comma-separated):", text_color=THEME_TEXT_COLOR)
        self.only_include_file_types_entry = ctk.CTkEntry(self.file_selection_options_frame, placeholder_text="e.g., docx, pdf",
                                                          fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                          border_color=THEME_WIDGET_BORDER, corner_radius=8)

        # Output Options (Expert Mode)
        self.output_options_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.output_options_frame.grid_columnconfigure((0, 1), weight=1)

        self.output_suffix_label = ctk.CTkLabel(self.output_options_frame, text="Output Suffix:", text_color=THEME_TEXT_COLOR)
        self.output_suffix_entry = ctk.CTkEntry(self.output_options_frame, placeholder_text=".enc",
                                                fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.output_suffix_entry.insert(0, ".enc")

        self.delete_original_checkbox = ctk.CTkCheckBox(self.output_options_frame, text="Delete Original After Encrypt",
                                                        fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                        hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)
        self.auto_backup_checkbox = ctk.CTkCheckBox(self.output_options_frame, text="Auto-backup original files before encryption",
                                                    fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                    hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)

        # Compression and Integrity Check (Expert Mode)
        self.compression_label = ctk.CTkLabel(self, text="Compression:", text_color=THEME_TEXT_COLOR)
        self.compression_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("none"), loc.get_string("gzip"), loc.get_string("zlib")],
                                                    fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                    button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                    border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                    dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                    dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.compression_dropdown.set(loc.get_string("none"))

        self.integrity_label = ctk.CTkLabel(self, text="Integrity Check:", text_color=THEME_TEXT_COLOR)
        self.integrity_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("none"), loc.get_string("sha256"), loc.get_string("sha512")],
                                                  fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                  button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                  dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.integrity_dropdown.set(loc.get_string("none"))


        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal",
                                               fg_color=THEME_WIDGET_BG, progress_color=THEME_ACCENT_BLUE,
                                               corner_radius=8)
        self.progress_bar.grid(row=16, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.progress_bar.set(0)

        # Encrypt Button
        self.encrypt_button = ctk.CTkButton(self, text="Encrypt File(s)", command=self.start_encryption_thread,
                                            fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                            text_color="white", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.encrypt_button.grid(row=17, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                          border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=18, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

        self.on_key_type_selected(self.key_type_dropdown.get()) # Initialize key input visibility

    def update_expert_mode_ui(self):
        is_expert = self.app_settings.get("expert_mode", False)
        current_row = 3 # Starting row for expert elements

        if is_expert:
            self.algo_details_frame.grid(row=current_row, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.iterations_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.iterations_entry.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.generated_salt_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.generated_salt_value.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.generated_nonce_iv_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.generated_nonce_iv_value.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.file_selection_options_frame.grid(row=current_row, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
            self.include_subfolders_checkbox.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="w")
            self.exclude_file_types_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
            self.exclude_file_types_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
            self.only_include_file_types_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
            self.only_include_file_types_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.output_options_frame.grid(row=current_row, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
            self.output_suffix_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
            self.output_suffix_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
            self.delete_original_checkbox.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="w")
            self.auto_backup_checkbox.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")
            current_row += 1

            self.compression_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.compression_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.integrity_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.integrity_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

        else:
            self.algo_details_frame.grid_forget()
            self.iterations_label.grid_forget()
            self.iterations_entry.grid_forget()
            self.generated_salt_label.grid_forget()
            self.generated_salt_value.grid_forget()
            self.generated_nonce_iv_label.grid_forget()
            self.generated_nonce_iv_value.grid_forget()
            self.file_selection_options_frame.grid_forget()
            self.output_options_frame.grid_forget()
            self.compression_label.grid_forget()
            self.compression_dropdown.grid_forget()
            self.integrity_label.grid_forget()
            self.integrity_dropdown.grid_forget()

            # Clear values when hiding
            self.generated_salt_value.configure(state="normal")
            self.generated_salt_value.delete(0, ctk.END)
            self.generated_salt_value.configure(state="readonly")
            self.generated_nonce_iv_value.configure(state="normal")
            self.generated_nonce_iv_value.delete(0, ctk.END)
            self.generated_nonce_iv_value.configure(state="readonly")

        # Adjust subsequent widget rows
        self.progress_bar.grid(row=current_row + 4, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.encrypt_button.grid(row=current_row + 5, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.log_textbox.grid(row=current_row + 6, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

        # Re-grid key input based on expert mode and key type
        self.on_key_type_selected(self.key_type_dropdown.get())
        self.on_algo_selected(self.algo_dropdown.get()) # Update algo details display

    def on_key_type_selected(self, choice):
        is_expert = self.app_settings.get("expert_mode", False)
        if choice == loc.get_string("password_derive_key"):
            self.password_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")
            self.password_entry.grid(row=5, column=1, padx=10, pady=5, sticky="ew")
            self.strength_label.grid(row=6, column=1, padx=10, pady=0, sticky="w")
            self.direct_key_label.grid_forget()
            self.direct_key_entry.grid_forget()
            self.password_entry.configure(show="*" if self.show_key_checkbox.get() == 0 else "")
            self.update_password_strength()
        else: # Direct Key
            self.password_label.grid_forget()
            self.password_entry.grid_forget()
            self.strength_label.grid_forget()
            self.direct_key_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")
            self.direct_key_entry.grid(row=5, column=1, padx=10, pady=5, sticky="ew")
            self.direct_key_entry.configure(show="*" if self.show_key_checkbox.get() == 0 else "")

    def update_plugin_options(self):
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown.configure(values=self.algo_options)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
            self.algo_dropdown.configure(state="normal")
        else:
            self.algo_dropdown.set(loc.get_string("no_plugins_loaded"))
            self.algo_dropdown.configure(state="disabled")
        self.on_algo_selected(self.algo_dropdown.get()) # Update details for selected algo

    def browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_path_entry.delete(0, ctk.END)
            self.input_path_entry.insert(0, file_path)
        else:
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
        current_show = "*" if self.show_key_checkbox.get() == 0 else ""
        self.password_entry.configure(show=current_show)
        self.direct_key_entry.configure(show=current_show)

    def update_password_strength(self, event=None):
        password = self.password_entry.get()
        strength = self.calculate_password_strength(password)
        if strength < 30:
            self.strength_label.configure(text=loc.get_string("password_strength") + loc.get_string("weak"), text_color=THEME_ERROR_RED)
        elif strength < 60:
            self.strength_label.configure(text=loc.get_string("password_strength") + loc.get_string("medium"), text_color=THEME_WARNING_ORANGE)
        else:
            self.strength_label.configure(text=loc.get_string("password_strength") + loc.get_string("strong"), text_color=THEME_SUCCESS_GREEN)

        if self.app_settings.get("show_security_warnings", True):
            if strength < 60 and password:
                self.log_callback.log(loc.get_string("weak_password_warning"), level="warning")

    def calculate_password_strength(self, password):
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
        self.log_callback.log(loc.get_string("encryption_algorithm_selected", choice=choice))
        plugin = self.plugin_manager.get_plugin(choice)
        if plugin:
            self.key_len_value.configure(text=str(getattr(plugin, 'key_length', 'N/A')))
            self.nonce_iv_len_value.configure(text=str(getattr(plugin, 'nonce_length', 'N/A')))
            self.cipher_mode_value.configure(text=getattr(plugin, 'cipher_mode', 'N/A'))
            self.padding_scheme_value.configure(text=getattr(plugin, 'padding_scheme', 'N/A'))

            # Update compression/integrity dropdowns based on plugin support
            comp_values = [loc.get_string("none")]
            if getattr(plugin, 'compression_supported', False):
                comp_values.extend([loc.get_string("gzip"), loc.get_string("zlib")])
            self.compression_dropdown.configure(values=comp_values)
            self.compression_dropdown.set(loc.get_string("none")) # Reset

            integrity_values = [loc.get_string("none")]
            if getattr(plugin, 'integrity_supported', False):
                integrity_values.extend([loc.get_string("sha256"), loc.get_string("sha512")])
            self.integrity_dropdown.configure(values=integrity_values)
            self.integrity_dropdown.set(loc.get_string("none")) # Reset


        else:
            self.key_len_value.configure(text="N/A")
            self.nonce_iv_len_value.configure(text="N/A")
            self.cipher_mode_value.configure(text="N/A")
            self.padding_scheme_value.configure(text="N/A")
            self.compression_dropdown.configure(values=[loc.get_string("none")])
            self.compression_dropdown.set(loc.get_string("none"))
            self.integrity_dropdown.configure(values=[loc.get_string("none")])
            self.integrity_dropdown.set(loc.get_string("none"))


        if choice == "RSA":
            self.key_type_dropdown.set(loc.get_string("direct_key_base64_pem"))
            self.key_type_dropdown.configure(state="disabled") # RSA needs direct key
        else:
            self.key_type_dropdown.configure(state="normal")
            if self.key_type_dropdown.get() not in [loc.get_string("password_derive_key"), loc.get_string("direct_key_base64_pem")]:
                self.key_type_dropdown.set(loc.get_string("password_derive_key")) # Reset if RSA was selected

        self.on_key_type_selected(self.key_type_dropdown.get()) # Update visibility based on type

    def start_encryption_thread(self):
        input_path = self.input_path_entry.get()
        output_folder = self.output_path_entry.get()
        algo_name = self.algo_dropdown.get()
        key_type = self.key_type_dropdown.get()
        iterations_str = self.iterations_entry.get() if self.app_settings.get("expert_mode", False) else "100000"
        output_suffix = self.output_suffix_entry.get() if self.app_settings.get("expert_mode", False) else ".enc"
        delete_original = self.delete_original_checkbox.get() if self.app_settings.get("expert_mode", False) else False
        auto_backup = self.auto_backup_checkbox.get() if self.app_settings.get("expert_mode", False) else False
        include_subfolders = self.include_subfolders_checkbox.get() if self.app_settings.get("expert_mode", False) else False
        exclude_types_str = self.exclude_file_types_entry.get() if self.app_settings.get("expert_mode", False) else ""
        only_include_types_str = self.only_include_file_types_entry.get() if self.app_settings.get("expert_mode", False) else ""
        compression_algo = self.compression_dropdown.get() if self.app_settings.get("expert_mode", False) else loc.get_string("none")
        integrity_algo = self.integrity_dropdown.get() if self.app_settings.get("expert_mode", False) else loc.get_string("none")


        key_or_password = ""
        if key_type == loc.get_string("password_derive_key"):
            key_or_password = self.password_entry.get()
        else:
            key_or_password = self.direct_key_entry.get()

        if not input_path or not output_folder or not algo_name or not key_or_password:
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("all_fields_filled"))
            return

        if not os.path.exists(input_path):
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("input_path_not_exist"))
            return

        if not os.path.isdir(output_folder):
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("output_folder_not_exist"))
            return

        try:
            iterations = int(iterations_str)
            if iterations <= 0:
                raise ValueError(loc.get_string("iterations_positive_integer"))
        except ValueError:
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("iterations_positive_integer"))
            return

        self.encrypt_button.configure(state="disabled", text=loc.get_string("encrypting"))
        self.progress_bar.set(0)
        self.generated_salt_value.configure(state="normal")
        self.generated_salt_value.delete(0, ctk.END)
        self.generated_salt_value.configure(state="readonly")
        self.generated_nonce_iv_value.configure(state="normal")
        self.generated_nonce_iv_value.delete(0, ctk.END)
        self.generated_nonce_iv_value.configure(state="readonly")


        # Determine if it's a file or folder and apply filters
        target_paths = []
        if os.path.isfile(input_path):
            target_paths = [input_path]
        elif os.path.isdir(input_path):
            if include_subfolders:
                for root, _, files in os.walk(input_path):
                    for file in files:
                        target_paths.append(os.path.join(root, file))
            else:
                target_paths = [os.path.join(input_path, f) for f in os.listdir(input_path) if os.path.isfile(os.path.join(input_path, f))]
        else:
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("invalid_input_path"))
            self.encrypt_button.configure(state="normal", text=loc.get_string("encrypt_files"))
            return

        # Apply file type filters
        exclude_types = [ext.strip().lower() for ext in exclude_types_str.split(',') if ext.strip()]
        only_include_types = [ext.strip().lower() for ext in only_include_types_str.split(',') if ext.strip()]

        filtered_paths = []
        for path in target_paths:
            file_extension = os.path.splitext(path)[1].lower().lstrip('.')
            if exclude_types and file_extension in exclude_types:
                continue
            if only_include_types and file_extension not in only_include_types:
                continue
            filtered_paths.append(path)
        target_paths = filtered_paths

        threading.Thread(target=self._perform_encryption, args=(target_paths, output_folder, algo_name, key_type, key_or_password, iterations, output_suffix, delete_original, auto_backup, compression_algo, integrity_algo)).start()

    def _perform_encryption(self, input_paths, output_folder, algo_name, key_type, key_or_password, iterations, output_suffix, delete_original, auto_backup, compression_algo, integrity_algo):
        plugin = self.plugin_manager.get_plugin(algo_name)
        if not plugin:
            messagebox.showerror(loc.get_string("encryption_error"), loc.get_string("plugin_not_found", algo_name=algo_name))
            self.after(0, lambda: self.encrypt_button.configure(state="normal", text=loc.get_string("encrypt_files")))
            return

        total_files = len(input_paths)
        if total_files == 0:
            messagebox.showinfo(loc.get_string("encryption_info"), loc.get_string("no_files_encrypt"))
            self.after(0, lambda: self.encrypt_button.configure(state="normal", text=loc.get_string("encrypt_files")))
            return

        overall_progress_per_file = 1.0 / total_files
        successful_operations = 0

        try:
            for i, input_path in enumerate(input_paths):
                try:
                    relative_path = os.path.relpath(input_path, os.path.dirname(input_paths[0]) if len(input_paths) > 1 else os.path.dirname(input_path))
                    output_filepath = os.path.join(output_folder, relative_path + output_suffix)
                    os.makedirs(os.path.dirname(output_filepath), exist_ok=True)

                    if os.path.exists(output_filepath) and not self.app_settings.get("overwrite_files", False):
                        response = messagebox.askyesno(loc.get_string("confirm_overwrite_title"),
                                                       loc.get_string("confirm_overwrite", filepath=output_filepath))
                        if not response:
                            self.log_callback.log(loc.get_string("skipping_overwrite", path=input_path), level="info")
                            continue

                    if auto_backup:
                        backup_path = output_filepath + ".bak"
                        try:
                            import shutil
                            shutil.copy2(input_path, backup_path)
                            self.log_callback.log(loc.get_string("created_backup", path=backup_path))
                        except Exception as backup_e:
                            self.log_callback.log(loc.get_string("failed_create_backup", path=input_path, error=backup_e), level="warning")


                    def file_progress_callback(current, total):
                        file_progress = current / total if total > 0 else 0
                        overall_progress = (i * overall_progress_per_file) + (file_progress * overall_progress_per_file)
                        self.after(0, lambda: self.progress_bar.set(overall_progress))
                        # Only log debug messages if log level is set to debug or lower
                        if logging.getLogger().isEnabledFor(logging.DEBUG):
                            self.after(0, lambda: self.log_callback.log(loc.get_string("file_progress", current_file_num=i+1, total_files=total_files, filename=os.path.basename(input_path)), level="debug"))


                    key_arg = None
                    password_arg = None
                    if key_type == loc.get_string("password_derive_key"):
                        password_arg = key_or_password
                    else: # Direct Key
                        # For Fernet, key_or_password is expected to be a URL-safe base64 string
                        # For AES, it's raw bytes (or a string to be encoded to bytes)
                        # For RSA, it's a PEM string
                        if algo_name == "Fernet":
                            try:
                                # Fernet expects a URL-safe base64 encoded key
                                key_arg = key_or_password.encode('utf-8') # Fernet.generate_key() returns bytes, which is then base64 encoded by Fernet.
                                # The Fernet constructor expects the base64-encoded bytes.
                            except Exception as e:
                                raise ValueError(f"Invalid Fernet key format: {e}. Ensure it's a valid URL-safe base64 encoded key.")
                        elif algo_name == "AES-256-CBC":
                            # AES-256-CBC expects a 32-byte key if direct, or password for derivation
                            # If direct key is provided, assume it's a hex string or raw bytes
                            if len(key_or_password) == 64 and all(c in '0123456789abcdefABCDEF' for c in key_or_password):
                                key_arg = bytes.fromhex(key_or_password) # Assume hex string
                            elif len(key_or_password) == 32:
                                key_arg = key_or_password.encode('latin-1') # Assume raw bytes
                            else:
                                raise ValueError("AES-256-CBC direct key must be 32 bytes (64 hex characters) or a raw 32-byte string.")
                        elif algo_name == "RSA":
                            key_arg = key_or_password # RSA plugin expects PEM string directly
                        elif algo_name == "ChaCha20-Poly1305":
                            # ChaCha20-Poly1305 expects a 32-byte key
                            if len(key_or_password) == 64 and all(c in '0123456789abcdefABCDEF' for c in key_or_password):
                                key_arg = bytes.fromhex(key_or_password) # Assume hex string
                            elif len(key_or_password) == 32:
                                key_arg = key_or_password.encode('latin-1') # Assume raw bytes
                            else:
                                raise ValueError("ChaCha20-Poly1305 direct key must be 32 bytes (64 hex characters) or a raw 32-byte string.")
                        else:
                            key_arg = key_or_password.encode('utf-8') # Default for other plugins


                    # Pass compression and integrity options to plugin
                    plugin.encrypt_file(input_path, output_filepath, key=key_arg, password=password_arg, progress_callback=file_progress_callback, iterations=iterations, compression=compression_algo, integrity_check=integrity_algo)

                    self.log_callback.log(loc.get_string("successfully_encrypted", input_path=input_path, output_path=output_filepath))
                    successful_operations += 1

                    # Display generated salt/nonce if expert mode is on and values are available (conceptual)
                    if self.app_settings.get("expert_mode", False):
                        self.after(0, lambda: self.generated_salt_value.configure(state="normal"))
                        self.after(0, lambda: self.generated_salt_value.delete(0, ctk.END))
                        # In a real plugin, you'd return these values from encrypt_file
                        self.after(0, lambda: self.generated_salt_value.insert(0, loc.get_string("generated_internal")))
                        self.after(0, lambda: self.generated_salt_value.configure(state="readonly"))

                        self.after(0, lambda: self.generated_nonce_iv_value.configure(state="normal"))
                        self.after(0, lambda: self.generated_nonce_iv_value.delete(0, ctk.END))
                        self.after(0, lambda: self.generated_nonce_iv_value.insert(0, loc.get_string("generated_internal")))
                        self.after(0, lambda: self.generated_nonce_iv_value.configure(state="readonly"))


                    if delete_original:
                        try:
                            os.remove(input_path)
                            self.log_callback.log(loc.get_string("deleted_original", path=input_path))
                        except Exception as delete_e:
                            self.log_callback.log(loc.get_string("failed_delete_original", path=input_path, error=delete_e), level="warning")

                except ValueError as ve:
                    self.log_callback.log(loc.get_string("encryption_failed_for", path=input_path, error=ve), level="error")
                except Exception as e:
                    self.log_callback.log(loc.get_string("unexpected_encryption_error", path=input_path, error=e), level="error")
            # End of for loop

            self.after(0, lambda: self.progress_bar.set(1.0))
            if successful_operations > 0:
                messagebox.showinfo(loc.get_string("encryption_complete_title"), loc.get_string("encryption_complete", count=successful_operations))
            else:
                messagebox.showinfo(loc.get_string("encryption_info"), loc.get_string("no_files_encrypted"))
        except Exception as e:
            messagebox.showerror(loc.get_string("overall_encryption_error_title"), loc.get_string("overall_encryption_error", error=e))
            self.log_callback.log(loc.get_string("overall_encryption_error", error=e), level="error")
        finally:
            self.after(0, lambda: self.encrypt_button.configure(state="normal", text=loc.get_string("encrypt_files")))


class DecryptTab(ctk.CTkFrame):
    def __init__(self, master, plugin_manager, app_settings, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.plugin_manager = plugin_manager
        self.app_settings = app_settings
        self.log_callback = log_callback
        self.grid_columnconfigure((0, 1, 2), weight=1)
        self.grid_rowconfigure(15, weight=1) # Adjusted for more options

        self.setup_ui()
        self.localize_ui() # Call localize after setup_ui
        self.update_plugin_options()
        self.update_expert_mode_ui()


    def localize_ui(self):
        self.input_label.configure(text=loc.get_string("input_encrypted_file_folder"))
        self.input_path_entry.configure(placeholder_text=loc.get_string("select_encrypted_file_folder"))
        self.browse_input_button.configure(text=loc.get_string("browse"))
        self.output_label.configure(text=loc.get_string("output_folder"))
        self.output_path_entry.configure(placeholder_text=loc.get_string("select_output_folder"))
        self.browse_output_button.configure(text=loc.get_string("browse"))
        self.algo_label.configure(text=loc.get_string("decryption_algorithm"))
        self.key_len_label.configure(text=loc.get_string("key_len"))
        self.nonce_iv_len_label.configure(text=loc.get_string("nonce_iv_len"))
        self.cipher_mode_label.configure(text=loc.get_string("mode"))
        self.padding_scheme_label.configure(text=loc.get_string("padding"))
        self.key_type_label.configure(text=loc.get_string("key_type"))
        self.key_type_dropdown.configure(values=[loc.get_string("password_derive_key"), loc.get_string("direct_key_base64_pem")])
        self.password_entry.configure(placeholder_text=loc.get_string("enter_password_derivation"))
        self.password_label.configure(text=loc.get_string("password"))
        self.direct_key_entry.configure(placeholder_text=loc.get_string("direct_key_base64_pem"))
        self.direct_key_label.configure(text=loc.get_string("direct_key"))
        self.show_key_checkbox.configure(text=loc.get_string("show_input"))
        self.iterations_label.configure(text=loc.get_string("kdf_iterations"))
        self.input_salt_label.configure(text=loc.get_string("input_salt"))
        self.input_nonce_iv_label.configure(text=loc.get_string("input_nonce_iv"))
        self.decrypt_button.configure(text=loc.get_string("decrypt_files"))
        self.decompression_label.configure(text=loc.get_string("compression")) # Renamed from decompression
        self.decompression_dropdown.configure(values=[loc.get_string("none"), loc.get_string("gzip"), loc.get_string("zlib")])
        self.integrity_label.configure(text=loc.get_string("integrity_check"))
        self.integrity_dropdown.configure(values=[loc.get_string("none"), loc.get_string("sha256"), loc.get_string("sha512")])
        if not self.algo_options: # Only update dropdown default if no plugins
            self.algo_dropdown.set(loc.get_string("no_plugins_loaded"))


    def setup_ui(self):
        # Input Encrypted File/Folder
        self.input_label = ctk.CTkLabel(self, text="Input Encrypted File/Folder:", text_color=THEME_TEXT_COLOR)
        self.input_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.input_path_entry = ctk.CTkEntry(self, placeholder_text="Select encrypted file or folder",
                                             fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                             border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.input_path_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.browse_input_button = ctk.CTkButton(self, text="Browse", command=self.browse_input,
                                                 fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 text_color="white", corner_radius=8)
        self.browse_input_button.grid(row=0, column=2, padx=10, pady=5)

        # Output Folder
        self.output_label = ctk.CTkLabel(self, text="Output Folder:", text_color=THEME_TEXT_COLOR)
        self.output_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.output_path_entry = ctk.CTkEntry(self, placeholder_text="Select output folder for decrypted files",
                                              fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                              border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.output_path_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        self.browse_output_button = ctk.CTkButton(self, text="Browse", command=self.browse_output,
                                                  fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  text_color="white", corner_radius=8)
        self.browse_output_button.grid(row=1, column=2, padx=10, pady=5)

        # Decryption Algorithm
        self.algo_label = ctk.CTkLabel(self, text="Decryption Algorithm:", text_color=THEME_TEXT_COLOR)
        self.algo_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown = ctk.CTkComboBox(self, values=self.algo_options, command=self.on_algo_selected,
                                             fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                             button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                             border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                             dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                             dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
        else:
            self.algo_dropdown.set(loc.get_string("no_plugins_loaded"))
            self.algo_dropdown.configure(state="disabled")
        self.algo_dropdown.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        # Algorithm Details Frame (Expert Mode)
        self.algo_details_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.algo_details_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.key_len_label = ctk.CTkLabel(self.algo_details_frame, text="Key Len:", text_color=THEME_DISABLED_TEXT)
        self.key_len_label.grid(row=0, column=0, sticky="w", padx=5)
        self.key_len_value = ctk.CTkLabel(self.algo_details_frame, text="N/A", text_color=THEME_TEXT_COLOR)
        self.key_len_value.grid(row=0, column=1, sticky="w", padx=0)

        self.nonce_iv_len_label = ctk.CTkLabel(self.algo_details_frame, text="Nonce/IV Len:", text_color=THEME_DISABLED_TEXT)
        self.nonce_iv_len_label.grid(row=0, column=2, sticky="w", padx=5)
        self.nonce_iv_len_value = ctk.CTkLabel(self.algo_details_frame, text="N/A", text_color=THEME_TEXT_COLOR)
        self.nonce_iv_len_value.grid(row=0, column=3, sticky="w", padx=0)

        self.cipher_mode_label = ctk.CTkLabel(self.algo_details_frame, text="Mode:", text_color=THEME_DISABLED_TEXT)
        self.cipher_mode_label.grid(row=1, column=0, sticky="w", padx=5)
        self.cipher_mode_value = ctk.CTkLabel(self.algo_details_frame, text="N/A", text_color=THEME_TEXT_COLOR)
        self.cipher_mode_value.grid(row=1, column=1, sticky="w", padx=0)

        self.padding_scheme_label = ctk.CTkLabel(self.algo_details_frame, text="Padding:", text_color=THEME_DISABLED_TEXT)
        self.padding_scheme_label.grid(row=1, column=2, sticky="w", padx=5)
        self.padding_scheme_value = ctk.CTkLabel(self.algo_details_frame, text="N/A", text_color=THEME_TEXT_COLOR)
        self.padding_scheme_value.grid(row=1, column=3, sticky="w", padx=0)

        # Key / Password Input
        self.key_type_label = ctk.CTkLabel(self, text="Key Type:", text_color=THEME_TEXT_COLOR)
        self.key_type_label.grid(row=4, column=0, padx=10, pady=5, sticky="w")
        self.key_type_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("password_derive_key"), loc.get_string("direct_key_base64_pem")],
                                                 command=self.on_key_type_selected,
                                                 fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                 button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                 dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.key_type_dropdown.set(loc.get_string("password_derive_key"))
        self.key_type_dropdown.grid(row=4, column=1, padx=10, pady=5, sticky="ew")

        self.password_entry = ctk.CTkEntry(self, placeholder_text="Enter password for key derivation",
                                           fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                           border_color=THEME_WIDGET_BORDER, corner_radius=8, show="*")
        self.password_entry.grid(row=5, column=1, padx=10, pady=5, sticky="ew")
        self.password_label = ctk.CTkLabel(self, text="Password:", text_color=THEME_TEXT_COLOR)
        self.password_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")

        self.direct_key_entry = ctk.CTkEntry(self, placeholder_text="Enter direct key (Base64 or PEM)",
                                             fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                             border_color=THEME_WIDGET_BORDER, corner_radius=8, show="*")
        self.direct_key_label = ctk.CTkLabel(self, text="Direct Key:", text_color=THEME_TEXT_COLOR)

        self.show_key_checkbox = ctk.CTkCheckBox(self, text="Show Input", command=self.toggle_key_visibility,
                                                 fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                 hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)
        self.show_key_checkbox.grid(row=5, column=2, padx=10, pady=5, sticky="w")

        # Expert Mode: Iterations
        self.iterations_label = ctk.CTkLabel(self, text="KDF Iterations:", text_color=THEME_TEXT_COLOR)
        self.iterations_entry = ctk.CTkEntry(self, placeholder_text="e.g., 100000",
                                             fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                             border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.iterations_entry.insert(0, "100000") # Default

        # Expert Mode: Salt/Nonce/IV Display (for decryption, these would be read from file)
        self.input_salt_label = ctk.CTkLabel(self, text="Input Salt:", text_color=THEME_DISABLED_TEXT)
        self.input_salt_value = ctk.CTkEntry(self, state="readonly", fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR, border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.input_nonce_iv_label = ctk.CTkLabel(self, text="Input Nonce/IV:", text_color=THEME_DISABLED_TEXT)
        self.input_nonce_iv_value = ctk.CTkEntry(self, state="readonly", fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR, border_color=THEME_WIDGET_BORDER, corner_radius=8)

        # Decompression and Integrity Check (Expert Mode)
        self.decompression_label = ctk.CTkLabel(self, text="Decompression:", text_color=THEME_TEXT_COLOR)
        self.decompression_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("none"), loc.get_string("gzip"), loc.get_string("zlib")],
                                                      fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                      button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                      border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                      dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                      dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.decompression_dropdown.set(loc.get_string("none"))

        self.integrity_label = ctk.CTkLabel(self, text="Integrity Check:", text_color=THEME_TEXT_COLOR)
        self.integrity_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("none"), loc.get_string("sha256"), loc.get_string("sha512")],
                                                  fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                  button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                  dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.integrity_dropdown.set(loc.get_string("none"))

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal",
                                               fg_color=THEME_WIDGET_BG, progress_color=THEME_ACCENT_BLUE,
                                               corner_radius=8)
        self.progress_bar.grid(row=13, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.progress_bar.set(0)

        # Decrypt Button
        self.decrypt_button = ctk.CTkButton(self, text="Decrypt File(s)", command=self.start_decryption_thread,
                                            fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                            text_color="white", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.decrypt_button.grid(row=14, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                          border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=15, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

        self.on_key_type_selected(self.key_type_dropdown.get()) # Initialize key input visibility

    def update_expert_mode_ui(self):
        is_expert = self.app_settings.get("expert_mode", False)
        current_row = 3 # Starting row for expert elements

        if is_expert:
            self.algo_details_frame.grid(row=current_row, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.iterations_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.iterations_entry.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.input_salt_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.input_salt_value.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.input_nonce_iv_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.input_nonce_iv_value.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.decompression_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.decompression_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.integrity_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.integrity_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

        else:
            self.algo_details_frame.grid_forget()
            self.iterations_label.grid_forget()
            self.iterations_entry.grid_forget()
            self.input_salt_label.grid_forget()
            self.input_salt_value.grid_forget()
            self.input_nonce_iv_label.grid_forget()
            self.input_nonce_iv_value.grid_forget()
            self.decompression_label.grid_forget()
            self.decompression_dropdown.grid_forget()
            self.integrity_label.grid_forget()
            self.integrity_dropdown.grid_forget()

            # Clear values when hiding
            self.input_salt_value.configure(state="normal")
            self.input_salt_value.delete(0, ctk.END)
            self.input_salt_value.configure(state="readonly")
            self.input_nonce_iv_value.configure(state="normal")
            self.input_nonce_iv_value.delete(0, ctk.END)
            self.input_nonce_iv_value.configure(state="readonly")

        # Adjust subsequent widget rows
        self.progress_bar.grid(row=current_row + 4, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.decrypt_button.grid(row=current_row + 5, column=0, columnspan=3, padx=10, pady=10, sticky="ew")
        self.log_textbox.grid(row=current_row + 6, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

        self.on_key_type_selected(self.key_type_dropdown.get())
        self.on_algo_selected(self.algo_dropdown.get())

    def on_key_type_selected(self, choice):
        if choice == loc.get_string("password_derive_key"):
            self.password_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")
            self.password_entry.grid(row=5, column=1, padx=10, pady=5, sticky="ew")
            self.direct_key_label.grid_forget()
            self.direct_key_entry.grid_forget()
            self.password_entry.configure(show="*" if self.show_key_checkbox.get() == 0 else "")
        else: # Direct Key
            self.password_label.grid_forget()
            self.password_entry.grid_forget()
            self.direct_key_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")
            self.direct_key_entry.grid(row=5, column=1, padx=10, pady=5, sticky="ew")
            self.direct_key_entry.configure(show="*" if self.show_key_checkbox.get() == 0 else "")

    def update_plugin_options(self):
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown.configure(values=self.algo_options)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
            self.algo_dropdown.configure(state="normal")
        else:
            self.algo_dropdown.set(loc.get_string("no_plugins_loaded"))
            self.algo_dropdown.configure(state="disabled")
        self.on_algo_selected(self.algo_dropdown.get())

    def browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_path_entry.delete(0, ctk.END)
            self.input_path_entry.insert(0, file_path)
        else:
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
        current_show = "*" if self.show_key_checkbox.get() == 0 else ""
        self.password_entry.configure(show=current_show)
        self.direct_key_entry.configure(show=current_show)

    def on_algo_selected(self, choice):
        self.log_callback.log(loc.get_string("decryption_algorithm_selected", choice=choice))
        plugin = self.plugin_manager.get_plugin(choice)
        if plugin:
            self.key_len_value.configure(text=str(getattr(plugin, 'key_length', 'N/A')))
            self.nonce_iv_len_value.configure(text=str(getattr(plugin, 'nonce_length', 'N/A')))
            self.cipher_mode_value.configure(text=getattr(plugin, 'cipher_mode', 'N/A'))
            self.padding_scheme_value.configure(text=getattr(plugin, 'padding_scheme', 'N/A'))

            # Update decompression/integrity dropdowns based on plugin support
            decomp_values = [loc.get_string("none")]
            if getattr(plugin, 'compression_supported', False): # Use compression_supported for both
                decomp_values.extend([loc.get_string("gzip"), loc.get_string("zlib")])
            self.decompression_dropdown.configure(values=decomp_values)
            self.decompression_dropdown.set(loc.get_string("none")) # Reset

            integrity_values = [loc.get_string("none")]
            if getattr(plugin, 'integrity_supported', False):
                integrity_values.extend([loc.get_string("sha256"), loc.get_string("sha512")])
            self.integrity_dropdown.configure(values=integrity_values)
            self.integrity_dropdown.set(loc.get_string("none")) # Reset
        else:
            self.key_len_value.configure(text="N/A")
            self.nonce_iv_len_value.configure(text="N/A")
            self.cipher_mode_value.configure(text="N/A")
            self.padding_scheme_value.configure(text="N/A")
            self.decompression_dropdown.configure(values=[loc.get_string("none")])
            self.decompression_dropdown.set(loc.get_string("none"))
            self.integrity_dropdown.configure(values=[loc.get_string("none")])
            self.integrity_dropdown.set(loc.get_string("none"))


        if choice == "RSA":
            self.key_type_dropdown.set(loc.get_string("direct_key_base64_pem"))
            self.key_type_dropdown.configure(state="disabled")
        else:
            self.key_type_dropdown.configure(state="normal")
            if self.key_type_dropdown.get() not in [loc.get_string("password_derive_key"), loc.get_string("direct_key_base64_pem")]:
                self.key_type_dropdown.set(loc.get_string("password_derive_key"))

        self.on_key_type_selected(self.key_type_dropdown.get())

    def start_decryption_thread(self):
        input_path = self.input_path_entry.get()
        output_folder = self.output_path_entry.get()
        algo_name = self.algo_dropdown.get()
        key_type = self.key_type_dropdown.get()
        iterations_str = self.iterations_entry.get() if self.app_settings.get("expert_mode", False) else "100000"
        decompression_algo = self.decompression_dropdown.get() if self.app_settings.get("expert_mode", False) else loc.get_string("none")
        integrity_algo = self.integrity_dropdown.get() if self.app_settings.get("expert_mode", False) else loc.get_string("none")


        key_or_password = ""
        if key_type == loc.get_string("password_derive_key"):
            key_or_password = self.password_entry.get()
        else:
            key_or_password = self.direct_key_entry.get()

        if not input_path or not output_folder or not algo_name or not key_or_password:
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("all_fields_filled"))
            return

        if not os.path.exists(input_path):
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("input_path_not_exist"))
            return

        if not os.path.isdir(output_folder):
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("output_folder_not_exist"))
            return

        try:
            iterations = int(iterations_str)
            if iterations <= 0:
                raise ValueError(loc.get_string("iterations_positive_integer"))
        except ValueError:
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("iterations_positive_integer"))
            return

        self.decrypt_button.configure(state="disabled", text=loc.get_string("decrypting"))
        self.progress_bar.set(0)
        self.input_salt_value.configure(state="normal")
        self.input_salt_value.delete(0, ctk.END)
        self.input_salt_value.configure(state="readonly")
        self.input_nonce_iv_value.configure(state="normal")
        self.input_nonce_iv_value.delete(0, ctk.END)
        self.input_nonce_iv_value.configure(state="readonly")


        # Determine if it's a file or folder
        if os.path.isfile(input_path):
            target_paths = [input_path]
        elif os.path.isdir(input_path):
            target_paths = []
            for root, _, files in os.walk(input_path):
                for file in files:
                    target_paths.append(os.path.join(root, file))
        else:
            messagebox.showerror(loc.get_string("input_error"), loc.get_string("invalid_input_path"))
            self.decrypt_button.configure(state="normal", text=loc.get_string("decrypt_files"))
            return

        threading.Thread(target=self._perform_decryption, args=(target_paths, output_folder, algo_name, key_type, key_or_password, iterations, decompression_algo, integrity_algo)).start()

    def _perform_decryption(self, input_paths, output_folder, algo_name, key_type, key_or_password, iterations, decompression_algo, integrity_algo):
        plugin = self.plugin_manager.get_plugin(algo_name)
        if not plugin:
            messagebox.showerror(loc.get_string("decryption_error"), loc.get_string("plugin_not_found", algo_name=algo_name))
            self.after(0, lambda: self.decrypt_button.configure(state="normal", text=loc.get_string("decrypt_files")))
            return

        total_files = len(input_paths)
        if total_files == 0:
            messagebox.showinfo(loc.get_string("decryption_info"), loc.get_string("no_files_decrypt"))
            self.after(0, lambda: self.decrypt_button.configure(state="normal", text=loc.get_string("decrypt_files")))
            return

        overall_progress_per_file = 1.0 / total_files
        successful_operations = 0

        try:
            for i, input_path in enumerate(input_paths):
                try:
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
                        response = messagebox.askyesno(loc.get_string("confirm_overwrite_title"),
                                                       loc.get_string("confirm_overwrite", filepath=output_filepath))
                        if not response:
                            self.log_callback.log(loc.get_string("skipping_overwrite", path=input_path), level="info")
                            continue

                    def file_progress_callback(current, total):
                        file_progress = current / total if total > 0 else 0
                        overall_progress = (i * overall_progress_per_file) + (file_progress * overall_progress_per_file)
                        self.after(0, lambda: self.progress_bar.set(overall_progress))
                        # Only log debug messages if log level is set to debug or lower
                        if logging.getLogger().isEnabledFor(logging.DEBUG):
                            self.after(0, lambda: self.log_callback.log(loc.get_string("file_progress", current_file_num=i+1, total_files=total_files, filename=os.path.basename(input_path)), level="debug"))


                    key_arg = None
                    password_arg = None
                    if key_type == loc.get_string("password_derive_key"):
                        password_arg = key_or_password
                    else: # Direct Key
                        if algo_name == "Fernet":
                            try:
                                key_arg = key_or_password.encode('utf-8')
                            except Exception as e:
                                raise ValueError(f"Invalid Fernet key format: {e}. Ensure it's a valid URL-safe base64 encoded key.")
                        elif algo_name == "AES-256-CBC":
                            if len(key_or_password) == 64 and all(c in '0123456789abcdefABCDEF' for c in key_or_password):
                                key_arg = bytes.fromhex(key_or_password)
                            elif len(key_or_password) == 32:
                                key_arg = key_or_password.encode('latin-1')
                            else:
                                raise ValueError("AES-256-CBC direct key must be 32 bytes (64 hex characters) or a raw 32-byte string.")
                        elif algo_name == "RSA":
                            key_arg = key_or_password # RSA plugin expects PEM string directly
                        elif algo_name == "ChaCha20-Poly1305":
                            # ChaCha20-Poly1305 expects a 32-byte key
                            if len(key_or_password) == 64 and all(c in '0123456789abcdefABCDEF' for c in key_or_password):
                                key_arg = bytes.fromhex(key_or_password) # Assume hex string
                            elif len(key_or_password) == 32:
                                key_arg = key_or_password.encode('latin-1') # Assume raw bytes
                            else:
                                raise ValueError("ChaCha20-Poly1305 direct key must be 32 bytes (64 hex characters) or a raw 32-byte string.")
                        else:
                            key_arg = key_or_password.encode('utf-8')


                    # Pass decompression and integrity options to plugin
                    plugin.decrypt_file(input_path, output_filepath, key=key_arg, password=password_arg, progress_callback=file_progress_callback, iterations=iterations, decompression=decompression_algo, integrity_check=integrity_algo)

                    self.log_callback.log(loc.get_string("successfully_decrypted", input_path=input_path, output_path=output_filepath))
                    successful_operations += 1

                    if self.app_settings.get("expert_mode", False):
                        self.after(0, lambda: self.input_salt_value.configure(state="normal"))
                        self.after(0, lambda: self.input_salt_value.delete(0, ctk.END))
                        self.after(0, lambda: self.input_salt_value.insert(0, loc.get_string("read_internal")))
                        self.after(0, lambda: self.input_salt_value.configure(state="readonly"))

                        self.after(0, lambda: self.input_nonce_iv_value.configure(state="normal"))
                        self.after(0, lambda: self.input_nonce_iv_value.delete(0, ctk.END))
                        self.after(0, lambda: self.input_nonce_iv_value.insert(0, loc.get_string("read_internal")))
                        self.after(0, lambda: self.input_nonce_iv_value.configure(state="readonly"))

                except ValueError as ve:
                    self.log_callback.log(loc.get_string("decryption_failed_for", path=input_path, error=ve), level="error")
                except Exception as e:
                    self.log_callback.log(loc.get_string("unexpected_decryption_error", path=input_path, error=e), level="error")
            # End of for loop

            self.after(0, lambda: self.progress_bar.set(1.0))
            if successful_operations > 0:
                messagebox.showinfo(loc.get_string("decryption_complete_title"), loc.get_string("decryption_complete", count=successful_operations))
            else:
                messagebox.showinfo(loc.get_string("decryption_info"), loc.get_string("no_files_decrypted"))
        except Exception as e:
            messagebox.showerror(loc.get_string("overall_decryption_error_title"), loc.get_string("overall_decryption_error", error=e))
            self.log_callback.log(loc.get_string("overall_decryption_error", error=e), level="error")
        finally:
            self.after(0, lambda: self.decrypt_button.configure(state="normal", text=loc.get_string("decrypt_files")))


class GenerateKeysTab(ctk.CTkFrame):
    def __init__(self, master, plugin_manager, log_callback, app_settings, **kwargs):
        super().__init__(master, **kwargs)
        self.plugin_manager = plugin_manager
        self.log_callback = log_callback
        self.app_settings = app_settings # Added app_settings
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(12, weight=1) # Adjusted for more options

        self.setup_ui()
        self.localize_ui() # Call localize after setup_ui
        self.update_plugin_options()
        self.update_expert_mode_ui()


    def localize_ui(self):
        self.algo_label.configure(text=loc.get_string("algorithm_key_generation"))
        self.key_type_label.configure(text=loc.get_string("key_type"))
        self.key_type_dropdown.configure(values=[loc.get_string("symmetric"), loc.get_string("asymmetric"), loc.get_string("password_based")])
        self.key_length_label.configure(text=loc.get_string("key_length_bits_rsa"))
        self.output_format_label.configure(text=loc.get_string("output_format"))
        self.output_format_dropdown.configure(values=[loc.get_string("base64_url_safe"), loc.get_string("hex"), loc.get_string("pem_rsa_only")])
        self.generate_button.configure(text=loc.get_string("generate_keys"))
        self.generated_keys_label.configure(text=loc.get_string("generated_keys"))
        self.copy_key_button.configure(text=loc.get_string("copy_keys_clipboard"))
        self.kdf_label.configure(text=loc.get_string("key_derivation_function"))
        self.salt_length_label.configure(text=loc.get_string("salt_length_bytes"))
        self.key_usage_label.configure(text=loc.get_string("key_usage"))
        self.key_usage_dropdown.configure(values=[loc.get_string("encryption"), loc.get_string("signing"), loc.get_string("key_exchange")])


    def setup_ui(self):
        # Algorithm Selection
        self.algo_label = ctk.CTkLabel(self, text="Algorithm for Key Generation:", text_color=THEME_TEXT_COLOR)
        self.algo_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown = ctk.CTkComboBox(self, values=self.algo_options, command=self.on_algo_selected,
                                             fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                             button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                             border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                             dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                             dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
        else:
            self.algo_dropdown.set(loc.get_string("no_plugins_loaded"))
            self.algo_dropdown.configure(state="disabled")
        self.algo_dropdown.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        # Key Type (Symmetric/Asymmetric/Password-Based)
        self.key_type_label = ctk.CTkLabel(self, text="Key Type:", text_color=THEME_TEXT_COLOR)
        self.key_type_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.key_type_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("symmetric"), loc.get_string("asymmetric"), loc.get_string("password_based")],
                                                 command=self.on_key_type_selected,
                                                 fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                 button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                 dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.key_type_dropdown.set(loc.get_string("symmetric")) # Default
        self.key_type_dropdown.grid(row=1, column=1, padx=10, pady=5, sticky="ew")


        # Expert Mode: Key Length (Optional, for RSA)
        self.key_length_label = ctk.CTkLabel(self, text="Key Length (bits, for RSA):", text_color=THEME_TEXT_COLOR)
        self.key_length_entry = ctk.CTkEntry(self, placeholder_text="e.g., 2048, 4096 (for RSA)",
                                             fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                             border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.key_length_entry.insert(0, "2048") # Default for RSA

        # Expert Mode: Key Derivation Function (KDF)
        self.kdf_label = ctk.CTkLabel(self, text="Key Derivation Function (KDF):", text_color=THEME_TEXT_COLOR)
        self.kdf_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("pbkdf2_hmac"), loc.get_string("scrypt")],
                                            fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                            button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                            border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                            dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                            dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.kdf_dropdown.set(loc.get_string("pbkdf2_hmac"))

        self.salt_length_label = ctk.CTkLabel(self, text="Salt Length (bytes):", text_color=THEME_TEXT_COLOR)
        self.salt_length_entry = ctk.CTkEntry(self, placeholder_text="e.g., 16",
                                              fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                              border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.salt_length_entry.insert(0, "16") # Default for PBKDF2HMAC

        # Expert Mode: Key Usage (for Asymmetric)
        self.key_usage_label = ctk.CTkLabel(self, text="Key Usage:", text_color=THEME_TEXT_COLOR)
        self.key_usage_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("encryption"), loc.get_string("signing"), loc.get_string("key_exchange")],
                                                  fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                  button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                  dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.key_usage_dropdown.set(loc.get_string("encryption"))

        # Expert Mode: Output Format
        self.output_format_label = ctk.CTkLabel(self, text="Output Format:", text_color=THEME_TEXT_COLOR)
        self.output_format_dropdown = ctk.CTkComboBox(self, values=[loc.get_string("base64_url_safe"), loc.get_string("hex"), loc.get_string("pem_rsa_only")],
                                                      fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                      button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                      border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                      dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                      dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.output_format_dropdown.set(loc.get_string("base64_url_safe"))

        # Generate Button
        self.generate_button = ctk.CTkButton(self, text="Generate Key(s)", command=self.generate_key,
                                             fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                             text_color="white", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.generate_button.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        # Generated Key Output
        self.generated_keys_label = ctk.CTkLabel(self, text="Generated Key(s):", text_color=THEME_TEXT_COLOR)
        self.generated_keys_label.grid(row=7, column=0, padx=10, pady=5, sticky="w")
        self.key_output_textbox = ctk.CTkTextbox(self, height=150, state="disabled", wrap="word",
                                                 fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                 border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.key_output_textbox.grid(row=8, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

        self.copy_key_button = ctk.CTkButton(self, text="Copy Key(s) to Clipboard", command=self.copy_key,
                                             fg_color=THEME_WIDGET_BG, hover_color=THEME_ACCENT_BLUE_HOVER,
                                             text_color=THEME_TEXT_COLOR, border_color=THEME_WIDGET_BORDER,
                                             corner_radius=8)
        self.copy_key_button.grid(row=9, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                          border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=10, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

        self.on_key_type_selected(self.key_type_dropdown.get()) # Initial call to set visibility

    def update_expert_mode_ui(self):
        is_expert = self.app_settings.get("expert_mode", False)
        current_row = 2 # Starting row for expert elements

        if is_expert:
            self.key_length_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.key_length_entry.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.kdf_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.kdf_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.salt_length_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.salt_length_entry.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.key_usage_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.key_usage_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.output_format_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.output_format_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

        else:
            self.key_length_label.grid_forget()
            self.key_length_entry.grid_forget()
            self.kdf_label.grid_forget()
            self.kdf_dropdown.grid_forget()
            self.salt_length_label.grid_forget()
            self.salt_length_entry.grid_forget()
            self.key_usage_label.grid_forget()
            self.key_usage_dropdown.grid_forget()
            self.output_format_label.grid_forget()
            self.output_format_dropdown.grid_forget()

        self.generate_button.grid(row=current_row, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        self.generated_keys_label.grid(row=current_row + 1, column=0, padx=10, pady=5, sticky="w")
        self.key_output_textbox.grid(row=current_row + 2, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        self.copy_key_button.grid(row=current_row + 3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        self.log_textbox.grid(row=current_row + 4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.on_key_type_selected(self.key_type_dropdown.get()) # Update states based on key type
        self.on_algo_selected(self.algo_dropdown.get()) # Update dropdown states

    def update_plugin_options(self):
        self.algo_options = self.plugin_manager.get_plugin_names()
        self.algo_dropdown.configure(values=self.algo_options)
        if self.algo_options:
            self.algo_dropdown.set(self.algo_options[0])
            self.algo_dropdown.configure(state="normal")
        else:
            self.algo_dropdown.set(loc.get_string("no_plugins_loaded"))
            self.algo_dropdown.configure(state="disabled")
        self.on_algo_selected(self.algo_dropdown.get())

    def on_key_type_selected(self, choice):
        is_expert = self.app_settings.get("expert_mode", False)
        if is_expert:
            if choice == loc.get_string("asymmetric"):
                self.key_length_entry.configure(state="normal")
                self.kdf_dropdown.configure(state="disabled")
                self.salt_length_entry.configure(state="disabled")
                self.key_usage_dropdown.configure(state="normal")
                self.output_format_dropdown.configure(values=[loc.get_string("base64_url_safe"), loc.get_string("hex"), loc.get_string("pem_rsa_only")], state="normal")
                if self.output_format_dropdown.get() not in [loc.get_string("pem_rsa_only"), loc.get_string("base64_url_safe"), loc.get_string("hex")]:
                    self.output_format_dropdown.set(loc.get_string("pem_rsa_only"))
            elif choice == loc.get_string("password_based"):
                self.key_length_entry.configure(state="disabled")
                self.kdf_dropdown.configure(state="normal")
                self.salt_length_entry.configure(state="normal")
                self.key_usage_dropdown.configure(state="disabled") # Password based keys usually for encryption/decryption
                self.output_format_dropdown.configure(values=[loc.get_string("base64_url_safe"), loc.get_string("hex")], state="normal")
                if self.output_format_dropdown.get() not in [loc.get_string("base64_url_safe"), loc.get_string("hex")]:
                    self.output_format_dropdown.set(loc.get_string("base64_url_safe"))
            else: # Symmetric
                self.key_length_entry.configure(state="disabled")
                self.kdf_dropdown.configure(state="disabled")
                self.salt_length_entry.configure(state="disabled")
                self.key_usage_dropdown.configure(state="normal") # Symmetric keys can also be used for signing, etc.
                self.output_format_dropdown.configure(values=[loc.get_string("base64_url_safe"), loc.get_string("hex")], state="normal")
                if self.output_format_dropdown.get() not in [loc.get_string("base64_url_safe"), loc.get_string("hex")]:
                    self.output_format_dropdown.set(loc.get_string("base64_url_safe"))
        else: # Not expert mode, all hidden anyway
            pass

        self.on_algo_selected(self.algo_dropdown.get()) # Update based on algorithm too

    def on_algo_selected(self, choice):
        is_expert = self.app_settings.get("expert_mode", False)
        plugin = self.plugin_manager.get_plugin(choice)

        if is_expert and plugin:
            # Update KDF options based on plugin support
            kdf_values = [loc.get_string("none")]
            if getattr(plugin, 'kdf_supported', False):
                kdf_values = [loc.get_string(k.lower().replace('-', '_')) for k in getattr(plugin, 'key_derivation_functions', [])]
                if not kdf_values: # If plugin says KDF supported but provides no specific KDFs
                    kdf_values = [loc.get_string("pbkdf2_hmac")] # Default fallback
            self.kdf_dropdown.configure(values=kdf_values)
            self.kdf_dropdown.set(kdf_values[0] if kdf_values else loc.get_string("none")) # Set default

            # Update Salt Length based on plugin suggestion
            self.salt_length_entry.delete(0, ctk.END)
            self.salt_length_entry.insert(0, str(getattr(plugin, 'salt_length_bytes', 'N/A')))
            self.salt_length_entry.configure(state="normal" if getattr(plugin, 'kdf_supported', False) else "disabled")

            # Update Key Usage options based on plugin
            key_usage_values = [loc.get_string(u.lower().replace(' ', '_')) for u in getattr(plugin, 'key_usage_options', ["Encryption"])]
            self.key_usage_dropdown.configure(values=key_usage_values)
            self.key_usage_dropdown.set(key_usage_values[0] if key_usage_values else loc.get_string("encryption"))


            # Handle RSA specific controls
            if choice == "RSA":
                self.key_type_dropdown.set(loc.get_string("asymmetric"))
                self.key_type_dropdown.configure(state="disabled") # Force asymmetric for RSA
                self.key_length_entry.configure(state="normal")
                self.output_format_dropdown.configure(values=[loc.get_string("base64_url_safe"), loc.get_string("hex"), loc.get_string("pem_rsa_only")], state="normal")
                if self.output_format_dropdown.get() not in [loc.get_string("pem_rsa_only"), loc.get_string("base64_url_safe"), loc.get_string("hex")]:
                    self.output_format_dropdown.set(loc.get_string("pem_rsa_only"))
            else:
                if self.key_type_dropdown.get() == loc.get_string("asymmetric"): # If it was RSA, reset key type
                    self.key_type_dropdown.set(loc.get_string("symmetric"))
                self.key_type_dropdown.configure(state="normal")
                self.key_length_entry.configure(state="disabled")
                self.output_format_dropdown.configure(values=[loc.get_string("base64_url_safe"), loc.get_string("hex")], state="normal")
                if self.output_format_dropdown.get() not in [loc.get_string("base64_url_safe"), loc.get_string("hex")]:
                    self.output_format_dropdown.set(loc.get_string("base64_url_safe"))

            # Ensure KDF/Salt fields are correctly enabled/disabled based on key type and plugin support
            self.on_key_type_selected(self.key_type_dropdown.get())
        else: # Not expert mode or no plugin
            self.key_type_dropdown.configure(state="normal")
            if self.key_type_dropdown.get() not in [loc.get_string("symmetric"), loc.get_string("asymmetric"), loc.get_string("password_based")]:
                self.key_type_dropdown.set(loc.get_string("symmetric")) # Default if no expert mode
            self.key_length_entry.configure(state="disabled")
            self.kdf_dropdown.configure(state="disabled")
            self.salt_length_entry.configure(state="disabled")
            self.key_usage_dropdown.configure(state="disabled")
            self.output_format_dropdown.configure(state="disabled")
            self.output_format_dropdown.set(loc.get_string("base64_url_safe")) # Default


    def generate_key(self):
        algo_name = self.algo_dropdown.get()
        plugin = self.plugin_manager.get_plugin(algo_name)
        is_expert = self.app_settings.get("expert_mode", False)

        if not plugin:
            messagebox.showerror(loc.get_string("error"), loc.get_string("plugin_not_found_gen", algo_name=algo_name))
            return

        key_length = None
        kdf_algo = None
        salt_len = None
        key_usage = None
        output_format = loc.get_string("base64_url_safe") # Default if not expert

        if is_expert:
            key_type = self.key_type_dropdown.get()
            output_format = self.output_format_dropdown.get()

            if key_type == loc.get_string("asymmetric"):
                try:
                    key_length = int(self.key_length_entry.get())
                    if key_length not in [1024, 2048, 3072, 4096]:
                        raise ValueError(loc.get_string("invalid_rsa_key_length"))
                except ValueError as e:
                    messagebox.showerror(loc.get_string("input_error"), f"{loc.get_string('invalid_key_length')}: {e}")
                    return
                key_usage = self.key_usage_dropdown.get()
                if algo_name != "RSA" and output_format == loc.get_string("pem_rsa_only"):
                    messagebox.showerror(loc.get_string("format_error"), loc.get_string("pem_rsa_only_format"))
                    return
            elif key_type == loc.get_string("password_based"):
                kdf_algo = self.kdf_dropdown.get()
                try:
                    salt_len = int(self.salt_length_entry.get())
                    if salt_len <= 0:
                        raise ValueError("Salt length must be a positive integer.")
                except ValueError as e:
                    messagebox.showerror(loc.get_string("input_error"), f"Invalid salt length: {e}")
                    return
            else: # Symmetric
                key_usage = self.key_usage_dropdown.get()

        self.generate_button.configure(state="disabled", text=loc.get_string("generating"))
        self.key_output_textbox.configure(state="normal")
        self.key_output_textbox.delete("1.0", ctk.END)
        self.key_output_textbox.insert(ctk.END, loc.get_string("generating_keys"))
        self.key_output_textbox.configure(state="disabled")

        threading.Thread(target=self._perform_key_generation, args=(plugin, algo_name, key_length, output_format, kdf_algo, salt_len, key_usage)).start()

    def _perform_key_generation(self, plugin, algo_name, key_length, output_format, kdf_algo, salt_len, key_usage):
        try:
            # Pass new parameters to plugin.generate_key
            # Ensure generate_key can handle None for optional args
            generated_key = plugin.generate_key(length=key_length, kdf=kdf_algo, salt_len=salt_len, key_usage=key_usage)

            output_text = ""
            if isinstance(generated_key, dict): # For RSA, returns dict with public/private
                if output_format == loc.get_string("pem_rsa_only"):
                    output_text += "--- PUBLIC KEY (PEM) ---\n"
                    output_text += generated_key.get("public_key", "N/A") + "\n\n"
                    output_text += "--- PRIVATE KEY (PEM) ---\n"
                    output_text += generated_key.get("private_key", "N/A") + "\n"
                else: # Base64 or Hex for RSA components
                    output_text += "--- PUBLIC KEY ---\n"
                    # Decode PEM to bytes, then encode to desired format
                    try:
                        # Attempt to load as PEM, if fails, treat as raw string (e.g., if plugin returns raw bytes for public key)
                        pub_key_bytes = serialization.load_pem_public_key(generated_key.get("public_key", "").encode(), backend=default_backend()).public_bytes(
                            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                    except ValueError: # If not a valid PEM, treat as raw string
                        pub_key_bytes = generated_key.get("public_key", "").encode()

                    if output_format == loc.get_string("base64_url_safe"):
                        output_text += urlsafe_b64encode(pub_key_bytes).decode() + "\n\n"
                    elif output_format == loc.get_string("hex"):
                        output_text += pub_key_bytes.hex() + "\n\n"

                    output_text += "--- PRIVATE KEY ---\n"
                    try:
                        # Attempt to load as PEM, if fails, treat as raw string
                        priv_key_bytes = serialization.load_pem_private_key(generated_key.get("private_key", "").encode(), password=None, backend=default_backend()).private_bytes(
                            encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
                        )
                    except ValueError: # If not a valid PEM, treat as raw string
                        priv_key_bytes = generated_key.get("private_key", "").encode()

                    if output_format == loc.get_string("base64_url_safe"):
                        output_text += urlsafe_b64encode(priv_key_bytes).decode() + "\n"
                    elif output_format == loc.get_string("hex"):
                        output_text += priv_key_bytes.hex() + "\n"
            elif isinstance(generated_key, bytes):
                if output_format == loc.get_string("base64_url_safe"):
                    output_text = urlsafe_b64encode(generated_key).decode()
                elif output_format == loc.get_string("hex"):
                    output_text = generated_key.hex()
                else: # Fallback, should not happen if dropdown values are managed
                    output_text = str(generated_key)
            else: # For password-based key strings
                output_text = str(generated_key)

            self.after(0, lambda: self.key_output_textbox.configure(state="normal"))
            self.after(0, lambda: self.key_output_textbox.delete("1.0", ctk.END))
            self.after(0, lambda: self.key_output_textbox.insert(ctk.END, output_text))
            self.after(0, lambda: self.key_output_textbox.configure(state="disabled"))
            self.log_callback.log(loc.get_string("generated_key_format", algo_name=algo_name, output_format=output_format))
            self.after(0, lambda: messagebox.showinfo(loc.get_string("key_generation"), loc.get_string("key_generation_success", algo_name=algo_name)))

        except Exception as e:
            self.after(0, lambda: messagebox.showerror(loc.get_string("key_generation_error_title"), loc.get_string("key_generation_error", error=e)))
            self.log_callback.log(loc.get_string("key_generation_error", error=e), level="error")
            self.after(0, lambda: self.key_output_textbox.configure(state="normal"))
            self.after(0, lambda: self.key_output_textbox.delete("1.0", ctk.END))
            self.after(0, lambda: self.key_output_textbox.insert(ctk.END, f"Error: {e}"))
            self.after(0, lambda: self.key_output_textbox.configure(state="disabled"))
        finally:
            self.after(0, lambda: self.generate_button.configure(state="normal", text=loc.get_string("generate_keys")))

    def copy_key(self):
        key_text = self.key_output_textbox.get("1.0", ctk.END).strip()
        if key_text:
            self.clipboard_clear()
            self.clipboard_append(key_text)
            messagebox.showinfo(loc.get_string("copy_to_clipboard"), loc.get_string("key_copied_clipboard"))
            self.log_callback.log(loc.get_string("key_copied_clipboard"))
        else:
            messagebox.showwarning(loc.get_string("copy_to_clipboard"), loc.get_string("no_key_copy"))


class SettingsTab(ctk.CTkFrame):
    def __init__(self, master, app_settings, log_callback, main_app_ref, **kwargs):
        super().__init__(master, **kwargs)
        self.app_settings = app_settings
        self.log_callback = log_callback
        self.main_app_ref = main_app_ref # Reference to the main app to trigger UI updates
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(12, weight=1) # Adjusted for more options

        self.setup_ui()
        self.localize_ui() # Call localize after setup_ui
        self.load_settings()


    def localize_ui(self):
        self.theme_label.configure(text=loc.get_string("theme"))
        self.theme_dropdown.configure(values=[loc.get_string("dark"), loc.get_string("light"), loc.get_string("system")])
        self.auto_clear_logs_checkbox.configure(text=loc.get_string("auto_clear_logs_startup"))
        self.overwrite_files_checkbox.configure(text=loc.get_string("confirm_overwrite_files"))
        self.expert_mode_checkbox.configure(text=loc.get_string("enable_expert_mode"))
        self.log_level_label.configure(text=loc.get_string("log_level"))
        self.log_level_dropdown.configure(values=["INFO", "WARNING", "ERROR", "DEBUG"]) # Log levels are fixed
        self.chunk_size_label.configure(text=loc.get_string("file_chunk_size_kb"))
        self.language_label.configure(text=loc.get_string("language_wip")) # Still WIP for this label
        self.language_dropdown.configure(values=loc.get_available_languages()) # Dynamically get available languages
        self.export_button.configure(text=loc.get_string("export_settings"))
        self.import_button.configure(text=loc.get_string("import_settings"))
        self.security_warnings_checkbox.configure(text=loc.get_string("security_warnings_toggle"))


    def setup_ui(self):
        # Theme Selector
        self.theme_label = ctk.CTkLabel(self, text="Theme:", text_color=THEME_TEXT_COLOR)
        self.theme_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.theme_options = ["Dark", "Light", "System"]
        self.theme_dropdown = ctk.CTkComboBox(self, values=self.theme_options, command=self.change_theme,
                                             fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                             button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                             border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                             dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                             dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.theme_dropdown.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        # Auto-clear Logs Toggle
        self.auto_clear_logs_checkbox = ctk.CTkCheckBox(self, text="Auto-clear logs on startup",
                                                        command=self.toggle_auto_clear_logs,
                                                        fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                        hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)
        self.auto_clear_logs_checkbox.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        # Overwrite Files Confirmation Toggle
        self.overwrite_files_checkbox = ctk.CTkCheckBox(self, text="Confirm before overwriting files",
                                                        command=self.toggle_overwrite_files,
                                                        fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                        hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)
        self.overwrite_files_checkbox.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        # Expert Mode Toggle
        self.expert_mode_checkbox = ctk.CTkCheckBox(self, text="Enable Expert Mode (More Options)",
                                                    command=self.toggle_expert_mode,
                                                    fg_color=THEME_WIDGET_BG, text_color=THEME_ACCENT_BLUE,
                                                    hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)
        self.expert_mode_checkbox.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        # Security Warnings Toggle
        self.security_warnings_checkbox = ctk.CTkCheckBox(self, text="Show Security Warnings (e.g., for weak passwords)",
                                                          command=self.toggle_security_warnings,
                                                          fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                                          hover_color=THEME_ACCENT_BLUE_HOVER, corner_radius=8)
        self.security_warnings_checkbox.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="w")


        # Expert Mode: Log Level
        self.log_level_label = ctk.CTkLabel(self, text="Log Level:", text_color=THEME_TEXT_COLOR)
        self.log_level_dropdown = ctk.CTkComboBox(self, values=["INFO", "WARNING", "ERROR", "DEBUG"],
                                                  command=self.change_log_level,
                                                  fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                  button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                  dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                  dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)

        # Expert Mode: File Chunk Size
        self.chunk_size_label = ctk.CTkLabel(self, text="File Chunk Size (KB):", text_color=THEME_TEXT_COLOR)
        self.chunk_size_entry = ctk.CTkEntry(self, placeholder_text="e.g., 64",
                                             fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                             border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.chunk_size_entry.insert(0, "64") # Default 64KB

        # Language Selector
        self.language_label = ctk.CTkLabel(self, text="Language:", text_color=THEME_TEXT_COLOR)
        self.language_dropdown = ctk.CTkComboBox(self, values=loc.get_available_languages(), command=self.change_language,
                                                 fg_color=THEME_WIDGET_BG, button_color=THEME_ACCENT_BLUE,
                                                 button_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 border_color=THEME_WIDGET_BORDER, text_color=THEME_TEXT_COLOR,
                                                 dropdown_fg_color=THEME_WIDGET_BG, dropdown_hover_color=THEME_ACCENT_BLUE_HOVER,
                                                 dropdown_text_color=THEME_TEXT_COLOR, corner_radius=8)
        self.language_dropdown.set(loc.current_language)


        # Export/Import Configuration
        self.export_button = ctk.CTkButton(self, text="Export Settings", command=self.export_settings,
                                           fg_color=THEME_WIDGET_BG, hover_color=THEME_ACCENT_BLUE_HOVER,
                                           text_color=THEME_TEXT_COLOR, border_color=THEME_WIDGET_BORDER,
                                           corner_radius=8)
        self.export_button.grid(row=10, column=0, padx=10, pady=10, sticky="ew")
        self.import_button = ctk.CTkButton(self, text="Import Settings", command=self.import_settings,
                                           fg_color=THEME_WIDGET_BG, hover_color=THEME_ACCENT_BLUE_HOVER,
                                           text_color=THEME_TEXT_COLOR, border_color=THEME_WIDGET_BORDER,
                                           corner_radius=8)
        self.import_button.grid(row=10, column=1, padx=10, pady=10, sticky="ew")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                          border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=11, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

        self.update_expert_mode_ui() # Initial UI update based on expert mode setting

    def update_expert_mode_ui(self):
        is_expert = self.app_settings.get("expert_mode", False)
        current_row = 5 # Starting row for expert elements

        if is_expert:
            self.log_level_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.log_level_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.chunk_size_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.chunk_size_entry.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

            self.language_label.grid(row=current_row, column=0, padx=10, pady=5, sticky="w")
            self.language_dropdown.grid(row=current_row, column=1, padx=10, pady=5, sticky="ew")
            current_row += 1

        else:
            self.log_level_label.grid_forget()
            self.log_level_dropdown.grid_forget()
            self.chunk_size_label.grid_forget()
            self.chunk_size_entry.grid_forget()
            self.language_label.grid_forget()
            self.language_dropdown.grid_forget()

        self.export_button.grid(row=current_row, column=0, padx=10, pady=10, sticky="ew")
        self.import_button.grid(row=current_row, column=1, padx=10, pady=10, sticky="ew")
        self.log_textbox.grid(row=current_row + 1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    def load_settings(self):
        self.theme_dropdown.set(self.app_settings.get("theme", "Dark")) # Default to Dark for new theme
        self.auto_clear_logs_checkbox.select() if self.app_settings.get("auto_clear_logs", False) else self.auto_clear_logs_checkbox.deselect()
        self.overwrite_files_checkbox.select() if self.app_settings.get("overwrite_files", False) else self.overwrite_files_checkbox.deselect()
        self.expert_mode_checkbox.select() if self.app_settings.get("expert_mode", False) else self.expert_mode_checkbox.deselect()
        self.security_warnings_checkbox.select() if self.app_settings.get("show_security_warnings", True) else self.security_warnings_checkbox.deselect()
        self.log_level_dropdown.set(self.app_settings.get("log_level", "INFO"))
        self.chunk_size_entry.delete(0, ctk.END)
        self.chunk_size_entry.insert(0, str(self.app_settings.get("file_chunk_size_kb", 64)))
        
        # Set language from settings, ensuring it's a valid loaded language
        saved_lang = self.app_settings.get("language", "en")
        if saved_lang not in loc.get_available_languages():
            saved_lang = "en" # Fallback to hardcoded English if saved language is not available
        self.language_dropdown.set(saved_lang)
        loc.set_language(saved_lang) # Apply language to localization manager
        
        self.update_expert_mode_ui() # Ensure UI reflects loaded expert mode

    def change_theme(self, new_theme):
        ctk.set_appearance_mode(new_theme)
        self.app_settings["theme"] = new_theme
        self.log_callback.log(loc.get_string("theme_changed", theme=new_theme))

    def toggle_auto_clear_logs(self):
        self.app_settings["auto_clear_logs"] = bool(self.auto_clear_logs_checkbox.get())
        self.log_callback.log(loc.get_string("auto_clear_logs_set", state=self.app_settings['auto_clear_logs']))

    def toggle_overwrite_files(self):
        self.app_settings["overwrite_files"] = bool(self.overwrite_files_checkbox.get())
        self.log_callback.log(loc.get_string("confirm_overwrite_set", state=self.app_settings['overwrite_files']))

    def toggle_expert_mode(self):
        self.app_settings["expert_mode"] = bool(self.expert_mode_checkbox.get())
        self.log_callback.log(loc.get_string("expert_mode_set", state=self.app_settings['expert_mode']))
        self.main_app_ref.update_all_tab_expert_mode_ui() # Trigger UI update across all tabs
        if self.app_settings["expert_mode"] and self.app_settings.get("show_security_warnings", True):
            messagebox.showwarning(loc.get_string("expert_mode_warning_title"), loc.get_string("expert_mode_warning_message"))

    def toggle_security_warnings(self):
        self.app_settings["show_security_warnings"] = bool(self.security_warnings_checkbox.get())
        self.log_callback.log(f"Show security warnings set to {self.app_settings['show_security_warnings']}")

    def change_log_level(self, new_level):
        logging.getLogger().setLevel(getattr(logging, new_level))
        self.app_settings["log_level"] = new_level
        self.log_callback.log(loc.get_string("log_level_changed", level=new_level))

    def change_language(self, new_lang_code):
        if loc.set_language(new_lang_code):
            self.app_settings["language"] = new_lang_code
            self.log_callback.log(loc.get_string("language_changed_to", lang=new_lang_code))
            messagebox.showinfo(loc.get_string("select_language"), loc.get_string("language_change_restart"))
            # Trigger UI re-localization for all tabs
            self.main_app_ref.relocalize_all_tabs()
        else:
            messagebox.showerror(loc.get_string("select_language"), loc.get_string("language_not_found", lang=new_lang_code))


    def export_settings(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[(loc.get_string("json_files"), "*.json")],
                                                 title=loc.get_string("export_settings"))
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.app_settings, f, indent=4)
                messagebox.showinfo(loc.get_string("export_settings"), loc.get_string("settings_exported"))
                self.log_callback.log(loc.get_string("settings_exported_to", path=file_path))
            except Exception as e:
                messagebox.showerror(loc.get_string("export_error"), loc.get_string("failed_export_settings", error=e))
                self.log_callback.log(loc.get_string("failed_export_settings", error=e), level="error")

    def import_settings(self):
        file_path = filedialog.askopenfilename(filetypes=[(loc.get_string("json_files"), "*.json")],
                                               title=loc.get_string("import_settings"))
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    imported_settings = json.load(f)
                self.app_settings.update(imported_settings) # Update current settings
                self.load_settings() # Reload UI to reflect new settings
                messagebox.showinfo(loc.get_string("import_settings"), loc.get_string("settings_imported"))
                self.log_callback.log(loc.get_string("settings_imported_from", path=file_path))
            except json.JSONDecodeError:
                messagebox.showerror(loc.get_string("import_error"), loc.get_string("invalid_json_file"))
                self.log_callback.log(loc.get_string("failed_import_settings_invalid_json"), level="error")
            except Exception as e:
                messagebox.showerror(loc.get_string("import_error"), loc.get_string("failed_import_settings", error=e))
                self.log_callback.log(loc.get_string("failed_import_settings", error=e), level="error")


class AboutTab(ctk.CTkFrame):
    def __init__(self, master, log_callback, **kwargs):
        super().__init__(master, **kwargs)
        self.log_callback = log_callback
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(6, weight=1) # Adjusted for more options

        self.setup_ui()
        self.localize_ui() # Call localize after setup_ui

    def localize_ui(self):
        self.app_name_label.configure(text=loc.get_string("app_name"))
        self.version_label.configure(text=loc.get_string("version") + APP_VERSION)
        self.developer_label.configure(text=loc.get_string("developed_by") + DEVELOPER_NAME)
        self.github_button.configure(text=loc.get_string("view_github"))
        self.license_label.configure(text=loc.get_string("license_proprietary"))
        self.feedback_label.configure(text=loc.get_string("feedback_contact_github"))


    def setup_ui(self):
        self.app_name_label = ctk.CTkLabel(self, text=APP_NAME, font=ctk.CTkFont(size=24, weight="bold"), text_color=THEME_TEXT_COLOR)
        self.app_name_label.grid(row=0, column=0, padx=20, pady=10, sticky="n")

        self.version_label = ctk.CTkLabel(self, text=f"Version: {APP_VERSION}", font=ctk.CTkFont(size=14), text_color=THEME_TEXT_COLOR)
        self.version_label.grid(row=1, column=0, padx=20, pady=5, sticky="n")

        self.developer_label = ctk.CTkLabel(self, text=f"Developed by: {DEVELOPER_NAME}", font=ctk.CTkFont(size=14), text_color=THEME_TEXT_COLOR)
        self.developer_label.grid(row=2, column=0, padx=20, pady=5, sticky="n")

        self.github_button = ctk.CTkButton(self, text="View GitHub", command=self.open_github,
                                           fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                           text_color="white", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.github_button.grid(row=3, column=0, padx=20, pady=10, sticky="n")

        self.license_label = ctk.CTkLabel(self, text="License: Proprietary (See terms.txt)", font=ctk.CTkFont(size=12), text_color=THEME_TEXT_COLOR)
        self.license_label.grid(row=4, column=0, padx=20, pady=5, sticky="n")

        self.feedback_label = ctk.CTkLabel(self, text="For feedback or contact, please visit the GitHub page.", font=ctk.CTkFont(size=12), text_color=THEME_TEXT_COLOR)
        self.feedback_label.grid(row=5, column=0, padx=20, pady=5, sticky="n")

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                          border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=6, column=0, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

    def open_github(self):
        import webbrowser
        webbrowser.open_new(GITHUB_URL)
        self.log_callback.log(loc.get_string("opened_github_link", url=GITHUB_URL))

class PluginsTab(ctk.CTkFrame):
    def __init__(self, master, plugin_manager, log_callback, app_settings, **kwargs):
        super().__init__(master, **kwargs)
        self.plugin_manager = plugin_manager
        self.log_callback = log_callback
        self.app_settings = app_settings
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1) # For the log textbox

        self.setup_ui()
        self.localize_ui() # Call localize after setup_ui
        self.load_plugin_list()
        self.update_expert_mode_ui()


    def localize_ui(self):
        self.title_label.configure(text=loc.get_string("loaded_encryption_plugins"))
        self.reload_button.configure(text=loc.get_string("reload_plugins"))
        self.selected_plugin_label.configure(text=loc.get_string("selected_plugin_details"))
        self.selected_plugin_name.configure(text=loc.get_string("name") + "N/A")
        self.selected_plugin_key_len.configure(text=loc.get_string("key_length") + "N/A")
        self.selected_plugin_nonce_len.configure(text=loc.get_string("nonce_iv_length") + "N/A")
        self.selected_plugin_mode.configure(text=loc.get_string("cipher_mode") + "N/A")
        self.selected_plugin_padding.configure(text=loc.get_string("padding") + "N/A")


    def setup_ui(self):
        self.title_label = ctk.CTkLabel(self, text="Loaded Encryption Plugins", font=ctk.CTkFont(size=18, weight="bold"), text_color=THEME_TEXT_COLOR)
        self.title_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.plugin_list_frame = ctk.CTkScrollableFrame(self, height=200,
                                                        fg_color=THEME_WIDGET_BG, border_color=THEME_WIDGET_BORDER,
                                                        corner_radius=8)
        self.plugin_list_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.plugin_list_frame.grid_columnconfigure(0, weight=1)

        self.reload_button = ctk.CTkButton(self, text="Reload Plugins", command=self.reload_plugins,
                                           fg_color=THEME_ACCENT_BLUE, hover_color=THEME_ACCENT_BLUE_HOVER,
                                           text_color="white", corner_radius=8, font=ctk.CTkFont(weight="bold"))
        self.reload_button.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        # Expert Mode: Plugin Details Display
        self.plugin_details_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.plugin_details_frame.grid_columnconfigure((0, 1), weight=1)

        self.selected_plugin_label = ctk.CTkLabel(self.plugin_details_frame, text="Selected Plugin Details:", font=ctk.CTkFont(weight="bold"), text_color=THEME_TEXT_COLOR)
        self.selected_plugin_name = ctk.CTkLabel(self.plugin_details_frame, text="Name: N/A", text_color=THEME_TEXT_COLOR)
        self.selected_plugin_key_len = ctk.CTkLabel(self.plugin_details_frame, text="Key Length: N/A", text_color=THEME_TEXT_COLOR)
        self.selected_plugin_nonce_len = ctk.CTkLabel(self.plugin_details_frame, text="Nonce/IV Length: N/A", text_color=THEME_TEXT_COLOR)
        self.selected_plugin_mode = ctk.CTkLabel(self.plugin_details_frame, text="Cipher Mode: N/A", text_color=THEME_TEXT_COLOR)
        self.selected_plugin_padding = ctk.CTkLabel(self.plugin_details_frame, text="Padding: N/A", text_color=THEME_TEXT_COLOR)

        # Log Textbox
        self.log_textbox = ctk.CTkTextbox(self, height=100, state="disabled",
                                          fg_color=THEME_WIDGET_BG, text_color=THEME_TEXT_COLOR,
                                          border_color=THEME_WIDGET_BORDER, corner_radius=8)
        self.log_textbox.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
        self.log_callback.set_textbox(self.log_textbox) # Link the log callback to this textbox

    def update_expert_mode_ui(self):
        is_expert = self.app_settings.get("expert_mode", False)
        row_offset = 0

        if is_expert:
            self.plugin_details_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
            self.selected_plugin_label.grid(row=0, column=0, columnspan=2, sticky="w", padx=5, pady=5)
            self.selected_plugin_name.grid(row=1, column=0, sticky="w", padx=10)
            self.selected_plugin_key_len.grid(row=2, column=0, sticky="w", padx=10)
            self.selected_plugin_nonce_len.grid(row=3, column=0, sticky="w", padx=10)
            self.selected_plugin_mode.grid(row=4, column=0, sticky="w", padx=10)
            self.selected_plugin_padding.grid(row=5, column=0, sticky="w", padx=10)
            row_offset = 1 # Adds the plugin details frame

        else:
            self.plugin_details_frame.grid_forget()

        self.log_textbox.grid(row=3 + row_offset, column=0, padx=10, pady=10, sticky="nsew")
        self.load_plugin_list() # Reload list to add click functionality for details

    def load_plugin_list(self):
        for widget in self.plugin_list_frame.winfo_children():
            widget.destroy()

        plugins = self.plugin_manager.encryption_plugins # Get actual plugin objects
        if plugins:
            for i, (plugin_name, plugin_obj) in enumerate(plugins.items()):
                plugin_label = ctk.CTkLabel(self.plugin_list_frame, text=f"- {plugin_name}", font=ctk.CTkFont(size=14),
                                            text_color=THEME_TEXT_COLOR)
                plugin_label.grid(row=i, column=0, padx=5, pady=2, sticky="w")
                # Add click event to show details if expert mode is on
                if self.app_settings.get("expert_mode", False):
                    plugin_label.bind("<Button-1>", lambda event, p=plugin_obj: self.display_plugin_details(p))
                    plugin_label.configure(cursor="hand2") # Indicate clickable

        else:
            no_plugins_label = ctk.CTkLabel(self.plugin_list_frame, text=loc.get_string("no_plugins_found"),
                                            font=ctk.CTkFont(size=14, slant="italic"), text_color=THEME_TEXT_COLOR)
            no_plugins_label.grid(row=0, column=0, padx=5, pady=10, sticky="w")

    def display_plugin_details(self, plugin_obj):
        self.selected_plugin_name.configure(text=f"{loc.get_string('name')} {plugin_obj.name}")
        self.selected_plugin_key_len.configure(text=f"{loc.get_string('key_length')} {getattr(plugin_obj, 'key_length', 'N/A')}")
        self.selected_plugin_nonce_len.configure(text=f"{loc.get_string('nonce_iv_length')} {getattr(plugin_obj, 'nonce_length', 'N/A')}")
        self.selected_plugin_mode.configure(text=f"{loc.get_string('cipher_mode')} {getattr(plugin_obj, 'cipher_mode', 'N/A')}")
        self.selected_plugin_padding.configure(text=f"{loc.get_string('padding')} {getattr(plugin_obj, 'padding_scheme', 'N/A')}")
        self.log_callback.log(loc.get_string("displayed_details_for_plugin", plugin_name=plugin_obj.name))


    def reload_plugins(self):
        self.log_callback.log(loc.get_string("reloading_plugins"))
        self.plugin_manager.load_plugins()
        self.load_plugin_list()
        self.master.master.update_plugin_dropdowns() # Inform other tabs to update their plugin dropdowns
        self.log_callback.log(loc.get_string("plugins_reloaded"))
        messagebox.showinfo(loc.get_string("plugins_tab_title"), loc.get_string("plugins_reloaded_success"))


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


# --- Splash Screen ---
class SplashScreen(ctk.CTkToplevel):
    def __init__(self, parent, icon_path):
        super().__init__(parent)
        self.parent = parent
        self.overrideredirect(True) # Remove window decorations
        self.geometry("400x300")
        self.configure(fg_color=THEME_BG_DARK, border_width=2, border_color=THEME_ACCENT_BLUE)

        # Center the splash screen on the screen
        self.update_idletasks() # Ensure window dimensions are calculated
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width // 2) - (self.winfo_width() // 2)
        y = (screen_height // 2) - (self.winfo_height() // 2)
        self.geometry(f"+{x}+{y}")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)

        # Load and display icon
        if os.path.exists(icon_path):
            try:
                # Use CTkImage for HighDPI compatibility
                image = Image.open(icon_path)
                # For CTkImage, it's often better to create it once at the desired size
                # and let CTkinter handle scaling.
                self.icon_ctk_image = ctk.CTkImage(light_image=image, dark_image=image, size=(128, 128))
                self.icon_label = ctk.CTkLabel(self, image=self.icon_ctk_image, text="")
                self.icon_label.grid(row=0, column=0, pady=(30, 10), sticky="s")
            except Exception as e:
                logging.error(f"Failed to load splash screen icon: {e}")
                self.icon_label = ctk.CTkLabel(self, text="Icon Error", text_color=THEME_ERROR_RED)
                self.icon_label.grid(row=0, column=0, pady=(30, 10), sticky="s")
        else:
            self.icon_label = ctk.CTkLabel(self, text="Icon Not Found", text_color=THEME_ERROR_RED)
            self.icon_label.grid(row=0, column=0, pady=(30, 10), sticky="s")

        self.title_label = ctk.CTkLabel(self, text=loc.get_string("app_name"), font=ctk.CTkFont(size=28, weight="bold"), text_color=THEME_ACCENT_BLUE)
        self.title_label.grid(row=1, column=0, pady=(0, 5), sticky="n")

        self.loading_label = ctk.CTkLabel(self, text=loc.get_string("splash_screen_loading"), font=ctk.CTkFont(size=14), text_color=THEME_TEXT_COLOR)
        self.loading_label.grid(row=2, column=0, pady=(0, 20), sticky="n")

        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal",
                                               fg_color=THEME_WIDGET_BG, progress_color=THEME_ACCENT_BLUE,
                                               corner_radius=8)
        self.progress_bar.grid(row=3, column=0, padx=50, pady=(0, 30), sticky="ew")
        self.progress_bar.set(0)

        # Simulate loading progress
        self.progress_value = 0
        self.update_progress()

    def update_progress(self):
        if self.progress_value < 1:
            self.progress_value += 0.05
            self.progress_bar.set(self.progress_value)
            self.after(50, self.update_progress)
        else:
            self.destroy() # Close splash screen when done

# --- Main Application Class ---
class SatanEncryptorSuite(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Initial hidden window for splash screen positioning
        self.withdraw()
        self.update_idletasks() # Ensure window dimensions are calculated

        self.title(APP_NAME)
        self.geometry("900x700")
        self.minsize(700, 600) # Minimum size
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Settings file path now uses the dynamically determined APP_SPECIFIC_DIR
        self.settings_file = SETTINGS_FILE
        self.app_settings = self.load_settings()

        # Apply initial theme and log level
        ctk.set_appearance_mode(self.app_settings.get("theme", "Dark"))
        ctk.set_default_color_theme("blue") # A good dark theme base
        logging.getLogger().setLevel(getattr(logging, self.app_settings.get("log_level", "INFO")))

        # Customizing colors for a "professional" feel
        self.configure(fg_color=THEME_BG_DARK) # Main window background

        # Show splash screen
        self.splash_screen = SplashScreen(self, os.path.join(ASSETS_DIR, ICON_FILENAME))
        self.splash_screen.grab_set() # Make splash screen modal
        self.splash_screen.wait_window(self.splash_screen) # Wait for splash screen to close

        # Initialize plugin manager
        self.plugin_manager = PluginManager()

        # Initialize UI Log Handler
        self.ui_log_handler = UILogHandler(self)
        logging.getLogger().addHandler(self.ui_log_handler)

        if self.app_settings.get("auto_clear_logs", False):
            self.clear_log_file()

        self.set_window_icon() # Call the method to set the icon
        self.create_widgets()
        
        # Deiconify and bring to front after a short delay to ensure splash screen is fully gone
        self.after(100, self.show_main_window) # Delay showing the main window

    def show_main_window(self):
        self.deiconify() # Show the main window
        self.lift() # Bring to front
        self.focus_force() # Give focus
        self.ui_log_handler.log(loc.get_string("app_started", app_name=APP_NAME, app_version=APP_VERSION), level="info")


    def create_widgets(self):
        # Destroy existing tabs if re-localizing
        if hasattr(self, 'tab_view'):
            for tab_name in self.tab_view.winfo_children():
                tab_name.destroy()
            self.tab_view.destroy()

        self.tab_view = ctk.CTkTabview(self, width=800, height=600,
                                       segmented_button_fg_color=THEME_WIDGET_BG,
                                       segmented_button_selected_color=THEME_ACCENT_BLUE,
                                       segmented_button_selected_hover_color=THEME_ACCENT_BLUE_HOVER,
                                       segmented_button_unselected_color=THEME_BG_DARK,
                                       segmented_button_unselected_hover_color=THEME_WIDGET_BG,
                                       text_color=THEME_TEXT_COLOR,
                                       corner_radius=15)

        self.tab_view.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        # Create tabs
        self.encrypt_tab = self.tab_view.add(loc.get_string("encrypt_tab"))
        self.decrypt_tab = self.tab_view.add(loc.get_string("decrypt_tab"))
        self.generate_keys_tab = self.tab_view.add(loc.get_string("generate_keys_tab"))
        self.settings_tab = self.tab_view.add(loc.get_string("settings_tab"))
        self.about_tab = self.tab_view.add(loc.get_string("about_tab"))
        self.plugins_tab = self.tab_view.add(loc.get_string("plugins_tab"))

        # Set background color for tab frames
        self.encrypt_tab.configure(fg_color=THEME_BG_DARK)
        self.decrypt_tab.configure(fg_color=THEME_BG_DARK)
        self.generate_keys_tab.configure(fg_color=THEME_BG_DARK)
        self.settings_tab.configure(fg_color=THEME_BG_DARK)
        self.about_tab.configure(fg_color=THEME_BG_DARK)
        self.plugins_tab.configure(fg_color=THEME_BG_DARK)


        # Add content to each tab
        self.encrypt_frame = EncryptTab(self.encrypt_tab, self.plugin_manager, self.app_settings, self.ui_log_handler,
                                        fg_color=THEME_BG_DARK, corner_radius=10)
        self.encrypt_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.encrypt_tab.grid_columnconfigure(0, weight=1)
        self.encrypt_tab.grid_rowconfigure(0, weight=1)

        self.decrypt_frame = DecryptTab(self.decrypt_tab, self.plugin_manager, self.app_settings, self.ui_log_handler,
                                        fg_color=THEME_BG_DARK, corner_radius=10)
        self.decrypt_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.decrypt_tab.grid_columnconfigure(0, weight=1)
        self.decrypt_tab.grid_rowconfigure(0, weight=1)

        self.generate_keys_frame = GenerateKeysTab(self.generate_keys_tab, self.plugin_manager, self.ui_log_handler, self.app_settings,
                                                   fg_color=THEME_BG_DARK, corner_radius=10)
        self.generate_keys_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.generate_keys_tab.grid_columnconfigure(0, weight=1)
        self.generate_keys_tab.grid_rowconfigure(0, weight=1)

        self.settings_frame = SettingsTab(self.settings_tab, self.app_settings, self.ui_log_handler, self, # Pass self reference
                                          fg_color=THEME_BG_DARK, corner_radius=10)
        self.settings_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.settings_tab.grid_columnconfigure(0, weight=1)
        self.settings_tab.grid_rowconfigure(0, weight=1)

        self.about_frame = AboutTab(self.about_tab, self.ui_log_handler,
                                    fg_color=THEME_BG_DARK, corner_radius=10)
        self.about_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.about_tab.grid_columnconfigure(0, weight=1)
        self.about_tab.grid_rowconfigure(0, weight=1)

        self.plugins_frame = PluginsTab(self.plugins_tab, self.plugin_manager, self.ui_log_handler, self.app_settings,
                                        fg_color=THEME_BG_DARK, corner_radius=10)
        self.plugins_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.plugins_tab.grid_columnconfigure(0, weight=1)
        self.plugins_tab.grid_rowconfigure(0, weight=1)

        # Initial log message (moved to show_main_window)
        # self.ui_log_handler.log(loc.get_string("app_started", app_name=APP_NAME, app_version=APP_VERSION), level="info")

    def set_window_icon(self):
        """Sets the window icon using PIL (Pillow) and CTkImage for HighDPI support."""
        icon_path = os.path.join(ASSETS_DIR, ICON_FILENAME)
        if os.path.exists(icon_path):
            try:
                # Load PIL Image
                pil_image = Image.open(icon_path)
                # Create ImageTk.PhotoImage from PIL Image for wm_iconphoto
                tk_photo_image = ImageTk.PhotoImage(pil_image)
                # Keep a reference to prevent garbage collection
                self._icon_tk_image = tk_photo_image
                self.wm_iconphoto(True, tk_photo_image)
                self.ui_log_handler.log(loc.get_string("window_icon_loaded", path=icon_path))
            except Exception as e:
                self.ui_log_handler.log(loc.get_string("failed_load_icon", path=icon_path, error=e), level="error")
        else:
            self.ui_log_handler.log(loc.get_string("icon_not_found", path=icon_path), level="warning")

    def update_plugin_dropdowns(self):
        """Called to update plugin lists in relevant tabs after plugin reload."""
        self.encrypt_frame.update_plugin_options()
        self.decrypt_frame.update_plugin_options()
        self.generate_keys_frame.update_plugin_options()

    def update_all_tab_expert_mode_ui(self):
        """Triggers UI updates on all tabs when expert mode changes."""
        self.encrypt_frame.update_expert_mode_ui()
        self.decrypt_frame.update_expert_mode_ui()
        self.generate_keys_frame.update_expert_mode_ui()
        self.plugins_frame.update_expert_mode_ui() # Plugins tab also has expert mode UI

    def relocalize_all_tabs(self):
        """Re-localizes all UI elements across all tabs."""
        # Destroy and recreate all tab frames to apply new language strings
        self.create_widgets()
        # After recreating, ensure the current tab is the one user was on, or default
        # (This part is complex as tab_view.get() might return old name if not immediately updated)
        # For simplicity, we'll just set it to the first tab.
        self.tab_view.set(loc.get_string("encrypt_tab"))
        # Also re-localize individual frames
        self.encrypt_frame.localize_ui()
        self.decrypt_frame.localize_ui()
        self.generate_keys_frame.localize_ui()
        self.settings_frame.localize_ui()
        self.about_frame.localize_ui()
        self.plugins_frame.localize_ui()


    def load_settings(self):
        """Loads application settings from a JSON file."""
        # Ensure the settings directory exists before trying to read the file
        os.makedirs(SETTINGS_DIR, exist_ok=True)
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                return settings
            except json.JSONDecodeError:
                logging.error("Error decoding settings.json. Using default settings.")
                return {"language": "en"} # Default language if settings file is corrupt
            except Exception as e:
                logging.error(f"Error loading settings: {e}. Using default settings.")
                return {"language": "en"} # Default language if settings file has other issues
        return {"language": "en"} # Default language if no settings file exists

    def save_settings(self):
        """Saves current application settings to a JSON file."""
        # Ensure the settings directory exists before trying to write the file
        os.makedirs(SETTINGS_DIR, exist_ok=True)
        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(self.app_settings, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save settings: {e}")

    def clear_log_file(self):
        """Clears the log file if auto-clear is enabled."""
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'w', encoding='utf-8') as f:
                    f.truncate(0)
                logging.info("Log file cleared on startup.")
        except Exception as e:
            logging.error(f"Failed to clear log file: {e}")

    def on_closing(self):
        """Handles actions when the application is closing."""
        self.save_settings()
        logging.info(loc.get_string("app_closed", app_name=APP_NAME))
        self.destroy()

if __name__ == "__main__":
    # Ensure necessary directories exist
    # These are now defined relative to the application's executable location for assets and plugins
    # but application data (logs, settings, languages) are in user-writable paths.
    # The PLUGINS_DIR is expected to be populated by the installer, not created/written by the app at runtime.
    if not os.path.exists(ASSETS_DIR):
        os.makedirs(ASSETS_DIR, exist_ok=True)
    # The PLUGINS_DIR is NOT created here by the app, it's expected to be installed by NSIS.
    # If it's missing, PluginManager.load_plugins() will log a warning.

    # Initialize LocalizationManager. It will now hardcode English first,
    # then attempt to load from files, making it more robust.
    # The 'loc' object is created globally at the top of the script.

    app = SatanEncryptorSuite()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
