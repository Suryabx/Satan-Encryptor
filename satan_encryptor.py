import sys
import os
import json
import argparse
import logging
import importlib.util
import time
from base64 import b64encode, b64decode
import hashlib
import webbrowser
from datetime import datetime
import shutil
import gzip
import bz2
import lzma
from logging.handlers import RotatingFileHandler

# --- PyQt6 Imports ---
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QCheckBox, QProgressBar,
    QTextEdit, QFileDialog, QMessageBox, QScrollArea, QFrame, QRadioButton,
    QListWidget, QListWidgetItem, QStatusBar, QHBoxLayout, QSizePolicy,
    QHeaderView, QTableWidget, QTableWidgetItem, QMenu, QSlider, QButtonGroup,
    QToolButton, QLayout
)
from PyQt6.QtGui import QPixmap, QIcon, QFont, QPalette, QColor, QMovie, QGuiApplication, QTextCharFormat, QTextCursor, QBrush, QAction, QImage
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer, QDir, QPropertyAnimation, QEasingCurve, QSize

# --- Cryptography Imports ---
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

# --- Configuration and Global Settings ---
APP_NAME = "Satan Encryptor Suite"
APP_VERSION = "2.1.1"
DEVELOPER_NAME = "Surya B, Abishek Raj PR "
DEVELOPER_EMAIL = "myselfsuryaaz@gmail.com"
GITHUB_URL = "https://github.com/Suryabx"
PLUGINS_DIR = "plugins"
ASSETS_DIR = "assets"
ICON_FILENAME = "icon.png"
SATAN_LOGO_FILENAME = "satan_logo.png"

# --- OS-Specific Directory Setup ---
if sys.platform == "win32":
    APP_DATA_BASE_DIR = os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local"))
elif sys.platform == "darwin":
    APP_DATA_BASE_DIR = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
else:
    APP_DATA_BASE_DIR = os.environ.get("XDG_DATA_HOME", os.path.join(os.path.expanduser("~"), ".local", "share"))

APP_SPECIFIC_DIR = os.path.join(APP_DATA_BASE_DIR, APP_NAME)
LOG_DIR = os.path.join(APP_SPECIFIC_DIR, "logs")
SETTINGS_DIR = APP_SPECIFIC_DIR
LANGUAGES_DIR = os.path.join(APP_SPECIFIC_DIR, "languages")
KEYS_DIR = os.path.join(APP_SPECIFIC_DIR, "keys")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "satan_encryptor_suite.log")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")
KEY_STORE_FILE = os.path.join(KEYS_DIR, "key_store.json")

# --- Logging Setup ---
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
    logger.addHandler(console_handler)

# --- CORRECTED: High-end Black and White Theme (Fixed box-shadow, adjusted colors) ---
THEME_ERROR_RED = "#D04141"
THEME_WARNING_ORANGE = "#D08770"
THEME_SUCCESS_GREEN = "#A3BE8C"

# Common QComboBox dropdown arrow styling (SVG for modern look)
COMBOBOX_ARROW_SVG_BASE = """
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-chevron-down"><path d="m6 9 6 6 6-6"/></svg>
"""
# SVG for chevron up (for collapsible sections)
CHEVRON_UP_SVG_BASE = """
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-chevron-up"><path d="m18 15-6-6-6 6"/></svg>
"""
# SVG for menu icon (dots)
MENU_ICON_SVG_BASE = """
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" class="lucide lucide-ellipsis-vertical"><circle cx="12" cy="12" r="1"/><circle cx="12" cy="5" r="1"/><circle cx="12" cy="19" r="1"/></svg>
"""
# SVG for sidebar open/close icon
SIDEBAR_TOGGLE_SVG_BASE = """
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-menu"><line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="18" y2="18"/></svg>
"""
# Github logo SVG
GITHUB_SVG_BASE = """
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" class="lucide lucide-github"><path d="M15 22v-4.129a3.344 3.344 0 0 0-1.077-.923c-3.14-.84-5.467-3.21-5.467-6.027 0-1.332.613-2.58 1.63-3.48a6.002 6.002 0 0 0-.251-3.447s.823-.264 2.704.996a11.168 11.168 0 0 1 5.378 0c1.881-1.26 2.704-.996 2.704-.996a6.002 6.002 0 0 0-.251 3.447c1.017.9 1.63 2.148 1.63 3.48 0 2.817-2.327 5.187-5.467 6.027-.393.105-.758.33-.923.639v4.129H15zM7.25 15.25v-1.5a.75.75 0 0 1 .75-.75h1.5a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-.75.75h-1.5a.75.75 0 0 1-.75-.75zM15 15.25v-1.5a.75.75 0 0 1 .75-.75h1.5a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-.75.75h-1.5a.75.75 0 0 1-.75-.75z"/></svg>
"""
# Mail icon SVG
MAIL_SVG_BASE = """
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-mail"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
"""


# Base64 encode the SVGs once with respective colors
COMBOBOX_ARROW_SVG = b64encode(COMBOBOX_ARROW_SVG_BASE.replace('currentColor', '#757575').encode()).decode()
CHEVRON_UP_SVG = b64encode(CHEVRON_UP_SVG_BASE.replace('currentColor', '#757575').encode()).decode()
MENU_ICON_SVG = b64encode(MENU_ICON_SVG_BASE.replace('currentColor', '#495057').encode()).decode()
SIDEBAR_TOGGLE_SVG = b64encode(SIDEBAR_TOGGLE_SVG_BASE.replace('currentColor', '#FFFFFF').encode()).decode()
GITHUB_SVG = b64encode(GITHUB_SVG_BASE.replace('currentColor', '#495057').encode()).decode()
MAIL_SVG = b64encode(MAIL_SVG_BASE.replace('currentColor', '#495057').encode()).decode()


BLACK_AND_WHITE_STYLESHEET = f"""
    QWidget {{
        background-color: #F8F9FA;
        color: #212529;
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: 10.5pt;
        border: none;
    }}
    QMainWindow {{
        background-color: #F8F9FA;
        border: 1px solid #E9ECEF;
        border-radius: 12px;
    }}
    QTabWidget::pane {{
        border: 1px solid #E9ECEF;
        border-radius: 10px;
        background-color: #FFFFFF;
    }}
    QTabBar::tab {{
        background: #E9ECEF;
        color: #495057;
        padding: 12px 22px;
        border-top-left-radius: 10px;
        border-top-right-radius: 10px;
        border: 1px solid #DEE2E6;
        margin-right: 3px;
        min-width: 80px;
        border-bottom-color: #E9ECEF;
    }}
    QTabBar::tab:selected {{
        background: #FFFFFF;
        color: #212529;
        border-bottom-color: #FFFFFF;
        font-weight: bold;
    }}
    QTabBar::tab:hover {{
        background: #DEE2E6;
    }}
    QPushButton {{
        background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 #FFFFFF, stop: 1 #F0F0F0);
        color: #212529;
        border: 1px solid #DEE2E6;
        padding: 10px 20px;
        border-radius: 10px;
        font-weight: bold;
    }}
    QPushButton:hover {{
        background-color: #E9ECEF;
    }}
    QPushButton:pressed {{
        background-color: #DEE2E6;
    }}
    QPushButton:disabled {{
        background-color: #F8F9FA;
        color: #ADB5BD;
        border: 1px solid #E9ECEF;
    }}
    QLineEdit, QTextEdit, QListWidget, QTableWidget, QSlider {{
        background-color: #FFFFFF;
        border: 1px solid #DEE2E6;
        border-radius: 8px;
        padding: 8px;
    }}
    QLineEdit:focus, QTextEdit:focus, QListWidget:focus, QTableWidget:focus, QSlider:focus {{
        border: 2px solid #ADB5BD;
    }}
    QComboBox {{
        background-color: #FFFFFF;
        border: 1px solid #DEE2E6;
        border-radius: 8px;
        padding: 8px;
        padding-right: 30px;
    }}
    QComboBox:focus {{
        border: 2px solid #ADB5BD;
    }}
    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 30px;
        border-left-width: 1px;
        border-left-color: #DEE2E6;
        border-left-style: solid;
        border-top-right-radius: 7px;
        border-bottom-right-radius: 7px;
    }}
    QComboBox::down-arrow {{
        image: url(data:image/svg+xml;base64,{COMBOBOX_ARROW_SVG});
        width: 24px;
        height: 24px;
        padding-right: 5px;
    }}
    QCheckBox::indicator {{
        border: 1px solid #DEE2E6;
        border-radius: 4px;
        background-color: #FFFFFF;
        width: 16px;
        height: 16px;
    }}
    QCheckBox::indicator:checked {{
        background-color: #495057;
        border: 1px solid #495057;
    }}
    QRadioButton::indicator {{
        width: 14px;
        height: 14px;
        border-radius: 7px;
        border: 1px solid #DEE2E6;
        background-color: #FFFFFF;
    }}
    QRadioButton::indicator:checked {{
        background-color: #495057;
        border: 1px solid #495057;
    }}
    QLabel#TitleLabel {{
        font-size: 18pt;
        font-weight: bold;
        color: #212529;
    }}
    QLabel#SectionLabel {{
        font-size: 12pt;
        font-weight: bold;
        color: #495057;
        margin-top: 15px;
        margin-bottom: 5px;
    }}
    QFrame#SectionFrame {{
        border: 1px solid #DEE2E6;
        border-radius: 10px;
    }}
    QProgressBar {{
        border: 1px solid #DEE2E6;
        border-radius: 10px;
        text-align: center;
        background-color: #E9ECEF;
        color: #495057;
        height: 25px;
    }}
    QProgressBar::chunk {{
        background-color: #ADB5BD;
        border-radius: 9px;
    }}
    QStatusBar {{
        background-color: #E9ECEF;
        color: #495057;
        border-top: 1px solid #DEE2E6;
    }}
    QTableWidget {{
        gridline-color: #DEE2E6;
        border: 1px solid #DEE2E6;
        border-radius: 8px;
    }}
    QTableWidget::item {{
        padding: 5px;
    }}
    QTableWidget::item:selected {{
        background-color: #DEE2E6;
        color: #212529;
    }}
    QHeaderView::section {{
        background-color: #E9ECEF;
        color: #495057;
        padding: 8px;
        border: 1px solid #DEE2E6;
        border-radius: 4px;
        font-weight: bold;
    }}
    QMenu {{
        background-color: #FFFFFF;
        border: 1px solid #DEE2E6;
        border-radius: 6px;
    }}
    QMenu::item {{
        padding: 8px 18px;
        color: #212529;
    }}
    QMenu::item:selected {{
        background-color: #E9ECEF;
    }}
    QSlider::groove:horizontal {{
        border: 1px solid #DEE2E6;
        height: 10px;
        background: #E9ECEF;
        margin: 2px 0;
        border-radius: 5px;
    }}
    QSlider::handle:horizontal {{
        background: #ADB5BD;
        border: 1px solid #ADB5BD;
        width: 20px;
        margin: -5px 0;
        border-radius: 10px;
    }}
    QToolButton#WhatsNewToggle {{
        border: none;
        background: transparent;
        padding: 5px;
        min-width: 30px;
        min-height: 30px;
        border-radius: 15px;
    }}
    QToolButton#WhatsNewToggle:hover {{
        background-color: #E0E0E0;
    }}
    QToolButton#WhatsNewToggle::down-arrow {{
        image: url(data:image/svg+xml;base64,{COMBOBOX_ARROW_SVG});
        width: 24px;
        height: 24px;
    }}
    QToolButton#WhatsNewToggle::up-arrow {{
        image: url(data:image/svg+xml;base64,{CHEVRON_UP_SVG});
        width: 24px;
        height: 24px;
    }}
    /* --- Main App Header Styles --- */
    #HeaderWidget {{
        background-color: #FFFFFF;
        border-bottom: 1px solid #DEE2E6;
    }}
    #HeaderTitle {{
        font-size: 18pt;
        font-weight: bold;
        color: #212529;
    }}
    #SidebarToggleButton {{
        background-color: #495057;
        border: none;
        border-radius: 10px;
        padding: 8px;
    }}
    #SidebarToggleButton:hover {{
        background-color: #6c757d;
    }}
    /* --- Main Content Area Styles --- */
    #MainContentArea {{
        background-color: #F8F9FA;
    }}
    /* --- Sidebar Styles --- */
    #SidebarWidget {{
        background-color: #E9ECEF;
        border-right: 1px solid #DEE2E6;
        padding: 20px;
    }}
    #SidebarHeader {{
        font-size: 16pt;
        font-weight: bold;
        color: #212529;
        margin-bottom: 20px;
    }}
    #SidebarButton {{
        background-color: transparent;
        color: #495057;
        border: none;
        padding: 12px 15px;
        text-align: left;
        border-radius: 8px;
        font-weight: bold;
    }}
    #SidebarButton:hover {{
        background-color: #DEE2E6;
    }}
    #SidebarButton:checked {{
        background-color: #ADB5BD;
        color: white;
    }}
    #SidebarButton:selected {{
        background-color: #495057;
        color: white;
    }}
    /* --- About Tab specific styles --- */
    #AboutTabLogo {{
        background-color: transparent;
        margin-bottom: 20px;
    }}
    #AboutTabName {{
        font-size: 24pt;
        font-weight: bold;
        color: #212529;
    }}
    #AboutTabInfo {{
        font-size: 12pt;
        color: #495057;
    }}
    #AboutTabLink {{
        color: #495057;
        text-decoration: none;
    }}
    #AboutTabLink:hover {{
        text-decoration: underline;
    }}
    #AboutTabContactButton {{
        background-color: #E9ECEF;
        border: 1px solid #DEE2E6;
        padding: 8px 16px;
        border-radius: 8px;
    }}
"""


# --- NEW FEATURE 1: Drag and Drop File/Folder Support ---
class DragDropLineEdit(QLineEdit):
    fileDropped = pyqtSignal(str)
    folderDropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        if urls := event.mimeData().urls():
            path = urls[0].toLocalFile()
            self.setText(path)
            if os.path.isdir(path):
                self.folderDropped.emit(path)
            else:
                self.fileDropped.emit(path)

# --- Localization Manager (Restored and Enhanced) ---
class LocalizationManager:
    def __init__(self):
        self.current_language = "en"
        self.translations = {}
        self._default_english_translations = {
            "app_name": "Satan Encryptor Suite", "encrypt_tab": "Encrypt", "decrypt_tab": "Decrypt",
            "generate_keys_tab": "Generate Keys", "settings_tab": "Settings", "about_tab": "About",
            "plugins_tab": "Plugins", "input_file_folder": "Input File/Folder:",
            "select_file_folder_encrypt": "Select file or folder to encrypt", "output_folder": "Output Folder:",
            "select_output_folder": "Select output folder", "encryption_algorithm": "Encryption Algorithm:",
            "no_plugins_loaded": "No Plugins Loaded", "key_len": "Key Len:", "nonce_iv_len": "Nonce/IV Len:",
            "mode": "Mode:", "padding": "Padding:", "key_type": "Key Type:",
            "password_derive_key": "Password (Derive Key)", "direct_key_base64_pem": "Direct Key (Base64/PEM)",
            "enter_password_derivation": "Enter password for key derivation", "password": "Password:",
            "direct_key": "Direct Key:", "show_input": "Show Input", "password_strength": "Password Strength: ",
            "weak": "Weak", "medium": "Medium", "strong": "Strong", "kdf_iterations": "KDF Iterations:",
            "output_suffix": "Output Suffix:", "delete_original_after_encrypt": "Delete Original After Encrypt",
            "encrypt_files": "Encrypt File(s)", "decrypt_files": "Decrypt File(s)",
            "input_encrypted_file_folder": "Input Encrypted File/Folder:",
            "select_encrypted_file_folder": "Select encrypted file or folder", "decryption_algorithm": "Decryption Algorithm:",
            "input_salt": "Input Salt:", "input_nonce_iv": "Input Nonce/IV:",
            "algorithm_key_generation": "Algorithm for Key Generation:", "key_length_bits_rsa": "Key Length (bits, for RSA):",
            "output_format": "Output Format:", "base64_url_safe": "Base64 (URL-safe)", "hex": "Hex",
            "pem_rsa_only": "PEM (RSA Only)", "generate_keys": "Generate Key(s)", "generated_keys": "Generated Key(s):",
            "copy_keys_clipboard": "Copy Key(s) to Clipboard", "theme": "Theme:",
            "system": "System", "auto_clear_logs_startup": "Auto-clear logs on startup",
            "confirm_overwrite_files": "Confirm before overwriting files", "enable_expert_mode": "Enable Expert Mode (More Options)",
            "log_level": "Log Level:", "file_chunk_size_kb": "File Chunk Size (KB):", "language_wip": "Language:",
            "export_settings": "Export Settings", "import_settings": "Import Settings",
            "loaded_encryption_plugins": "Loaded Encryption Plugins", "reload_plugins": "Reload Plugins",
            "selected_plugin_details": "Selected Plugin Details:", "name": "Name:", "key_length": "Key Length:",
            "nonce_iv_length": "Nonce/IV Length:", "cipher_mode": "Cipher Mode:",
            "no_plugins_found": "No plugins found. Place .py files in the 'plugins' folder.", "view_github": "View GitHub",
            "license_proprietary": "License: Proprietary (See terms.txt)",
            "feedback_contact_github": "For feedback or contact, please visit the GitHub page.",
            "app_started": "{app_name} v{app_version} started.", "input_error": "Input Error",
            "all_fields_filled": "All fields must be filled.", "encryption_complete_title": "Encryption Complete",
            "encryption_complete": "{count} file(s) encrypted successfully!", "decryption_complete_title": "Decryption Complete",
            "decryption_complete": "{count} file(s) decrypted successfully!", "key_generation": "Key Generation",
            "key_generation_success": "{algo_name} key(s) generated successfully!", "key_generation_error_title": "Key Generation Error",
            "key_copied_clipboard": "Key(s) copied to clipboard!", "no_key_copy": "No key to copy.",
            "plugins_reloaded": "Plugins Reloaded", "plugins_reloaded_success": "Plugins reloaded successfully!",
            "app_closed": "{app_name} closed.", "browse": "Browse", "encrypting": "Encrypting...", "decrypting": "Decrypting...",
            "expert_mode_warning_title": "Expert Mode Enabled",
            "expert_mode_warning_message": "Expert Mode exposes advanced cryptographic options. Incorrect use may lead to data loss or insecure operations. Proceed with caution.",
            "version": "Version: ", "developed_by": "Developed by: ",
            "tooltip_input_file": "Select the file or folder to process. You can also drag and drop a file here.",
            "tooltip_output_folder": "Select the destination folder for the output files.",
            "tooltip_algorithm": "Choose the encryption or decryption algorithm.",
            "tooltip_key_type": "Choose between deriving a key from a password or using a direct key (Base64/PEM).",
            "tooltip_password": "Enter the password. Used to generate a secure encryption key.",
            "tooltip_direct_key": "Enter the key directly, usually in Base64 or PEM format.",
            "tooltip_iterations": "Number of rounds for password-based key derivation. Higher is more secure.",
            "tooltip_delete_original": "If checked, the original file will be deleted after a successful operation.",
            "tooltip_rsa_gen_password": "Optional. If provided, the generated RSA private key will be encrypted with this password.",
            "tooltip_save_key": "Save the generated key(s) to a file.",
            "plugins_enable_disable": "Enable or disable encryption plugins. Changes are saved automatically.",
            "save_public_key": "Save Public Key...", "save_private_key": "Save Private Key...",
            "key_saved_to": "Key saved to {path}", "file_save_error": "File Save Error",
            "no_key_to_save": "No key content to save.", "copied_to_clipboard": "Copied to clipboard!",
            "status_file_selected": "File selected: {path}", "status_metadata_found": "Metadata found. Algorithm set to {algo}.",
            "status_metadata_error": "Could not read metadata: {e}",
            "metadata_not_found": "Metadata file (.meta) not found. Manual configuration required.",
            "invalid_password_or_corrupt": "Decryption failed: Invalid password or corrupted file.",
            "file_processing_status": "Processing: {filename}", "waiting_for_op": "Waiting for operation...",
            "rsa_gen_password_label": "Key Password (optional):",
            "whats_new_tab": "What's New",
            "whats_new_title": "What's New in Version {version}",
            "whats_new_content": """
                <h3>Welcome to the new and improved Satan Encryptor Suite!</h3>
                <p>This version brings a host of new features and improvements:</p>
                <ul>
                    <li><b>Modern UI Overhaul:</b> A fresh, clean look with new colors, gradients, and styles for a better user experience.</li>
                    <li><b>Drag & Drop Support:</b> You can now drag files directly onto the input fields to select them instantly.</li>
                    <li><b>Automatic Metadata Files:</b> Encryption settings (like algorithm, salt, etc.) are now saved automatically with your files, making decryption much easier.</li>
                    <li><b>Enhanced Security:</b> Generate password-protected RSA keys to keep your private keys secure.</li>
                    <li><b>Plugin Management:</b> Easily enable or disable encryption algorithms from the new 'Plugins' tab.</li>
                    <li><b>Command-Line Interface (CLI):</b> Automate your encryption tasks by running the application from the command line.</li>
                    <li><b>Key File Support for Encryption/Decryption:</b> You can now use generated RSA public/private keys or symmetric keys directly from files for cryptographic operations.</li>
                    <li><b>Improved Key Management:</b> The Key Management tab now provides better tools to view, export, and delete your stored keys.</li>
                    <li><b>Refined UI/CSS:</b> The application's visual aesthetics have been further polished across all themes for a more modern and consistent look.</li>
                </ul>
                <p>Thank you for using the application!</p>
            """,
            # NEW STRINGS FOR NEW FEATURES
            "compression_algorithm": "Compression Algorithm:",
            "compression_level": "Compression Level:",
            "no_compression": "No Compression",
            "gzip": "Gzip", "bzip2": "Bzip2", "lzma": "LZMA",
            "secure_shredding_passes": "Secure Shredding Passes (0 for none):",
            "file_integrity_check": "File Integrity Check (SHA-256)",
            "log_viewer": "Log Viewer",
            "filter_by_level": "Filter by Level:",
            "search_logs": "Search Logs...",
            "export_logs": "Export Logs",
            "all_levels": "All Levels", "info": "INFO", "warning": "WARNING", "error": "ERROR",
            "log_exported_to": "Logs exported to {path}",
            "log_export_error": "Error exporting logs: {e}",
            "key_management_tab": "Key Management",
            "managed_keys": "Managed Keys:",
            "key_name": "Key Name", "key_type": "Type", "key_path": "Path", "key_actions": "Actions",
            "export_key": "Export Key", "delete_key": "Delete Key", "view_key": "View Key",
            "key_deleted": "Key '{name}' deleted.",
            "key_exported": "Key '{name}' exported to {path}",
            "confirm_delete_key": "Are you sure you want to delete key '{name}'? This action cannot be undone.",
            "key_view_title": "View Key: {name}",
            "key_load_error": "Error loading key: {e}",
            "checksum_mismatch": "Checksum mismatch for {filename}! File may be corrupted.",
            "checksum_verified": "Checksum verified for {filename}.",
            "file_shredding": "Securely shredding original file...",
            "shredding_complete": "Original file securely shredded.",
            "batch_processing_progress": "Overall Progress: {current}/{total} files ({percentage:.1f}%)",
            "file_processing_status_batch": "Processing file {current_file_index}/{total_files}: {filename}",
            "select_folder": "Select Folder",
            "operation_cancelled": "Operation cancelled by user.",
            "loading_app": "Loading Application...",
            "initializing_ui": "Initializing User Interface...",
            "loading_plugins": "Loading Encryption Plugins...",
            "preparing_key_manager": "Preparing Key Manager...",
            "finalizing_startup": "Finalizing Startup...",
            "font_selection": "Font Selection:",
            "animation_speed": "Animation Speed:",
            "log_file_settings": "Log File Settings",
            "max_log_size_mb": "Max Log Size (MB):",
            "enable_log_rotation": "Enable Log Rotation",
            "default_output_folder": "Default Output Folder:",
            "select_default_output_folder": "Select Default Output Folder",
            "default_encryption_algorithm": "Default Encryption Algorithm:",
            "confirm_on_exit": "Confirm on Exit",
            "contact_developer": "Contact Developer",
            "contact_email_label": "Contact Email:",
            "save_symmetric_key": "Save Symmetric Key...",
            "password_input_type": "Password Input Type:",
            "use_password": "Use Password",
            "use_key_file": "Use Key File",
            "key_file_path": "Key File Path:",
            "select_key_file": "Select Key File",
            "open_github": "Open GitHub"
        }
        self.translations["en"] = self._default_english_translations

    def get_string(self, key, **kwargs):
        return self.translations.get(self.current_language, self.translations["en"]).get(key, key).format(**kwargs)

loc = LocalizationManager()

# --- NEW: Secure File Shredding Utility ---
def secure_delete_file(filepath, passes=3):
    """
    Securely deletes a file by overwriting its content multiple times
    and then unlinking it.
    """
    if not os.path.exists(filepath):
        logger.warning(f"Attempted to shred non-existent file: {filepath}")
        return

    file_size = os.path.getsize(filepath)
    try:
        with open(filepath, 'r+b') as f:
            for i in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())

            f.seek(0)
            f.write(b'\0' * file_size)
            f.flush()
            os.fsync(f.fileno())

        os.remove(filepath)
        logger.info(f"Securely shredded file: {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error during secure file shredding of {filepath}: {e}")
        return False

# --- UPDATED: Plugin Management System ---
class PluginManager:
    def __init__(self, settings):
        self.encryption_plugins = {}
        self.settings = settings
        self.load_plugins()

    def load_plugins(self):
        self.encryption_plugins.clear()
        if not os.path.exists(PLUGINS_DIR):
            os.makedirs(PLUGINS_DIR)
            return
        for filename in os.listdir(PLUGINS_DIR):
            if filename.endswith(".py") and not filename.startswith("__"):
                try:
                    spec = importlib.util.spec_from_file_location(filename[:-3], os.path.join(PLUGINS_DIR, filename))
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[filename[:-3]] = module
                    spec.loader.exec_module(module)
                    if hasattr(module, 'EncryptorPlugin'):
                        plugin_instance = module.EncryptorPlugin()
                        self.encryption_plugins[plugin_instance.name] = plugin_instance
                        logger.info(f"Loaded plugin: {plugin_instance.name}")
                except Exception as e:
                    logger.error(f"Failed to load plugin '{filename}': {e}")

    def get_available_plugins(self):
        if "enabled_plugins" not in self.settings:
            self.settings["enabled_plugins"] = {name: True for name in self.encryption_plugins}

        enabled_plugins = self.settings.get("enabled_plugins", {})
        return [name for name, is_enabled in enabled_plugins.items() if is_enabled and name in self.encryption_plugins]

    def get_all_plugins(self):
        return self.encryption_plugins

    def set_plugin_status(self, name, is_enabled):
        enabled_plugins = self.settings.get("enabled_plugins", {})
        enabled_plugins[name] = is_enabled
        self.settings["enabled_plugins"] = enabled_plugins

# --- NEW: Key Management System ---
class KeyManager:
    def __init__(self):
        self.keys = self._load_keys()

    def _load_keys(self):
        if os.path.exists(KEY_STORE_FILE):
            try:
                with open(KEY_STORE_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load key store: {e}")
        return []

    def _save_keys(self):
        try:
            with open(KEY_STORE_FILE, 'w') as f:
                json.dump(self.keys, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save key store: {e}")

    def add_key(self, name, type, path):
        original_name = name
        counter = 1
        while any(key['name'] == name for key in self.keys):
            name = f"{original_name}_{counter}"
            counter += 1

        self.keys.append({"name": name, "type": type, "path": path, "added_on": datetime.now().isoformat()})
        self._save_keys()
        return name

    def get_keys(self):
        return self.keys

    def delete_key(self, name):
        original_len = len(self.keys)
        self.keys = [key for key in self.keys if key['name'] != name]
        if len(self.keys) < original_len:
            self._save_keys()
            return True
        return False

    def get_key_by_name(self, name):
        return next((key for key in self.keys if key['name'] == name), None)

# --- UPDATED: Worker for Threading ---
class Worker(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)
    file_progress = pyqtSignal(int, int, str)
    current_file_status = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs, self.is_cancelled = fn, args, kwargs, False

    def run(self):
        try:
            result = self.fn(self, *self.args, **self.kwargs)
            if not self.is_cancelled:
                self.finished.emit(result)
        except Exception as e:
            logger.error(f"Worker thread error: {e}", exc_info=True)
            if not self.is_cancelled:
                self.error.emit(str(e))

    def cancel(self):
        self.is_cancelled = True
        logger.info("Worker thread cancellation requested.")

# --- Base Tab Widget ---
class BaseTab(QWidget):
    def __init__(self, plugin_manager, app_settings, main_window):
        super().__init__()
        self.plugin_manager, self.app_settings, self.main_window = plugin_manager, app_settings, main_window
        self.layout = QGridLayout(self)
        self.setLayout(self.layout)

    def log(self, message, level="info"):
        self.main_window.log_signal.emit(message, level)

    def retranslate_ui(self):
        raise NotImplementedError

    def update_expert_mode_ui(self):
        pass

    def update_plugin_options(self):
        pass

# --- Compression Utilities ---
def compress_file(input_filepath, output_filepath, algorithm="gzip", level=-1):
    """Compresses a file using the specified algorithm."""
    try:
        if algorithm == "Gzip":
            with open(input_filepath, 'rb') as f_in:
                with gzip.open(output_filepath, 'wb', compresslevel=level if level != -1 else 9) as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif algorithm == "Bzip2":
            with open(input_filepath, 'rb') as f_in:
                with bz2.open(output_filepath, 'wb', compresslevel=level if level != -1 else 9) as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif algorithm == "LZMA":
            with open(input_filepath, 'rb') as f_in:
                with lzma.open(output_filepath, 'wb', preset=level if level != -1 else 6) as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            raise ValueError(f"Unsupported compression algorithm: {algorithm}")
        logger.info(f"Compressed {input_filepath} to {output_filepath} using {algorithm}")
        return True
    except Exception as e:
        logger.error(f"Error compressing file {input_filepath}: {e}")
        return False

def decompress_file(input_filepath, output_filepath, algorithm="gzip"):
    """Decompresses a file using the specified algorithm."""
    try:
        if algorithm == "Gzip":
            with gzip.open(input_filepath, 'rb') as f_in:
                with open(output_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif algorithm == "Bzip2":
            with bz2.open(input_filepath, 'rb') as f_in:
                with open(output_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif algorithm == "LZMA":
            with lzma.open(input_filepath, 'rb') as f_in:
                with open(output_filepath, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            raise ValueError(f"Unsupported decompression algorithm: {algorithm}")
        logger.info(f"Decompressed {input_filepath} to {output_filepath} using {algorithm}")
        return True
    except Exception as e:
        logger.error(f"Error decompressing file {input_filepath}: {e}")
        return False

# --- Encrypt/Decrypt Tabs (Restored and Enhanced) ---
class CryptoTab(BaseTab):
    def __init__(self, plugin_manager, app_settings, main_window, is_encrypt_mode):
        super().__init__(plugin_manager, app_settings, main_window)
        self.is_encrypt_mode = is_encrypt_mode
        self.setup_ui()
        self.connect_signals()
        self.update_plugin_options()
        self.update_expert_mode_ui()

    def setup_ui(self):
        self.input_path_entry = DragDropLineEdit()
        self.output_path_entry = DragDropLineEdit()
        self.browse_input_button = QPushButton(loc.get_string("browse"))
        self.browse_output_button = QPushButton(loc.get_string("browse"))
        self.algo_dropdown = QComboBox()

        self.key_input_type_label = QLabel(loc.get_string("password_input_type"))
        self.password_radio_button = QRadioButton(loc.get_string("use_password"))
        self.key_file_radio_button = QRadioButton(loc.get_string("use_key_file"))
        self.password_radio_button.setChecked(True)

        self.key_input_group = QButtonGroup(self)
        self.key_input_group.addButton(self.password_radio_button)
        self.key_input_group.addButton(self.key_file_radio_button)
        self.key_input_group.buttonToggled.connect(
            lambda button: self.toggle_key_input_method(button == self.password_radio_button)
        )

        self.password_label = QLabel(loc.get_string("password"))
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)

        self.key_file_label = QLabel(loc.get_string("key_file_path"))
        self.key_file_path_entry = DragDropLineEdit()
        self.key_file_path_entry.setReadOnly(True)
        self.browse_key_file_button = QPushButton(loc.get_string("browse"))
        self.browse_key_file_button.clicked.connect(self.browse_key_file)
        self.key_file_path_entry.fileDropped.connect(self.on_key_file_dropped)

        self.action_button = QPushButton()
        self.progress_bar = QProgressBar()
        self.file_status_label = QLabel(loc.get_string("waiting_for_op"))
        self.file_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.compression_algo_label = QLabel(loc.get_string("compression_algorithm"))
        self.compression_algo_dropdown = QComboBox()
        self.compression_algo_dropdown.addItems([loc.get_string("no_compression"), loc.get_string("gzip"), loc.get_string("bzip2"), loc.get_string("lzma")])
        self.compression_level_label = QLabel(loc.get_string("compression_level"))
        self.compression_level_entry = QLineEdit("-1")

        self.checksum_checkbox = QCheckBox(loc.get_string("file_integrity_check"))
        self.delete_original_checkbox = QCheckBox(loc.get_string("delete_original_after_encrypt"))
        self.secure_shredding_passes_label = QLabel(loc.get_string("secure_shredding_passes"))
        self.secure_shredding_passes_entry = QLineEdit("0")

        self.layout.addWidget(QLabel(loc.get_string("input_file_folder")), 0, 0)
        self.layout.addWidget(self.input_path_entry, 0, 1, 1, 2)
        self.layout.addWidget(self.browse_input_button, 0, 3)

        self.layout.addWidget(QLabel(loc.get_string("output_folder")), 1, 0)
        self.layout.addWidget(self.output_path_entry, 1, 1, 1, 2)
        self.layout.addWidget(self.browse_output_button, 1, 3)

        self.layout.addWidget(QLabel(loc.get_string("encryption_algorithm") if self.is_encrypt_mode else loc.get_string("decryption_algorithm")), 2, 0)
        self.layout.addWidget(self.algo_dropdown, 2, 1, 1, 3)

        key_input_method_layout = QHBoxLayout()
        key_input_method_layout.addWidget(self.key_input_type_label)
        key_input_method_layout.addWidget(self.password_radio_button)
        key_input_method_layout.addWidget(self.key_file_radio_button)
        key_input_method_layout.addStretch(1)

        self.layout.addLayout(key_input_method_layout, 3, 0, 1, 4)

        self.layout.addWidget(self.password_label, 4, 0)
        self.layout.addWidget(self.password_entry, 4, 1, 1, 3)

        self.layout.addWidget(self.key_file_label, 5, 0)
        self.layout.addWidget(self.key_file_path_entry, 5, 1, 1, 2)
        self.layout.addWidget(self.browse_key_file_button, 5, 3)

        row_offset = 6
        if self.is_encrypt_mode:
            self.layout.addWidget(self.compression_algo_label, row_offset, 0)
            self.layout.addWidget(self.compression_algo_dropdown, row_offset, 1)
            self.layout.addWidget(self.compression_level_label, row_offset, 2)
            self.layout.addWidget(self.compression_level_entry, row_offset, 3)
            row_offset += 1
            self.layout.addWidget(self.checksum_checkbox, row_offset, 0, 1, 2)
            self.layout.addWidget(self.delete_original_checkbox, row_offset, 2, 1, 2)
            row_offset += 1
            self.layout.addWidget(self.secure_shredding_passes_label, row_offset, 0)
            self.layout.addWidget(self.secure_shredding_passes_entry, row_offset, 1)
            row_offset += 1

        self.layout.addWidget(self.action_button, row_offset, 0, 1, 4)
        row_offset += 1
        self.layout.addWidget(self.progress_bar, row_offset, 0, 1, 4)
        row_offset += 1
        self.layout.addWidget(self.file_status_label, row_offset, 0, 1, 4)
        self.layout.setRowStretch(row_offset + 1, 1)

        self.toggle_key_input_method(self.password_radio_button.isChecked())


    def connect_signals(self):
        self.input_path_entry.fileDropped.connect(self.on_file_dropped)
        self.input_path_entry.folderDropped.connect(self.on_folder_dropped)
        self.browse_input_button.clicked.connect(self.browse_input)
        self.browse_output_button.clicked.connect(self.browse_output)
        self.action_button.clicked.connect(self.start_operation)
        self.delete_original_checkbox.stateChanged.connect(self.toggle_shredding_options)
        self.toggle_shredding_options(self.delete_original_checkbox.checkState())

    def toggle_key_input_method(self, use_password_checked):
        self.password_label.setVisible(use_password_checked)
        self.password_entry.setVisible(use_password_checked)
        self.key_file_label.setVisible(not use_password_checked)
        self.key_file_path_entry.setVisible(not use_password_checked)
        self.browse_key_file_button.setVisible(not use_password_checked)
        self.key_file_path_entry.setEnabled(not use_password_checked)
        self.browse_key_file_button.setEnabled(not use_password_checked)

    def on_key_file_dropped(self, file_path):
        self.key_file_path_entry.setText(file_path)

    def browse_key_file(self):
        file_filter = "Key Files (*.pem *.key);;PEM Files (*.pem);;Symmetric Key Files (*.key);;All Files (*.*)"
        if path := QFileDialog.getOpenFileName(self, loc.get_string("select_key_file"), "", file_filter)[0]:
            self.key_file_path_entry.setText(path)

    def toggle_shredding_options(self, state):
        is_checked = (state == Qt.CheckState.Checked)
        self.secure_shredding_passes_label.setEnabled(is_checked)
        self.secure_shredding_passes_entry.setEnabled(is_checked)

    def on_file_dropped(self, file_path):
        self.input_path_entry.setText(file_path)
        self.main_window.show_status_message(loc.get_string("status_file_selected", path=os.path.basename(file_path)), 3000)
        if not self.is_encrypt_mode and file_path.endswith('.enc'):
            try:
                with open(file_path + '.meta', 'r') as f:
                    metadata = json.load(f)
                if (algo := metadata.get('algorithm')) in self.plugin_manager.get_available_plugins():
                    self.algo_dropdown.setCurrentText(algo)
                    self.main_window.show_status_message(loc.get_string("status_metadata_found", algo=algo), 5000)
                if metadata.get('key_source') == 'file' and metadata.get('key_path'):
                    self.key_file_radio_button.setChecked(True)
                    self.key_file_path_entry.setText(metadata['key_path'])
                else:
                    self.password_radio_button.setChecked(True)
            except FileNotFoundError:
                self.main_window.show_status_message(loc.get_string("metadata_not_found"), 5000)
            except Exception as e:
                self.main_window.show_status_message(loc.get_string("status_metadata_error", e=str(e)), 5000)

    def on_folder_dropped(self, folder_path):
        self.input_path_entry.setText(folder_path)
        self.main_window.show_status_message(loc.get_string("status_file_selected", path=os.path.basename(folder_path)), 3000)

    def browse_input(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.FileMode.ExistingFiles)
        dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        dialog.setOption(QFileDialog.Option.ShowDirsOnly, False)
        dialog.setNameFilter("All Files (*.*)")

        select_folder_button = QPushButton(loc.get_string("select_folder"))
        select_folder_button.clicked.connect(lambda: self._handle_folder_dialog_selection(dialog))

        layout = dialog.layout()
        if layout:
            button_box = dialog.findChild(QWidget, "buttonBox")
            if button_box and button_box.layout():
                button_box.layout().addWidget(select_folder_button)
            else:
                layout.addWidget(select_folder_button, layout.rowCount(), 0, 1, layout.columnCount())

        if dialog.exec():
            selected_paths = dialog.selectedFiles()
            if selected_paths:
                path = selected_paths[0]
                if os.path.isdir(path):
                    self.on_folder_dropped(path)
                else:
                    self.on_file_dropped(path)

    def _handle_folder_dialog_selection(self, dialog):
        folder_path = QFileDialog.getExistingDirectory(self, loc.get_string("select_folder"))
        if folder_path:
            self.input_path_entry.setText(folder_path)
            self.on_folder_dropped(folder_path)
        dialog.done(0)

    def browse_output(self):
        if path := QFileDialog.getExistingDirectory(self, loc.get_string("select_output_folder")):
            self.output_path_entry.setText(path)

    def update_plugin_options(self):
        current_algo = self.algo_dropdown.currentText()
        self.algo_dropdown.clear()
        if available := self.plugin_manager.get_available_plugins():
            self.algo_dropdown.addItems(available)
            if current_algo in available:
                self.algo_dropdown.setCurrentText(current_algo)
            elif self.app_settings.get("default_encryption_algorithm") in available:
                self.algo_dropdown.setCurrentText(self.app_settings.get("default_encryption_algorithm"))
            else:
                self.algo_dropdown.setCurrentIndex(0)

    def start_operation(self):
        input_path = self.input_path_entry.text()
        output_path = self.output_path_entry.text()
        algo_name = self.algo_dropdown.currentText()
        compression_algo = self.compression_algo_dropdown.currentText() if self.is_encrypt_mode else loc.get_string("no_compression")
        compression_level = int(self.compression_level_entry.text()) if self.is_encrypt_mode and self.compression_level_entry.text().isdigit() else -1
        perform_checksum = self.checksum_checkbox.isChecked() if self.is_encrypt_mode else False
        delete_original = self.delete_original_checkbox.isChecked() if self.is_encrypt_mode else False
        secure_shredding_passes = int(self.secure_shredding_passes_entry.text()) if delete_original and self.secure_shredding_passes_entry.text().isdigit() else 0

        key_source = "password" if self.password_radio_button.isChecked() else "file"
        password_or_key_file = self.password_entry.text() if key_source == "password" else self.key_file_path_entry.text()

        params = {
            "input_path": input_path,
            "output_path": output_path,
            "key_source": key_source,
            "password_or_key_file": password_or_key_file,
            "algo_name": algo_name,
            "compression_algo": compression_algo,
            "compression_level": compression_level,
            "perform_checksum": perform_checksum,
            "delete_original": delete_original,
            "secure_shredding_passes": secure_shredding_passes
        }

        if not all([input_path, output_path, algo_name]):
            QMessageBox.warning(self, loc.get_string("input_error"), loc.get_string("all_fields_filled"))
            return
        if key_source == "password" and not password_or_key_file:
            QMessageBox.warning(self, loc.get_string("input_error"), loc.get_string("password") + " field cannot be empty.")
            return
        if key_source == "file" and not password_or_key_file:
            QMessageBox.warning(self, loc.get_string("input_error"), loc.get_string("key_file_path") + " field cannot be empty.")
            return
        if key_source == "file" and not os.path.exists(password_or_key_file):
            QMessageBox.warning(self, loc.get_string("input_error"), "Key file not found: " + password_or_key_file)
            return


        self.action_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.file_status_label.setText(loc.get_string("waiting_for_op"))

        op_func = self._perform_batch_encryption if self.is_encrypt_mode else self._perform_batch_decryption
        self.thread = QThread()
        self.worker = Worker(op_func, **params)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_operation_complete)
        self.worker.error.connect(self.on_operation_error)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.file_progress.connect(self.update_file_progress_label)
        self.worker.current_file_status.connect(self.file_status_label.setText)

        self.thread.start()

    def update_file_progress_label(self, current_file_index, total_files, filename):
        self.file_status_label.setText(loc.get_string("file_processing_status_batch",
                                                      current_file_index=current_file_index,
                                                      total_files=total_files,
                                                      filename=os.path.basename(filename)))
        overall_progress = int((current_file_index / total_files) * 100)
        self.progress_bar.setValue(overall_progress)


    def on_operation_complete(self, result_message):
        self.action_button.setEnabled(True)
        self.progress_bar.setValue(100)
        self.file_status_label.setText(loc.get_string("waiting_for_op"))
        self.main_window.show_status_message(str(result_message), 5000)
        QMessageBox.information(self, "Success", str(result_message))
        self.thread.quit()
        self.thread.wait()

    def on_operation_error(self, error_message):
        self.action_button.setEnabled(True)
        self.file_status_label.setText(loc.get_string("waiting_for_op"))
        self.main_window.show_status_message(f"Error: {error_message}", 8000)
        QMessageBox.critical(self, "Error", error_message)
        self.thread.quit()
        self.thread.wait()

    def _derive_key(self, password, salt):
        return PBKDF2HMAC(hashes.SHA256(), 32, salt, 480000, backend=default_backend()).derive(password.encode())

    def _load_key_from_file(self, key_file_path):
        """Loads key material from a file (PEM for RSA, Base64 for symmetric)."""
        try:
            with open(key_file_path, 'rb') as f:
                key_data = f.read()
            if key_file_path.lower().endswith('.pem'):
                try:
                    private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
                    return private_key
                except ValueError as ve:
                    if "bad decrypt" in str(ve) or "Unsupported or incorrect encryption" in str(ve):
                        raise ValueError(f"Encrypted PEM key file '{os.path.basename(key_file_path)}' requires a password.")
                    else:
                        raise ValueError(f"Invalid PEM file format or corrupted: {ve}")
                except Exception as e:
                    try:
                        public_key = serialization.load_pem_public_key(key_data, backend=default_backend())
                        return public_key
                    except Exception as e:
                        raise ValueError(f"Invalid PEM file format: {e}")
            elif key_file_path.lower().endswith('.key'):
                return b64decode(key_data)
            else:
                raise ValueError("Unsupported key file extension. Use .pem or .key")
        except Exception as e:
            logger.error(f"Error loading key from file '{os.path.basename(key_file_path)}': {e}")
            raise ValueError(f"Failed to load key from file: {e}")


    def _get_files_in_path(self, path):
        """Recursively gets all file paths within a given path."""
        if os.path.isfile(path):
            return [path]
        elif os.path.isdir(path):
            file_list = []
            for root, _, files in os.walk(path):
                for file in files:
                    file_list.append(os.path.join(root, file))
            return file_list
        return []

    def _perform_batch_encryption(self, worker, **kwargs):
        input_path = kwargs["input_path"]
        output_base_path = kwargs["output_path"]
        key_source = kwargs["key_source"]
        password_or_key_file = kwargs["password_or_key_file"]
        algo_name = kwargs["algo_name"]
        compression_algo = kwargs["compression_algo"]
        compression_level = kwargs["compression_level"]
        perform_checksum = kwargs["perform_checksum"]
        delete_original = kwargs["delete_original"]
        secure_shredding_passes = kwargs["secure_shredding_passes"]

        files_to_process = self._get_files_in_path(input_path)
        total_files = len(files_to_process)
        processed_count = 0
        successful_count = 0

        if total_files == 0:
            return loc.get_string("encryption_complete", count=0)

        encryption_key_material = None
        if key_source == "file":
            try:
                encryption_key_material = self._load_key_from_file(password_or_key_file)
                if isinstance(encryption_key_material, rsa.RSAPrivateKey):
                    encryption_key_material = encryption_key_material.public_key()
                elif not isinstance(encryption_key_material, bytes):
                    raise ValueError("Unsupported key file type for encryption.")
            except ValueError as e:
                raise Exception(f"Key file loading error: {e}")


        for i, file_path in enumerate(files_to_process):
            if worker.is_cancelled:
                return loc.get_string("operation_cancelled")

            worker.file_progress.emit(i + 1, total_files, file_path)
            worker.current_file_status.emit(loc.get_string("file_processing_status", filename=os.path.basename(file_path)))

            try:
                relative_path_part = os.path.relpath(file_path, input_path)
                relative_dir = os.path.dirname(relative_path_part)

                output_dir = os.path.join(output_base_path, relative_dir)
                os.makedirs(output_dir, exist_ok=True)
                final_output_path = os.path.join(output_dir, os.path.basename(file_path) + ".enc")

                with open(file_path, 'rb') as f:
                    plaintext = f.read()

                original_checksum = None
                if perform_checksum:
                    original_checksum = hashlib.sha256(plaintext).hexdigest()
                    logger.info(f"Generated checksum for {os.path.basename(file_path)}: {original_checksum}")

                compressed_data = plaintext
                if compression_algo != loc.get_string("no_compression"):
                    temp_compressed_path = file_path + ".comp_temp"
                    if compress_file(file_path, temp_compressed_path, compression_algo, compression_level):
                        with open(temp_compressed_path, 'rb') as f_comp:
                            compressed_data = f_comp.read()
                        os.remove(temp_compressed_path)
                    else:
                        raise Exception("Compression failed.")

                salt_b64 = None
                iv_b64 = None
                tag_b64 = None
                encrypted_data = None
                key_type_meta = "symmetric"
                key_path_meta = None

                if key_source == "password":
                    salt = os.urandom(16)
                    key = self._derive_key(password_or_key_file, salt)
                    iv = os.urandom(12)
                    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
                    encrypted_data = encryptor.update(compressed_data) + encryptor.finalize()
                    salt_b64 = b64encode(salt).decode()
                    iv_b64 = b64encode(iv).decode()
                    tag_b64 = b64encode(encryptor.tag).decode()
                else:
                    key_path_meta = password_or_key_file
                    if isinstance(encryption_key_material, rsa.RSAPublicKey):
                        key_type_meta = "rsa"
                        symmetric_key_for_file = os.urandom(32)
                        rsa_encrypted_symmetric_key = encryption_key_material.encrypt(
                            symmetric_key_for_file,
                            rsa_padding.OAEP(
                                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        iv = os.urandom(12)
                        encryptor = Cipher(algorithms.AES(symmetric_key_for_file), modes.GCM(iv), backend=default_backend()).encryptor()
                        encrypted_data = encryptor.update(compressed_data) + encryptor.finalize()
                        iv_b64 = b64encode(iv).decode()
                        tag_b64 = b64encode(encryptor.tag).decode()
                        salt_b64 = b64encode(rsa_encrypted_symmetric_key).decode()

                    elif isinstance(encryption_key_material, bytes):
                        iv = os.urandom(12)
                        encryptor = Cipher(algorithms.AES(encryption_key_material), modes.GCM(iv), backend=default_backend()).encryptor()
                        encrypted_data = encryptor.update(compressed_data) + encryptor.finalize()
                        iv_b64 = b64encode(iv).decode()
                        tag_b64 = b64encode(encryptor.tag).decode()
                        salt_b64 = None
                    else:
                        raise ValueError("Invalid key material from file.")

                with open(final_output_path, 'wb') as f:
                    f.write(encrypted_data)

                meta = {
                    'algorithm': algo_name,
                    'salt': salt_b64,
                    'iv': iv_b64,
                    'tag': tag_b64,
                    'compression': compression_algo if compression_algo != loc.get_string("no_compression") else None,
                    'original_checksum': original_checksum,
                    'key_source': key_source,
                    'key_path': key_path_meta
                }
                with open(final_output_path + '.meta', 'w') as f:
                    json.dump(meta, f, indent=4)

                if delete_original:
                    worker.current_file_status.emit(loc.get_string("file_shredding"))
                    if secure_shredding_passes > 0:
                        secure_delete_file(file_path, secure_shredding_passes)
                    else:
                        os.remove(file_path)
                    worker.current_file_status.emit(loc.get_string("shredding_complete"))

                successful_count += 1
                logger.info(f"Successfully encrypted: {os.path.basename(file_path)}")

            except Exception as e:
                logger.error(f"Failed to encrypt {os.path.basename(file_path)}: {e}")
                worker.error.emit(f"Failed to encrypt {os.path.basename(file_path)}: {e}")

            processed_count += 1
            worker.progress.emit(int((processed_count / total_files) * 100))

        return loc.get_string("encryption_complete", count=successful_count)

    def _perform_batch_decryption(self, worker, **kwargs):
        input_path = kwargs["input_path"]
        output_base_path = kwargs["output_path"]
        key_source = kwargs["key_source"]
        password_or_key_file = kwargs["password_or_key_file"]
        algo_name = kwargs["algo_name"]
        perform_checksum = kwargs["perform_checksum"]

        files_to_process = [f for f in self._get_files_in_path(input_path) if f.endswith('.enc')]
        total_files = len(files_to_process)
        processed_count = 0
        successful_count = 0

        if total_files == 0:
            return loc.get_string("decryption_complete", count=0)

        decryption_key_material = None
        if key_source == "file":
            try:
                decryption_key_material = self._load_key_from_file(password_or_key_file)
                if not isinstance(decryption_key_material, (rsa.RSAPrivateKey, bytes)):
                    raise ValueError("Unsupported key file type for decryption. Must be RSA Private Key or Symmetric Key.")
            except ValueError as e:
                raise Exception(f"Key file loading error: {e}")


        for i, file_path in enumerate(files_to_process):
            if worker.is_cancelled:
                return loc.get_string("operation_cancelled")

            worker.file_progress.emit(i + 1, total_files, file_path)
            worker.current_file_status.emit(loc.get_string("file_processing_status", filename=os.path.basename(file_path)))

            meta_path = file_path + '.meta'
            if not os.path.exists(meta_path):
                logger.warning(f"Metadata file not found for {os.path.basename(file_path)}. Skipping.")
                worker.error.emit(loc.get_string("metadata_not_found"))
                processed_count += 1
                continue

            try:
                with open(meta_path, 'r') as f:
                    meta = json.load(f)

                salt_b64 = meta.get('salt')
                iv_b64 = meta['iv']
                tag_b64 = meta['tag']
                compression_algo_meta = meta.get('compression')
                original_checksum_meta = meta.get('original_checksum')
                key_source_meta = meta.get('key_source', 'password')

                decryption_key = None

                if key_source_meta == "password":
                    if not password_or_key_file:
                        raise ValueError("Password not provided for decryption.")
                    salt = b64decode(salt_b64)
                    decryption_key = self._derive_key(password_or_key_file, salt)
                elif key_source_meta == "file":
                    if not decryption_key_material:
                        raise ValueError("Key file not provided or invalid for decryption.")

                    if isinstance(decryption_key_material, rsa.RSAPrivateKey):
                        rsa_encrypted_symmetric_key = b64decode(salt_b64)
                        symmetric_key_for_file = decryption_key_material.decrypt(
                            rsa_encrypted_symmetric_key,
                            rsa_padding.OAEP(
                                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        decryption_key = symmetric_key_for_file
                    elif isinstance(decryption_key_material, bytes):
                        decryption_key = decryption_key_material
                    else:
                        raise ValueError("Invalid key material type for decryption.")

                if decryption_key is None:
                    raise ValueError("Could not determine decryption key.")

                with open(file_path, 'rb') as f:
                    ciphertext = f.read()

                try:
                    iv = b64decode(iv_b64)
                    tag = b64decode(tag_b64)
                    decryptor = Cipher(algorithms.AES(decryption_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
                    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                except InvalidTag:
                    raise ValueError(loc.get_string("invalid_password_or_corrupt"))

                decompressed_data = decrypted_data
                if compression_algo_meta:
                    temp_decompressed_path = file_path.replace(".enc", "") + ".decomp_temp"
                    with open(temp_decompressed_path, 'wb') as f_temp:
                        f_temp.write(decrypted_data)

                    if decompress_file(temp_decompressed_path, temp_decompressed_path + ".final", compression_algo_meta):
                        with open(temp_decompressed_path + ".final", 'rb') as f_decomp:
                            decompressed_data = f_decomp.read()
                        os.remove(temp_decompressed_path)
                        os.remove(temp_decompressed_path + ".final")
                    else:
                        os.remove(temp_decompressed_path)
                        raise Exception("Decompression failed.")

                relative_path_part = os.path.relpath(file_path, input_path)
                relative_dir = os.path.dirname(relative_path_part)

                output_dir = os.path.join(output_base_path, relative_dir)
                os.makedirs(output_dir, exist_ok=True)
                final_output_path = os.path.join(output_dir, os.path.basename(file_path).replace(".enc", ""))

                with open(final_output_path, 'wb') as f:
                    f.write(decompressed_data)

                if original_checksum_meta:
                    current_checksum = hashlib.sha256(decompressed_data).hexdigest()
                    if current_checksum == original_checksum_meta:
                        logger.info(loc.get_string("checksum_verified", filename=os.path.basename(file_path)))
                    else:
                        logger.warning(loc.get_string("checksum_mismatch", filename=os.path.basename(file_path)))
                        worker.current_file_status.emit(loc.get_string("checksum_mismatch", filename=os.path.basename(file_path)))

                successful_count += 1
                logger.info(f"Successfully decrypted: {os.path.basename(file_path)}")

            except Exception as e:
                logger.error(f"Failed to decrypt {os.path.basename(file_path)}: {e}")
                worker.error.emit(f"Failed to decrypt {os.path.basename(file_path)}: {e}")

            processed_count += 1
            worker.progress.emit(int((processed_count / total_files) * 100))

        return loc.get_string("decryption_complete", count=successful_count)


class EncryptTab(CryptoTab):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, is_encrypt_mode=True)
        self.retranslate_ui()

    def retranslate_ui(self):
        self.action_button.setText(loc.get_string("encrypt_files"))
        self.input_path_entry.setToolTip(loc.get_string("tooltip_input_file"))
        self.output_path_entry.setToolTip(loc.get_string("tooltip_output_folder"))
        self.algo_dropdown.setToolTip(loc.get_string("tooltip_algorithm"))
        self.password_entry.setToolTip(loc.get_string("tooltip_password"))
        self.delete_original_checkbox.setToolTip(loc.get_string("tooltip_delete_original"))


class DecryptTab(CryptoTab):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, is_encrypt_mode=False)
        self.retranslate_ui()

    def retranslate_ui(self):
        self.action_button.setText(loc.get_string("decrypt_files"))
        self.input_path_entry.setToolTip(loc.get_string("tooltip_input_file"))
        self.output_path_entry.setToolTip(loc.get_string("tooltip_output_folder"))
        self.algo_dropdown.setToolTip(loc.get_string("tooltip_algorithm"))
        self.password_entry.setToolTip(loc.get_string("tooltip_password"))


# --- Generate Keys Tab (Restored and Enhanced) ---
class GenerateKeysTab(BaseTab):
    def __init__(self, key_manager, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key_manager = key_manager
        self.private_pem = None
        self.public_pem = None
        self.symmetric_key_b64 = None
        self.setup_ui()
        self.retranslate_ui()
        self.update_plugin_options()

    def setup_ui(self):
        self.algo_label = QLabel(loc.get_string("algorithm_key_generation"))
        self.algo_dropdown = QComboBox()
        self.layout.addWidget(self.algo_label, 0, 0)
        self.layout.addWidget(self.algo_dropdown, 0, 1, 1, 2)

        self.rsa_password_label = QLabel(loc.get_string("rsa_gen_password_label"))
        self.rsa_password_entry = QLineEdit()
        self.rsa_password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.rsa_password_label, 1, 0)
        self.layout.addWidget(self.rsa_password_entry, 1, 1, 1, 2)

        self.key_name_label = QLabel(loc.get_string("key_name"))
        self.key_name_entry = QLineEdit()
        self.layout.addWidget(self.key_name_label, 2, 0)
        self.layout.addWidget(self.key_name_entry, 2, 1, 1, 2)

        self.generate_button = QPushButton()
        self.layout.addWidget(self.generate_button, 3, 0, 1, 3)

        self.key_output_textbox = QTextEdit()
        self.key_output_textbox.setReadOnly(True)
        self.layout.addWidget(self.key_output_textbox, 4, 0, 1, 3)

        btn_layout = QHBoxLayout()
        self.copy_key_button = QPushButton(loc.get_string("copy_keys_clipboard"))
        self.save_public_key_button = QPushButton(loc.get_string("save_public_key"))
        self.save_private_key_button = QPushButton(loc.get_string("save_private_key"))
        self.save_symmetric_key_button = QPushButton(loc.get_string("save_symmetric_key"))

        btn_layout.addWidget(self.copy_key_button)
        btn_layout.addWidget(self.save_public_key_button)
        btn_layout.addWidget(self.save_private_key_button)
        btn_layout.addWidget(self.save_symmetric_key_button)
        self.layout.addLayout(btn_layout, 5, 0, 1, 3)
        self.layout.setRowStretch(6, 1)

        self.generate_button.clicked.connect(self.generate_keys)
        self.copy_key_button.clicked.connect(lambda: self.main_window.copy_to_clipboard(self.key_output_textbox.toPlainText()))
        self.save_public_key_button.clicked.connect(lambda: self.save_key_to_file('public'))
        self.save_private_key_button.clicked.connect(lambda: self.save_key_to_file('private'))
        self.save_symmetric_key_button.clicked.connect(lambda: self.save_key_to_file('symmetric'))
        self.algo_dropdown.currentTextChanged.connect(self.on_algo_selected)

        self.on_algo_selected(self.algo_dropdown.currentText())

    def retranslate_ui(self):
        self.generate_button.setText(loc.get_string("generate_keys"))
        self.rsa_password_entry.setToolTip(loc.get_string("tooltip_rsa_gen_password"))
        self.save_public_key_button.setToolTip(loc.get_string("tooltip_save_key"))
        self.save_private_key_button.setToolTip(loc.get_string("tooltip_save_key"))
        self.save_symmetric_key_button.setToolTip(loc.get_string("tooltip_save_key"))

    def update_plugin_options(self):
        current_algo = self.algo_dropdown.currentText()
        self.algo_dropdown.clear()
        all_plugins = self.plugin_manager.get_all_plugins()
        if all_plugins:
            self.algo_dropdown.addItems(list(all_plugins.keys()))
            if current_algo in all_plugins:
                self.algo_dropdown.setCurrentText(current_algo)
            else:
                self.algo_dropdown.setCurrentIndex(0)
        else:
            self.algo_dropdown.addItem("No Plugins Found")

    def on_algo_selected(self, algo_name):
        is_rsa = "RSA" in algo_name.upper()
        self.rsa_password_label.setVisible(is_rsa)
        self.rsa_password_entry.setVisible(is_rsa)
        self.key_name_label.setVisible(is_rsa)
        self.key_name_entry.setVisible(is_rsa)
        self.save_public_key_button.setVisible(is_rsa)
        self.save_private_key_button.setVisible(is_rsa)
        self.save_symmetric_key_button.setVisible(not is_rsa)

    def generate_keys(self):
        algo_name = self.algo_dropdown.currentText()
        is_rsa = "RSA" in algo_name.upper()
        key_name = self.key_name_entry.text().strip() if is_rsa else ""

        if is_rsa and not key_name:
            QMessageBox.warning(self, loc.get_string("input_error"), "Please provide a name for the RSA key pair.")
            return
        if not is_rsa and not algo_name:
            if "AES" in self.plugin_manager.get_available_plugins():
                algo_name = "AES"
            else:
                QMessageBox.warning(self, loc.get_string("input_error"), "Please select a symmetric algorithm or ensure 'AES' plugin is available for symmetric key generation.")
                return

        self.private_pem = None
        self.public_pem = None
        self.symmetric_key_b64 = None
        self.key_output_textbox.clear()

        try:
            if is_rsa:
                password = self.rsa_password_entry.text().encode() if self.rsa_password_entry.text() else None
                enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()

                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                self.private_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc_algo)
                self.public_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                self.key_output_textbox.setText(f"--- PUBLIC KEY ---\n{self.public_pem.decode()}\n\n--- PRIVATE KEY ---\n{self.private_pem.decode()}")

            else:
                key = os.urandom(32)
                self.symmetric_key_b64 = b64encode(key).decode()
                self.key_output_textbox.setText(f"--- SYMMETRIC KEY (Base64) ---\n{self.symmetric_key_b64}")

            QMessageBox.information(self, loc.get_string("key_generation"), loc.get_string("key_generation_success", algo_name=algo_name))
        except Exception as e:
            QMessageBox.critical(self, loc.get_string("key_generation_error_title"), str(e))
            logger.error(f"Key generation error: {e}")

    def save_key_to_file(self, key_type):
        if key_type == 'symmetric':
            content = self.symmetric_key_b64
            if not content:
                QMessageBox.warning(self, "No Key", loc.get_string("no_key_to_save"))
                return
            path, _ = QFileDialog.getSaveFileName(self, loc.get_string("save_symmetric_key"), "symmetric_key.key", "Key Files (*.key);;Text Files (*.txt);;All Files (*.*)")
            if path:
                try:
                    with open(path, 'w') as f:
                        f.write(content)
                    self.key_manager.add_key(os.path.basename(path), "Symmetric", path)
                    self.main_window.key_management_tab.load_keys()
                    self.main_window.show_status_message(loc.get_string("key_saved_to", path=path), 5000)
                except Exception as e:
                    QMessageBox.critical(self, loc.get_string("file_save_error"), str(e))
                    logger.error(f"Error saving symmetric key to file: {e}")
        else:
            content = getattr(self, f"{key_type}_pem", None)
            if not content:
                QMessageBox.warning(self, "No Key", loc.get_string("no_key_to_save"))
                return
            default_filename = self.key_name_entry.text().strip() or key_type
            path, _ = QFileDialog.getSaveFileName(self, f"Save {key_type.capitalize()} Key", f"{default_filename}_{key_type}.pem", "PEM Files (*.pem)")
            if path:
                try:
                    with open(path, 'wb') as f:
                        f.write(content)
                    if key_type == 'private':
                        self.key_manager.add_key(self.key_name_entry.text().strip(), "RSA", path)
                        self.main_window.key_management_tab.load_keys()
                    self.main_window.show_status_message(loc.get_string("key_saved_to", path=path), 5000)
                except Exception as e:
                    QMessageBox.critical(self, loc.get_string("file_save_error"), str(e))
                    logger.error(f"Error saving RSA key to file: {e}")


# --- Plugins Tab (Restored and Enhanced) ---
class PluginsTab(BaseTab):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setup_ui()
        self.retranslate_ui()
        self.load_plugin_list()

    def setup_ui(self):
        self.plugin_list_widget = QListWidget()
        self.reload_button = QPushButton()
        self.layout.addWidget(QLabel("Available Encryption Plugins:"), 0, 0)
        self.layout.addWidget(self.plugin_list_widget, 1, 0)
        self.layout.addWidget(self.reload_button, 2, 0)
        self.plugin_list_widget.itemChanged.connect(self.on_plugin_status_changed)
        self.reload_button.clicked.connect(self.reload_plugins)

    def retranslate_ui(self):
        self.reload_button.setText("Reload Plugins from Disk")
        self.plugin_list_widget.setToolTip(loc.get_string("plugins_enable_disable"))

    def load_plugin_list(self):
        self.plugin_list_widget.blockSignals(True)
        self.plugin_list_widget.clear()
        all_plugins = self.plugin_manager.get_all_plugins()
        enabled_plugins = self.app_settings.get("enabled_plugins", {})

        for name in all_plugins.keys():
            item = QListWidgetItem(name)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            if name not in enabled_plugins:
                enabled_plugins[name] = True
            item.setCheckState(Qt.CheckState.Checked if enabled_plugins.get(name, True) else Qt.CheckState.Unchecked)
            self.plugin_list_widget.addItem(item)
        self.plugin_manager.settings["enabled_plugins"] = enabled_plugins
        self.plugin_list_widget.blockSignals(False)

    def on_plugin_status_changed(self, item):
        self.plugin_manager.set_plugin_status(item.text(), item.checkState() == Qt.CheckState.Checked)
        self.main_window.update_all_tabs_plugin_options()
        self.main_window.save_settings()

    def reload_plugins(self):
        self.plugin_manager.load_plugins()
        self.load_plugin_list()
        self.main_window.update_all_tabs_plugin_options()
        self.main_window.show_status_message(loc.get_string("plugins_reloaded"), 3000)

# --- Settings and About Tabs (Restored) ---
class SettingsTab(BaseTab):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setup_ui()
        self.load_settings_to_ui()

    def setup_ui(self):
        self.language_label = QLabel(loc.get_string("language_wip"))
        self.language_dropdown = QComboBox()
        self.language_dropdown.addItem("English")
        self.language_dropdown.setEnabled(False)
        self.layout.addWidget(self.language_label, 0, 0)
        self.layout.addWidget(self.language_dropdown, 0, 1)

        self.font_label = QLabel(loc.get_string("font_selection"))
        self.font_dropdown = QComboBox()
        self.font_dropdown.addItems(["Segoe UI", "Arial", "Verdana", "Tahoma", "Courier New", "SF Pro Display"])
        self.font_dropdown.currentTextChanged.connect(self.change_font)
        self.layout.addWidget(self.font_label, 1, 0)
        self.layout.addWidget(self.font_dropdown, 1, 1)

        self.animation_speed_label = QLabel(loc.get_string("animation_speed"))
        self.animation_speed_slider = QSlider(Qt.Orientation.Horizontal)
        self.animation_speed_slider.setRange(1, 10)
        self.animation_speed_slider.setValue(5)
        self.animation_speed_slider.setTickInterval(1)
        self.animation_speed_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.animation_speed_slider.valueChanged.connect(self.change_animation_speed)
        self.layout.addWidget(self.animation_speed_label, 2, 0)
        self.layout.addWidget(self.animation_speed_slider, 2, 1)

        self.default_output_folder_label = QLabel(loc.get_string("default_output_folder"))
        self.default_output_folder_entry = QLineEdit()
        self.browse_default_output_button = QPushButton(loc.get_string("browse"))
        self.browse_default_output_button.clicked.connect(self.browse_default_output_folder)
        self.layout.addWidget(self.default_output_folder_label, 3, 0)
        self.layout.addWidget(self.default_output_folder_entry, 3, 1)
        self.layout.addWidget(self.browse_default_output_button, 3, 2)

        self.default_encryption_algo_label = QLabel(loc.get_string("default_encryption_algorithm"))
        self.default_encryption_algo_dropdown = QComboBox()
        self.default_encryption_algo_dropdown.currentTextChanged.connect(self.save_default_encryption_algo)
        self.layout.addWidget(self.default_encryption_algo_label, 4, 0)
        self.layout.addWidget(self.default_encryption_algo_dropdown, 4, 1, 1, 2)
        self.update_default_encryption_algo_options()

        self.default_shred_passes_label = QLabel(loc.get_string("secure_shredding_passes"))
        self.default_shred_passes_entry = QLineEdit("0")
        self.default_shred_passes_entry.textChanged.connect(self.save_shredding_setting)
        self.layout.addWidget(self.default_shred_passes_label, 5, 0)
        self.layout.addWidget(self.default_shred_passes_entry, 5, 1)

        self.confirm_on_exit_checkbox = QCheckBox(loc.get_string("confirm_on_exit"))
        self.confirm_on_exit_checkbox.stateChanged.connect(self.save_confirm_on_exit_setting)
        self.layout.addWidget(self.confirm_on_exit_checkbox, 6, 0, 1, 2)

        self.log_settings_group_label = QLabel(loc.get_string("log_file_settings"))
        self.log_settings_group_label.setObjectName("SectionLabel")
        self.layout.addWidget(self.log_settings_group_label, 7, 0, 1, 3)

        self.max_log_size_label = QLabel(loc.get_string("max_log_size_mb"))
        self.max_log_size_entry = QLineEdit("5")
        self.max_log_size_entry.textChanged.connect(self.save_log_settings)
        self.layout.addWidget(self.max_log_size_label, 8, 0)
        self.layout.addWidget(self.max_log_size_entry, 8, 1)

        self.enable_log_rotation_checkbox = QCheckBox(loc.get_string("enable_log_rotation"))
        self.enable_log_rotation_checkbox.stateChanged.connect(self.save_log_settings)
        self.layout.addWidget(self.enable_log_rotation_checkbox, 9, 0, 1, 2)


        self.layout.setRowStretch(10, 1)

    def change_font(self, font_name):
        self.app_settings["font"] = font_name
        self.main_window.apply_font(font_name)
        self.main_window.save_settings()

    def change_animation_speed(self, value):
        self.app_settings["animation_speed"] = value
        self.main_window.save_settings()

    def browse_default_output_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, loc.get_string("select_default_output_folder"))
        if folder_path:
            self.default_output_folder_entry.setText(folder_path)
            self.app_settings["default_output_folder"] = folder_path
            self.main_window.save_settings()

    def update_default_encryption_algo_options(self):
        current_algo = self.default_encryption_algo_dropdown.currentText()
        self.default_encryption_algo_dropdown.clear()
        available_plugins = self.plugin_manager.get_available_plugins()
        self.default_encryption_algo_dropdown.addItems([""] + available_plugins)
        if current_algo in available_plugins:
            self.default_encryption_algo_dropdown.setCurrentText(current_algo)
        elif self.app_settings.get("default_encryption_algorithm") in available_plugins:
            self.default_encryption_algo_dropdown.setCurrentText(self.app_settings.get("default_encryption_algorithm"))
        else:
            self.default_encryption_algo_dropdown.setCurrentIndex(0)

    def save_default_encryption_algo(self, algo_name):
        self.app_settings["default_encryption_algorithm"] = algo_name if algo_name else None
        self.main_window.save_settings()

    def save_shredding_setting(self):
        try:
            passes = int(self.default_shred_passes_entry.text())
            self.app_settings["default_shredding_passes"] = max(0, passes)
            self.main_window.save_settings()
        except ValueError:
            pass

    def save_confirm_on_exit_setting(self, state):
        self.app_settings["confirm_on_exit"] = (state == Qt.CheckState.Checked)
        self.main_window.save_settings()

    def save_log_settings(self):
        try:
            max_size_mb = int(self.max_log_size_entry.text())
            self.app_settings["max_log_size_mb"] = max(1, max_size_mb)
            self.app_settings["enable_log_rotation"] = self.enable_log_rotation_checkbox.isChecked()
            self.main_window.configure_logging()
            self.main_window.save_settings()
        except ValueError:
            pass

    def load_settings_to_ui(self):
        self.default_shred_passes_entry.setText(str(self.app_settings.get("default_shredding_passes", 0)))
        self.font_dropdown.setCurrentText(self.app_settings.get("font", "Segoe UI"))
        self.animation_speed_slider.setValue(self.app_settings.get("animation_speed", 5))
        self.max_log_size_entry.setText(str(self.app_settings.get("max_log_size_mb", 5)))
        self.enable_log_rotation_checkbox.setChecked(self.app_settings.get("enable_log_rotation", True))
        self.default_output_folder_entry.setText(self.app_settings.get("default_output_folder", ""))
        self.confirm_on_exit_checkbox.setChecked(self.app_settings.get("confirm_on_exit", False))
        self.update_default_encryption_algo_options()


class AboutTab(BaseTab):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setup_ui()

    def setup_ui(self):
        # The base class already provides a QGridLayout named self.layout.
        # We will use this layout directly.

        # Create a container widget for the central content to hold all elements
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Satan logo
        self.logo_label = QLabel()
        logo_path = os.path.join(ASSETS_DIR, SATAN_LOGO_FILENAME)
        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path).scaledToHeight(128, Qt.TransformationMode.SmoothTransformation)
            self.logo_label.setPixmap(pixmap)
            self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.setObjectName("AboutTabLogo")
        content_layout.addWidget(self.logo_label)

        # App name and version
        self.app_name_label = QLabel(loc.get_string("app_name"))
        font = self.app_name_label.font()
        font.setPointSize(24)
        font.setBold(True)
        self.app_name_label.setFont(font)
        self.app_name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.app_name_label.setObjectName("AboutTabName")
        content_layout.addWidget(self.app_name_label)

        self.version_label = QLabel(f'{loc.get_string("version")}{APP_VERSION}')
        self.version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.version_label.setObjectName("AboutTabInfo")
        content_layout.addWidget(self.version_label)

        self.developer_label = QLabel(f'{loc.get_string("developed_by")}{DEVELOPER_NAME}')
        self.developer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.developer_label.setObjectName("AboutTabInfo")
        content_layout.addWidget(self.developer_label)

        # Add a spacer to push contact info down
        content_layout.addSpacing(20)

        # Contact and GitHub links
        contact_layout = QHBoxLayout()
        contact_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        contact_layout.setSpacing(20)

        # GitHub Button/Link
        github_button = QPushButton()
        github_button.setIcon(QIcon(QPixmap.fromImage(QImage.fromData(b64decode(GITHUB_SVG.encode())))))
        github_button.setText("GitHub")
        github_button.setObjectName("AboutTabContactButton")
        github_button.clicked.connect(lambda: webbrowser.open(GITHUB_URL))
        contact_layout.addWidget(github_button)

        # Mail Button/Link
        mail_button = QPushButton()
        mail_button.setIcon(QIcon(QPixmap.fromImage(QImage.fromData(b64decode(MAIL_SVG.encode())))))
        mail_button.setText("Email")
        mail_button.setObjectName("AboutTabContactButton")
        mail_button.clicked.connect(lambda: webbrowser.open(f"mailto:{DEVELOPER_EMAIL}"))
        contact_layout.addWidget(mail_button)

        content_layout.addLayout(contact_layout)
        
        # Add the content_widget to the central cell of the main layout, surrounded by stretch items
        # This will center the entire content block within the tab.
        self.layout.setRowStretch(0, 1)
        self.layout.setColumnStretch(0, 1)
        self.layout.addWidget(content_widget, 1, 1)
        self.layout.setRowStretch(2, 1)
        self.layout.setColumnStretch(2, 1)

# --- NEW: What's New Tab ---
class WhatsNewTab(BaseTab):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_expanded = False
        self.setup_ui()
        self.retranslate_ui()

    def setup_ui(self):
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0,0,0,0)

        self.title_label = QLabel(loc.get_string("whats_new_title", version=APP_VERSION))
        self.title_label.setObjectName("TitleLabel")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header_layout.addWidget(self.title_label)

        self.toggle_button = QToolButton(self)
        self.toggle_button.setObjectName("WhatsNewToggle")
        self.toggle_button.setArrowType(Qt.ArrowType.DownArrow)
        self.toggle_button.clicked.connect(self.toggle_content_visibility)
        header_layout.addWidget(self.toggle_button)

        header_layout.addStretch(1)

        header_widget.mousePressEvent = lambda event: self.toggle_content_visibility()
        header_widget.setCursor(Qt.CursorShape.PointingHandCursor)

        self.layout.addWidget(header_widget, 0, 0, 1, 1)

        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(10, 5, 10, 5)
        self.content_text_edit = QTextEdit()
        self.content_text_edit.setReadOnly(True)
        self.content_layout.addWidget(self.content_text_edit)
        self.content_widget.setLayout(self.content_layout)

        self.layout.addWidget(self.content_widget, 1, 0, 1, 1)
        self.layout.setRowStretch(2, 1)

        self.animation = QPropertyAnimation(self.content_widget, b"maximumHeight")
        self.animation.setDuration(self.app_settings.get("animation_speed", 5) * 50)
        self.animation.setEasingCurve(QEasingCurve.Type.InOutQuad)

        self.content_widget.hide()
        self.content_widget.setMaximumHeight(0)

    def retranslate_ui(self):
        self.title_label.setText(loc.get_string("whats_new_title", version=APP_VERSION))
        self.content_text_edit.setHtml(loc.get_string("whats_new_content"))
        self.toggle_button.setArrowType(Qt.ArrowType.UpArrow if self.is_expanded else Qt.ArrowType.DownArrow)

    def toggle_content_visibility(self):
        self.is_expanded = not self.is_expanded
        self.toggle_button.setArrowType(Qt.ArrowType.UpArrow if self.is_expanded else Qt.ArrowType.DownArrow)

        if self.is_expanded:
            self.content_widget.show()
            self.content_widget.setMaximumHeight(QApplication.primaryScreen().size().height())
            self.content_widget.adjustSize()
            target_height = self.content_widget.sizeHint().height()
            self.content_widget.setMaximumHeight(0)
            self.animation.setStartValue(0)
            self.animation.setEndValue(target_height)
        else:
            self.animation.setStartValue(self.content_widget.height())
            self.animation.setEndValue(0)
            self.animation.finished.connect(self.content_widget.hide)

        self.animation.start()


# --- NEW: Interactive Log Viewer Widget ---
class LogViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.log_entries = []
        self.setup_ui()

    def setup_ui(self):
        self.layout = QVBoxLayout(self)
        self.setLayout(self.layout)

        control_layout = QHBoxLayout()
        self.filter_label = QLabel(loc.get_string("filter_by_level"))
        self.filter_dropdown = QComboBox()
        self.filter_dropdown.addItems([loc.get_string("all_levels"), loc.get_string("info"), loc.get_string("warning"), loc.get_string("error")])
        self.filter_dropdown.currentTextChanged.connect(self.apply_filter)

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText(loc.get_string("search_logs"))
        self.search_entry.textChanged.connect(self.apply_filter)

        self.export_button = QPushButton(loc.get_string("export_logs"))
        self.export_button.clicked.connect(self.export_logs)

        control_layout.addWidget(self.filter_label)
        control_layout.addWidget(self.filter_dropdown)
        control_layout.addWidget(self.search_entry)
        control_layout.addWidget(self.export_button)
        self.layout.addLayout(control_layout)

        self.log_table = QTableWidget()
        self.log_table.setColumnCount(3)
        self.log_table.setHorizontalHeaderLabels(["Time", "Level", "Message"])
        self.log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.log_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.log_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.log_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.log_table.customContextMenuRequested.connect(self.show_context_menu)

        self.layout.addWidget(self.log_table)

    def append_log(self, message, level):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_entries.append({"timestamp": timestamp, "level": level.upper(), "message": message})
        self.apply_filter()

    def apply_filter(self):
        self.log_table.setRowCount(0)
        filter_level = self.filter_dropdown.currentText().upper()
        search_text = self.search_entry.text().lower()

        for entry in self.log_entries:
            if (filter_level == loc.get_string("all_levels").upper() or entry["level"] == filter_level) and \
               (not search_text or search_text in entry["message"].lower() or search_text in entry["level"].lower()):

                row_position = self.log_table.rowCount()
                self.log_table.insertRow(row_position)

                self.log_table.setItem(row_position, 0, QTableWidgetItem(entry["timestamp"]))
                level_item = QTableWidgetItem(entry["level"])

                if entry["level"] == "ERROR":
                    level_item.setForeground(QBrush(QColor(THEME_ERROR_RED)))
                elif entry["level"] == "WARNING":
                    level_item.setForeground(QBrush(QColor(THEME_WARNING_ORANGE)))
                elif entry["level"] == "INFO":
                    level_item.setForeground(QBrush(QColor(THEME_SUCCESS_GREEN)))

                self.log_table.setItem(row_position, 1, level_item)
                self.log_table.setItem(row_position, 2, QTableWidgetItem(entry["message"]))

        self.log_table.scrollToBottom()

    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, loc.get_string("export_logs"), "application_logs.txt", "Text Files (*.txt);;All Files (*.*)")
        if path:
            try:
                with open(path, 'w') as f:
                    for entry in self.log_entries:
                        f.write(f"[{entry['timestamp']}] [{entry['level']}] {entry['message']}\n")
                QMessageBox.information(self, "Export Complete", loc.get_string("log_exported_to", path=path))
            except Exception as e:
                QMessageBox.critical(self, "Export Error", loc.get_string("log_export_error", e=str(e)))
                logger.error(f"Error exporting logs: {e}")

    def show_context_menu(self, pos):
        pass

# --- NEW: Key Management Tab ---
class KeyManagementTab(BaseTab):
    def __init__(self, key_manager, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key_manager = key_manager
        self.setup_ui()
        self.retranslate_ui()
        self.load_keys()

    def setup_ui(self):
        self.key_table = QTableWidget()
        self.key_table.setColumnCount(4)
        self.key_table.setHorizontalHeaderLabels([loc.get_string("key_name"), loc.get_string("key_type"), loc.get_string("key_path"), loc.get_string("key_actions")])
        self.key_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.key_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.key_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.key_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.key_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.key_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.key_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.key_table.customContextMenuRequested.connect(self.show_context_menu)

        self.layout.addWidget(QLabel(loc.get_string("managed_keys")), 0, 0)
        self.layout.addWidget(self.key_table, 1, 0, 1, 1)
        self.layout.setRowStretch(2, 1)

    def retranslate_ui(self):
        pass

    def load_keys(self):
        self.key_table.setRowCount(0)
        for row, key_data in enumerate(self.key_manager.get_keys()):
            self.key_table.insertRow(row)
            self.key_table.setItem(row, 0, QTableWidgetItem(key_data.get("name", "N/A")))
            self.key_table.setItem(row, 1, QTableWidgetItem(key_data.get("type", "N/A")))
            self.key_table.setItem(row, 2, QTableWidgetItem(key_data.get("path", "N/A")))

    def show_context_menu(self, pos):
        item = self.key_table.itemAt(pos)
        if item:
            row = item.row()
            key_name = self.key_table.item(row, 0).text()
            key_data = self.key_manager.get_key_by_name(key_name)

            if key_data:
                menu = QMenu(self)
                view_action = QAction(loc.get_string("view_key"), self)
                export_action = QAction(loc.get_string("export_key"), self)
                delete_action = QAction(loc.get_string("delete_key"), self)

                view_action.triggered.connect(lambda: self.view_key(key_data))
                export_action.triggered.connect(lambda: self.export_key(key_data))
                delete_action.triggered.connect(lambda: self.delete_key(key_data))

                menu.addAction(view_action)
                menu.addAction(export_action)
                menu.addAction(delete_action)
                menu.exec(self.key_table.viewport().mapToGlobal(pos))

    def view_key(self, key_data):
        key_path = key_data.get("path")
        if not key_path or not os.path.exists(key_path):
            QMessageBox.warning(self, "Key Error", loc.get_string("key_load_error", e="File not found."))
            return
        try:
            with open(key_path, 'r') as f:
                content = f.read()
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(loc.get_string("key_view_title", name=key_data.get("name", "N/A")))
            msg_box.setText(content)
            msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg_box.exec()
        except Exception as e:
            QMessageBox.critical(self, "Key Error", loc.get_string("key_load_error", e=str(e)))
            logger.error(f"Error viewing key {key_data.get('name')}: {e}")

    def export_key(self, key_data):
        key_path = key_data.get("path")
        if not key_path or not os.path.exists(key_path):
            QMessageBox.warning(self, "Key Error", loc.get_string("key_load_error", e="File not found."))
            return

        if key_data.get("type") == "RSA":
            file_filter = "PEM Files (*.pem);;All Files (*.*)"
            default_extension = ".pem"
        elif key_data.get("type") == "Symmetric":
            file_filter = "Key Files (*.key);;Text Files (*.txt);;All Files (*.*)"
            default_extension = ".key"
        else:
            file_filter = "All Files (*.*)"
            default_extension = ""

        path, _ = QFileDialog.getSaveFileName(self, loc.get_string("export_key"), os.path.basename(key_path).replace(".pem", "").replace(".key", "") + default_extension, file_filter)
        if path:
            try:
                shutil.copy(key_path, path)
                self.main_window.show_status_message(loc.get_string("key_exported", name=key_data.get("name"), path=path), 5000)
            except Exception as e:
                QMessageBox.critical(self, loc.get_string("file_save_error"), str(e))
                logger.error(f"Error exporting key {key_data.get('name')}: {e}")

    def delete_key(self, key_data):
        reply = QMessageBox.question(self, "Confirm Delete",
                                     loc.get_string("confirm_delete_key", name=key_data.get("name")),
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            if self.key_manager.delete_key(key_data.get("name")):
                key_file_path = key_data.get("path")
                if key_file_path and os.path.exists(key_file_path):
                    try:
                        os.remove(key_file_path)
                        if key_data.get("type") == "RSA":
                            public_key_path = key_file_path.replace("_private.pem", "_public.pem")
                            if os.path.exists(public_key_path):
                                os.remove(public_key_path)
                        logger.info(f"Deleted key file(s): {key_file_path}")
                    except Exception as e:
                        logger.error(f"Error deleting key file {key_file_path}: {e}")
                self.load_keys()
                self.main_window.show_status_message(loc.get_string("key_deleted", name=key_data.get("name")), 3000)
            else:
                QMessageBox.warning(self, "Delete Failed", f"Could not delete key '{key_data.get('name')}'.")


# --- Main Application Class ---
class SatanEncryptorSuite(QMainWindow):
    log_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.app_settings = self.load_settings()
        self.plugin_manager = PluginManager(self.app_settings)
        self.key_manager = KeyManager()
        self.sidebar_width = 250
        self.is_sidebar_open = True

        self.setWindowTitle(APP_NAME)
        self.setGeometry(100, 100, 1000, 800)
        icon_path = os.path.join(ICON_FILENAME)
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            logger.warning(f"Application icon not found at {icon_path}. Using default icon.")

        self.setStatusBar(QStatusBar(self))

        self.configure_logging()
        self.create_widgets()
        self.apply_theme()
        self.apply_font(self.app_settings.get("font", "Segoe UI"))
        self.log_signal.connect(self.log_viewer.append_log)
        self.show_status_message(f"{APP_NAME} v{APP_VERSION} started.", 5000)

    def configure_logging(self):
        for handler in logger.handlers[:]:
            if isinstance(handler, RotatingFileHandler):
                logger.removeHandler(handler)

        max_size_mb = self.app_settings.get("max_log_size_mb", 5)
        enable_rotation = self.app_settings.get("enable_log_rotation", True)

        if enable_rotation:
            file_handler = RotatingFileHandler(LOG_FILE, maxBytes=max_size_mb * 1024 * 1024, backupCount=5)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logger.addHandler(file_handler)
            logger.info(f"Log rotation enabled: Max size {max_size_mb}MB.")
        else:
            logger.info("Log rotation disabled.")


    def create_widgets(self):
        main_container_widget = QWidget()
        main_container_layout = QVBoxLayout(main_container_widget)
        main_container_layout.setContentsMargins(0, 0, 0, 0)
        main_container_layout.setSpacing(0)
        self.setCentralWidget(main_container_widget)

        header_widget = QWidget()
        header_widget.setObjectName("HeaderWidget")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(15, 5, 15, 5)
        self.sidebar_toggle_button = QPushButton()
        self.sidebar_toggle_button.setObjectName("SidebarToggleButton")
        self.sidebar_toggle_button.setIcon(QIcon(QPixmap.fromImage(QImage.fromData(b64decode(SIDEBAR_TOGGLE_SVG.encode())))))
        self.sidebar_toggle_button.setFixedSize(40, 40)
        self.sidebar_toggle_button.setIconSize(QSize(24, 24))
        self.sidebar_toggle_button.clicked.connect(self.toggle_sidebar)
        header_layout.addWidget(self.sidebar_toggle_button)

        app_title_label = QLabel(APP_NAME)
        app_title_label.setObjectName("HeaderTitle")
        header_layout.addWidget(app_title_label)
        header_layout.addStretch(1)

        main_container_layout.addWidget(header_widget)

        content_area_widget = QWidget()
        content_area_widget.setObjectName("MainContentArea")
        content_area_layout = QHBoxLayout(content_area_widget)
        content_area_layout.setContentsMargins(0, 0, 0, 0)
        content_area_layout.setSpacing(0)

        self.sidebar_widget = QWidget()
        self.sidebar_widget.setObjectName("SidebarWidget")
        self.sidebar_widget.setFixedWidth(self.sidebar_width)
        sidebar_layout = QVBoxLayout(self.sidebar_widget)

        self.tab_buttons = []
        self.tab_widget = QTabWidget()
        
        # Corrected: Iterate through tabs to make them invisible instead of using the non-existent method
        self.tab_widget.setMovable(False)


        tab_names = [
            loc.get_string("encrypt_tab"),
            loc.get_string("decrypt_tab"),
            loc.get_string("generate_keys_tab"),
            loc.get_string("key_management_tab"),
            loc.get_string("plugins_tab"),
            loc.get_string("settings_tab"),
            loc.get_string("about_tab"),
            loc.get_string("whats_new_tab"),
        ]

        for i, name in enumerate(tab_names):
            button = QPushButton(name)
            button.setObjectName("SidebarButton")
            button.setCheckable(True)
            if i == 0:
                button.setChecked(True)
            button.clicked.connect(lambda _, index=i: self.switch_tab(index))
            sidebar_layout.addWidget(button)
            self.tab_buttons.append(button)
        sidebar_layout.addStretch(1)

        content_area_layout.addWidget(self.sidebar_widget)
        content_area_layout.addWidget(self.tab_widget)
        main_container_layout.addWidget(content_area_widget, 4)

        self.log_viewer = LogViewer()
        main_container_layout.addWidget(self.log_viewer, 1)

        self.encrypt_tab = EncryptTab(self.plugin_manager, self.app_settings, self)
        self.decrypt_tab = DecryptTab(self.plugin_manager, self.app_settings, self)
        self.generate_keys_tab = GenerateKeysTab(self.key_manager, self.plugin_manager, self.app_settings, self)
        self.plugins_tab = PluginsTab(self.plugin_manager, self.app_settings, self)
        self.settings_tab = SettingsTab(self.plugin_manager, self.app_settings, self)
        self.about_tab = AboutTab(self.plugin_manager, self.app_settings, self)
        self.whats_new_tab = WhatsNewTab(self.plugin_manager, self.app_settings, self)
        self.key_management_tab = KeyManagementTab(self.key_manager, self.plugin_manager, self.app_settings, self)

        self.tab_widget.addTab(self.encrypt_tab, loc.get_string("encrypt_tab"))
        self.tab_widget.addTab(self.decrypt_tab, loc.get_string("decrypt_tab"))
        self.tab_widget.addTab(self.generate_keys_tab, loc.get_string("generate_keys_tab"))
        self.tab_widget.addTab(self.key_management_tab, loc.get_string("key_management_tab"))
        self.tab_widget.addTab(self.plugins_tab, loc.get_string("plugins_tab"))
        self.tab_widget.addTab(self.settings_tab, loc.get_string("settings_tab"))
        self.tab_widget.addTab(self.about_tab, loc.get_string("about_tab"))
        self.tab_widget.addTab(self.whats_new_tab, loc.get_string("whats_new_tab"))

        # The correct way to hide all tabs
        for i in range(self.tab_widget.count()):
            self.tab_widget.setTabVisible(i, False)

        if default_output := self.app_settings.get("default_output_folder"):
            self.encrypt_tab.output_path_entry.setText(default_output)
            self.decrypt_tab.output_path_entry.setText(default_output)

    def switch_tab(self, index):
        self.tab_widget.setCurrentIndex(index)
        for i, button in enumerate(self.tab_buttons):
            button.setChecked(i == index)
    
    def toggle_sidebar(self):
        target_width = 0 if self.is_sidebar_open else self.sidebar_width
        start_width = self.sidebar_widget.width()

        self.animation = QPropertyAnimation(self.sidebar_widget, b"minimumWidth")
        self.animation.setDuration(300)
        self.animation.setStartValue(start_width)
        self.animation.setEndValue(target_width)
        self.animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.animation.start()

        self.is_sidebar_open = not self.is_sidebar_open

    def show_status_message(self, message, timeout=3000):
        self.statusBar().showMessage(message, timeout)

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load settings: {e}")
        return {
            "theme": "black_and_white",
            "enabled_plugins": {},
            "default_shredding_passes": 0,
            "font": "Segoe UI",
            "animation_speed": 5,
            "max_log_size_mb": 5,
            "enable_log_rotation": True,
            "default_output_folder": "",
            "default_encryption_algorithm": None,
            "confirm_on_exit": False
        }

    def save_settings(self):
        try:
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(self.app_settings, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")

    def apply_theme(self):
        self.setStyleSheet(BLACK_AND_WHITE_STYLESHEET)

    def apply_font(self, font_name):
        font = QFont(font_name)
        QApplication.setFont(font)

    def update_all_tabs_plugin_options(self):
        self.encrypt_tab.update_plugin_options()
        self.decrypt_tab.update_plugin_options()
        self.generate_keys_tab.update_plugin_options()
        self.settings_tab.update_default_encryption_algo_options()

    def copy_to_clipboard(self, text):
        if text:
            QGuiApplication.clipboard().setText(text)
            self.show_status_message(loc.get_string("copied_to_clipboard"), 2000)

    def closeEvent(self, event):
        if self.app_settings.get("confirm_on_exit", False):
            reply = QMessageBox.question(self, "Confirm Exit",
                                         "Are you sure you want to exit?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.save_settings()
                event.accept()
            else:
                event.ignore()
        else:
            self.save_settings()
            event.accept()


# --- NEW FEATURE 8: Command-Line Interface (CLI) ---
class CryptoCLI:
    def __init__(self, args):
        self.args = args
        self.plugin_manager = PluginManager({})
        self.key_manager = KeyManager()
        self.logger = logger

    def _derive_key(self, password, salt):
        return PBKDF2HMAC(hashes.SHA256(), 32, salt, 480000, backend=default_backend()).derive(password.encode())

    def _load_key_from_file(self, key_file_path):
        """Loads key material from a file (PEM for RSA, Base64 for symmetric)."""
        try:
            with open(key_file_path, 'rb') as f:
                key_data = f.read()
            if key_file_path.lower().endswith('.pem'):
                try:
                    private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
                    return private_key
                except ValueError as ve:
                    if "bad decrypt" in str(ve) or "Unsupported or incorrect encryption" in str(ve):
                        raise ValueError(f"Encrypted PEM key file '{os.path.basename(key_file_path)}' requires a password.")
                    else:
                        raise ValueError(f"Invalid PEM file format or corrupted: {ve}")
                except Exception as e:
                    try:
                        public_key = serialization.load_pem_public_key(key_data, backend=default_backend())
                        return public_key
                    except Exception as e:
                        raise ValueError(f"Invalid PEM file format: {e}")
            elif key_file_path.lower().endswith('.key'):
                return b64decode(key_data)
            else:
                raise ValueError("Unsupported key file extension. Use .pem or .key")
        except Exception as e:
            self.logger.error(f"Error loading key from file {key_file_path}: {e}")
            raise ValueError(f"Failed to load key from file: {e}")

    def _get_files_in_path(self, path):
        if os.path.isfile(path):
            return [path]
        elif os.path.isdir(path):
            file_list = []
            for root, _, files in os.walk(path):
                for file in files:
                    file_list.append(os.path.join(root, file))
            return file_list
        return []

    def _cli_encrypt(self):
        input_path = self.args.input
        output_path = self.args.output
        key_source = "password" if self.args.password else "file"
        password_or_key_file = self.args.password if self.args.password else self.args.key_file
        algo_name = self.args.algorithm
        compression_algo = getattr(self.args, 'compression', loc.get_string("no_compression"))
        compression_level = getattr(self.args, 'compression_level', -1)
        perform_checksum = getattr(self.args, 'checksum', False)
        delete_original = getattr(self.args, 'delete_original', False)
        secure_shredding_passes = getattr(self.args, 'shred_passes', 0)

        files_to_process = self._get_files_in_path(input_path)
        total_files = len(files_to_process)
        successful_count = 0

        if total_files == 0:
            self.logger.info("No files found to encrypt.")
            print("No files found to encrypt.")
            return

        encryption_key_material = None
        if key_source == "file":
            try:
                encryption_key_material = self._load_key_from_file(password_or_key_file)
                if isinstance(encryption_key_material, rsa.RSAPrivateKey):
                    encryption_key_material = encryption_key_material.public_key()
                elif not isinstance(encryption_key_material, bytes):
                    raise ValueError("Unsupported key file type for encryption.")
            except ValueError as e:
                self.logger.error(f"CLI Encryption Error: {e}")
                print(f"CLI Encryption Error: {e}")
                return

        self.logger.info(f"Starting encryption of {total_files} file(s)...")
        print(f"Starting encryption of {total_files} file(s)...")

        for i, file_path in enumerate(files_to_process):
            self.logger.info(f"Processing ({i+1}/{total_files}): {os.path.basename(file_path)}")
            print(f"Processing ({i+1}/{total_files}): {os.path.basename(file_path)}")
            try:
                relative_path_part = os.path.relpath(file_path, input_path)
                relative_dir = os.path.dirname(relative_path_part)

                output_dir = os.path.join(output_path, relative_dir)
                os.makedirs(output_dir, exist_ok=True)
                final_output_path = os.path.join(output_dir, os.path.basename(file_path) + ".enc")

                with open(file_path, 'rb') as f:
                    plaintext = f.read()

                original_checksum = None
                if perform_checksum:
                    original_checksum = hashlib.sha256(plaintext).hexdigest()
                    self.logger.info(f"Generated checksum for {os.path.basename(file_path)}: {original_checksum}")

                compressed_data = plaintext
                if compression_algo != loc.get_string("no_compression"):
                    temp_compressed_path = file_path + ".comp_temp"
                    if compress_file(file_path, temp_compressed_path, compression_algo, compression_level):
                        with open(temp_compressed_path, 'rb') as f_comp:
                            compressed_data = f_comp.read()
                        os.remove(temp_compressed_path)
                    else:
                        raise Exception("Compression failed.")

                salt_b64 = None
                iv_b64 = None
                tag_b64 = None
                encrypted_data = None
                key_type_meta = "symmetric"
                key_path_meta = None

                if key_source == "password":
                    salt = os.urandom(16)
                    key = self._derive_key(password_or_key_file, salt)
                    iv = os.urandom(12)
                    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
                    encrypted_data = encryptor.update(compressed_data) + encryptor.finalize()
                    salt_b64 = b64encode(salt).decode()
                    iv_b64 = b64encode(iv).decode()
                    tag_b64 = b64encode(encryptor.tag).decode()
                else:
                    key_path_meta = password_or_key_file
                    if isinstance(encryption_key_material, rsa.RSAPublicKey):
                        key_type_meta = "rsa"
                        symmetric_key_for_file = os.urandom(32)
                        rsa_encrypted_symmetric_key = encryption_key_material.encrypt(
                            symmetric_key_for_file,
                            rsa_padding.OAEP(
                                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        iv = os.urandom(12)
                        encryptor = Cipher(algorithms.AES(symmetric_key_for_file), modes.GCM(iv), backend=default_backend()).encryptor()
                        encrypted_data = encryptor.update(compressed_data) + encryptor.finalize()
                        iv_b64 = b64encode(iv).decode()
                        tag_b64 = b64encode(encryptor.tag).decode()
                        salt_b64 = b64encode(rsa_encrypted_symmetric_key).decode()

                    elif isinstance(encryption_key_material, bytes):
                        iv = os.urandom(12)
                        encryptor = Cipher(algorithms.AES(encryption_key_material), modes.GCM(iv), backend=default_backend()).encryptor()
                        encrypted_data = encryptor.update(compressed_data) + encryptor.finalize()
                        iv_b64 = b64encode(iv).decode()
                        tag_b64 = b64encode(encryptor.tag).decode()
                        salt_b64 = None
                    else:
                        raise ValueError("Invalid key material from file.")

                with open(final_output_path, 'wb') as f:
                    f.write(encrypted_data)

                meta = {
                    'algorithm': algo_name,
                    'salt': salt_b64,
                    'iv': iv_b64,
                    'tag': tag_b64,
                    'compression': compression_algo if compression_algo != loc.get_string("no_compression") else None,
                    'original_checksum': original_checksum,
                    'key_source': key_source,
                    'key_path': key_path_meta
                }
                with open(final_output_path + '.meta', 'w') as f:
                    json.dump(meta, f, indent=4)

                if delete_original:
                    self.logger.info(loc.get_string("file_shredding"))
                    print(loc.get_string("file_shredding"))
                    if secure_shredding_passes > 0:
                        secure_delete_file(file_path, secure_shredding_passes)
                    else:
                        os.remove(file_path)
                    self.logger.info(loc.get_string("shredding_complete"))
                    print(loc.get_string("shredding_complete"))

                successful_count += 1
                self.logger.info(f"Successfully encrypted: {os.path.basename(file_path)}")
                print(f"Encrypted: {os.path.basename(file_path)}")

            except Exception as e:
                self.logger.error(f"Error encrypting {os.path.basename(file_path)}: {e}")
                print(f"Error encrypting {os.path.basename(file_path)}: {e}")
        self.logger.info(f"Encryption finished. Successfully encrypted {successful_count}/{total_files} files.")
        print(f"Encryption finished. Successfully encrypted {successful_count}/{total_files} files.")


    def _cli_decrypt(self):
        input_path = self.args.input
        output_path = self.args.output
        key_source = "password" if self.args.password else "file"
        password_or_key_file = self.args.password if self.args.password else self.args.key_file

        files_to_process = [f for f in self._get_files_in_path(input_path) if f.endswith('.enc')]
        total_files = len(files_to_process)
        successful_count = 0

        if total_files == 0:
            self.logger.info("No encrypted files found to decrypt.")
            print("No encrypted files found to decrypt.")
            return

        decryption_key_material = None
        if key_source == "file":
            try:
                decryption_key_material = self._load_key_from_file(password_or_key_file)
            except ValueError as e:
                self.logger.error(f"CLI Decryption Error: {e}")
                print(f"CLI Decryption Error: {e}")
                return

        self.logger.info(f"Starting decryption of {total_files} file(s)...")
        print(f"Starting decryption of {total_files} file(s)...")

        for i, file_path in enumerate(files_to_process):
            self.logger.info(f"Processing ({i+1}/{total_files}): {os.path.basename(file_path)}")
            print(f"Processing ({i+1}/{total_files}): {os.path.basename(file_path)}")
            meta_path = file_path + '.meta'
            if not os.path.exists(meta_path):
                self.logger.warning(f"Metadata file not found for {os.path.basename(file_path)}. Skipping.")
                print(f"Warning: Metadata file not found for {os.path.basename(file_path)}. Skipping.")
                continue

            try:
                with open(meta_path, 'r') as f:
                    meta = json.load(f)

                salt_b64 = meta.get('salt')
                iv_b64 = meta['iv']
                tag_b64 = meta['tag']
                compression_algo_meta = meta.get('compression')
                original_checksum_meta = meta.get('original_checksum')
                key_source_meta = meta.get('key_source', 'password')

                decryption_key = None

                if key_source_meta == "password":
                    if not password_or_key_file:
                        raise ValueError("Password not provided for decryption.")
                    salt = b64decode(salt_b64)
                    decryption_key = self._derive_key(password_or_key_file, salt)
                elif key_source_meta == "file":
                    if not decryption_key_material:
                        raise ValueError("Key file not provided or invalid for decryption.")

                    if isinstance(decryption_key_material, rsa.RSAPrivateKey):
                        rsa_encrypted_symmetric_key = b64decode(salt_b64)
                        symmetric_key_for_file = decryption_key_material.decrypt(
                            rsa_encrypted_symmetric_key,
                            rsa_padding.OAEP(
                                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        decryption_key = symmetric_key_for_file
                    elif isinstance(decryption_key_material, bytes):
                        decryption_key = decryption_key_material
                    else:
                        raise ValueError("Invalid key material type for decryption.")

                if decryption_key is None:
                    raise ValueError("Could not determine decryption key.")

                with open(file_path, 'rb') as f:
                    ciphertext = f.read()

                try:
                    iv = b64decode(iv_b64)
                    tag = b64decode(tag_b64)
                    decryptor = Cipher(algorithms.AES(decryption_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
                    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                except InvalidTag:
                    raise ValueError("Invalid password or corrupted file.")

                decompressed_data = decrypted_data
                if compression_algo_meta:
                    temp_decompressed_path = file_path.replace(".enc", "") + ".decomp_temp"
                    with open(temp_decompressed_path, 'wb') as f_temp:
                        f_temp.write(decrypted_data)

                    if decompress_file(temp_decompressed_path, temp_decompressed_path + ".final", compression_algo_meta):
                        with open(temp_decompressed_path + ".final", 'rb') as f_decomp:
                            decompressed_data = f_decomp.read()
                        os.remove(temp_decompressed_path)
                        os.remove(temp_decompressed_path + ".final")
                    else:
                        os.remove(temp_decompressed_path)
                        raise Exception("Decompression failed.")

                relative_path_part = os.path.relpath(file_path, input_path)
                relative_dir = os.path.dirname(relative_path_part)

                output_dir = os.path.join(output_path, relative_dir)
                os.makedirs(output_dir, exist_ok=True)
                final_output_path = os.path.join(output_dir, os.path.basename(file_path).replace(".enc", ""))

                with open(final_output_path, 'wb') as f:
                    f.write(decompressed_data)

                if original_checksum_meta:
                    current_checksum = hashlib.sha256(decompressed_data).hexdigest()
                    if current_checksum == original_checksum_meta:
                        self.logger.info(f"Checksum verified for {os.path.basename(file_path)}.")
                        print(f"Checksum verified for {os.path.basename(file_path)}.")
                    else:
                        self.logger.warning(f"Checksum mismatch for {os.path.basename(file_path)}! File may be corrupted.")
                        print(f"WARNING: Checksum mismatch for {os.path.basename(file_path)}! File may be corrupted.")

                successful_count += 1
                self.logger.info(f"Successfully decrypted: {os.path.basename(file_path)}")
                print(f"Decrypted: {os.path.basename(file_path)}")

            except Exception as e:
                self.logger.error(f"Error decrypting {os.path.basename(file_path)}: {e}")
                print(f"Error decrypting {os.path.basename(file_path)}: {e}")
        self.logger.info(f"Decryption finished. Successfully decrypted {successful_count}/{total_files} files.")
        print(f"Decryption finished. Successfully decrypted {successful_count}/{total_files} files.")


    def _cli_gen_rsa(self):
        output_path = self.args.output
        password = self.args.password.encode() if self.args.password else None
        enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()

        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            private_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc_algo)
            public_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

            private_key_file = os.path.join(output_path, "private_key.pem")
            public_key_file = os.path.join(output_path, "public_key.pem")

            with open(private_key_file, 'wb') as f:
                f.write(private_pem)
            with open(public_key_file, 'wb') as f:
                f.write(public_pem)

            self.logger.info(f"RSA key pair generated successfully:")
            self.logger.info(f"  Private Key: {private_key_file}")
            self.logger.info(f"  Public Key: {public_key_file}")
            print(f"RSA key pair generated successfully:")
            print(f"  Private Key: {private_key_file}")
            print(f"  Public Key: {public_key_file}")
            self.key_manager.add_key(f"CLI_Generated_RSA_{int(time.time())}", "RSA", private_key_file)

        except Exception as e:
            self.logger.error(f"Error generating RSA keys: {e}")
            print(f"Error generating RSA keys: {e}")

    def run(self):
        if self.args.action == 'encrypt':
            self._cli_encrypt()
        elif self.args.action == 'decrypt':
            self._cli_decrypt()
        elif self.args.action == 'gen-rsa':
            self._cli_gen_rsa()
        else:
            self.logger.error("Unknown CLI action.")
            print("Unknown CLI action.")


def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} CLI")
    subparsers = parser.add_subparsers(dest='action', help='CLI action')

    p_encrypt = subparsers.add_parser('encrypt', help='Encrypt files/folders')
    p_encrypt.add_argument('-i', '--input', required=True, help='Input file or folder path')
    p_encrypt.add_argument('-o', '--output', required=True, help='Output folder path')
    p_encrypt.add_argument('-a', '--algorithm', required=True, help='Encryption algorithm (e.g., AES)')
    p_encrypt.add_argument('-c', '--compression', choices=['Gzip', 'Bzip2', 'LZMA', 'No Compression'], default='No Compression', help='Compression algorithm')
    p_encrypt.add_argument('-l', '--compression-level', type=int, default=-1, help='Compression level (-1 for default, 1-9)')
    p_encrypt.add_argument('--checksum', action='store_true', help='Generate SHA-256 checksum for integrity check')
    p_encrypt.add_argument('--delete-original', action='store_true', help='Delete original file after encryption')
    p_encrypt.add_argument('--shred-passes', type=int, default=0, help='Number of passes for secure file shredding (0 for regular delete)')
    encrypt_key_group = p_encrypt.add_mutually_exclusive_group(required=True)
    encrypt_key_group.add_argument('--password', help='Password for encryption')
    encrypt_key_group.add_argument('--key-file', help='Path to key file for encryption')


    p_decrypt = subparsers.add_parser('decrypt', help='Decrypt files/folders')
    p_decrypt.add_argument('-i', '--input', required=True, help='Input encrypted file or folder path')
    p_decrypt.add_argument('-o', '--output', required=True, help='Output folder path')
    decrypt_key_group = p_decrypt.add_mutually_exclusive_group(required=True)
    decrypt_key_group.add_argument('--password', help='Password for decryption')
    decrypt_key_group.add_argument('--key-file', help='Path to key file for decryption')

    p_keygen = subparsers.add_parser('gen-rsa', help='Generate RSA key pair')
    p_keygen.add_argument('-o', '--output', required=True, help='Output folder for keys')
    p_keygen.add_argument('-p', '--password', help='Optional password to encrypt the private key')

    if len(sys.argv) > 1 and sys.argv[1] in ['encrypt', 'decrypt', 'gen-rsa']:
        CryptoCLI(parser.parse_args()).run()
        sys.exit(0)

    app = QApplication(sys.argv)

    temp_settings = {}
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                temp_settings = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load settings for GUI startup: {e}")

    initial_font_name = temp_settings.get("font", "Segoe UI")
    QApplication.setFont(QFont(initial_font_name))

    # A check for the assets directory and logo file.
    os.makedirs(ASSETS_DIR, exist_ok=True)
    if not os.path.exists(os.path.join(ASSETS_DIR, SATAN_LOGO_FILENAME)):
        # You'll need to create a satan_logo.png file in the 'assets' folder for the logo to appear.
        logger.warning(f"Satan logo not found at {os.path.join(ASSETS_DIR, SATAN_LOGO_FILENAME)}. Please add it to the assets folder.")

    main_win = SatanEncryptorSuite()
    main_win.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
