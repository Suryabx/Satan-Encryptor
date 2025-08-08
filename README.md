#  Satan Encryptor Suite

**A professional, plugin-based Python application for secure file encryption and decryption with a modern PyQt6 UI.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-informational)

---

## ✨ Features

- 🔒 AES-256, Fernet, and RSA encryption (plugin-based & easily extensible)
- 📁 File/folder encryption & decryption with drag and drop support
- 🔑 Secure key generation (symmetric and RSA key pairs)
- 🧾 Automatic metadata files (settings saved with encrypted files)
- 📂 Key file support for encryption/decryption (RSA key pairs or symmetric keys)
- 🗝️ Improved Key Management tab (view, export, delete keys)
- 📦 Compression support: Gzip, Bzip2, LZMA
- 🧨 Secure file shredding (overwrite files multiple times)
- ✅ File integrity check using SHA-256
- 💻 CLI support for automated encryption tasks
- 🔐 Password strength meter
- ⚙️ Comprehensive settings, advanced logging viewer, theme support
- 🆕 Dedicated "What's New" tab to highlight recent updates


## 🚀 Quick Start

### 1. Clone and Enter the Project

```bash
git clone https://github.com/Suryabx/SatanEncryptorSuite.git
cd SatanEncryptorSuite


```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

## 2. Create and Activate a Virtual Environment ##
-  On Windows (CMD or PowerShell)

```
python3 -m venv .venv
.venv\Scripts\activate
```
## On Linux / macOS (bash or zsh) ##

```
python3 -m venv .venv
source .venv/bin/activate

```
You’ll see your terminal prompt change to (.venv) — this means the virtual environment is active.

## To Deactivate the Virtual Environment (All Platforms) ##

```
deactivate
```

This exits the virtual environment and returns to the system Python environment.

## Install Dependencies ##

```
pip install PyQt6 cryptography Pillow
```

 PyQt6 includes PyQt6-Qt6, PyQt6-sip. Pillow is for image handling.
 
 ## Run the Application ##

 ```
 python satan_encryptor.py

```
### Plugins ###
- You can easily extend Satan Encryptor Suite by adding new encryption algorithms.

### Adding New Plugins ###
- Add a _plugin.py file to the plugins/ directory.
- The plugin must implement the EncryptorPlugin interface.

## Example Plugins ##
- fernet_plugin.py
- aes_plugin.py
- rsa_plugin.py

## Project Structure ##

```
SatanEncryptor/
├── satan_encryptor_suite.py
├── installer_script.nsi         # NSIS installer script
├── assets/
│   ├── icon.png
│   └── icon.ico
├── plugins/
│   └── *.py (encryption plugins)
├── languages/
│   └── ...
└── dist/
    └── Satan Encryptor Suite/
        ├── Satan Encryptor Suite.exe
        ├── assets/
        ├── plugins/
        └── languages/
```

## Security Notes ##
- Best practices when using encryption tools:
- Use strong and unique passwords/keys
- Store keys in a secure location
- Losing the key = losing access to your files
- For highly sensitive data, consider using additional security layers

## Building Windows Executable ##
- Create a standalone .exe using PyInstaller:

```
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --icon=assets/icon.png \
  --add-data "plugins;plugins" --add-data "assets;assets" satan_encryptor_suite.py
```

- The output .exe will be in the dist/ directory.
- Ensure all required folders (plugins, assets) are included.

## License ##
-This project is licensed under the MIT License.
-See the LICENSE file for full license details.
