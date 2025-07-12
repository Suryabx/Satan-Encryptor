# Satan Encryptor Suite

A professional, plugin-based Python application for secure file encryption and decryption with a modern UI (customtkinter).

## Features
- AES-256, Fernet, and RSA encryption (plugin-based, easily extensible)
- File/folder encryption & decryption
- Secure key generation
- Password strength meter
- Settings, logging, and theme support

## Quick Start
```bash
# Clone and enter the project
git clone https://github.com/Suryabx/SatanEncryptorSuite.git
cd SatanEncryptorSuite

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install customtkinter cryptography Pillow

# Run the app
python satan_encryptor_suite.py
```

## Plugins
- Add new algorithms by placing a `_plugin.py` file in the `plugins/` folder implementing `EncryptorPlugin`.
- Example plugins: `fernet_plugin.py`, `aes_plugin.py`, `rsa_plugin.py`.

## File Structure
```
YourProjectFolder/
├── satan_encryptor_suite.py
├── installer_script.nsi  <-- NSIS script should be here
├── assets/
│   └── icon.png
│   └── icon.ico          <-- This is where icon.ico should be
├── plugins/
│   └── ...
├── languages/
│   └── ...
└── dist/                 <-- PyInstaller output folder
    └── Satan Encryptor Suite/
        └── Satan Encryptor Suite.exe
        └── assets/
        └── plugins/
        └── languages/
        └── ...
```

## Security Notes
- Use strong, unique passwords/keys
- Store keys securely; losing them means losing access
- For critical data, use professional-grade solutions

## Build Executable (Windows)
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --icon=assets/icon.png --add-data "plugins;plugins" --add-data "assets;assets" satan_encryptor_suite.py
```

## License
MIT. See `LICENSE` file.
