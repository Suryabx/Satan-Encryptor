# Satan Encryptor Suite

A simple yet powerful encryption application built with Python's tkinter library. This version provides core encryption functionality with a plugin-based architecture while using only standard library components.

## Features

### 🔒 Core Encryption
- **Plugin-based architecture** for easy expansion
- **Multiple encryption algorithms** (AES-256*, XOR, ROT13)
- **File and folder encryption** support
- **Secure key generation**
- **Password strength meter**

### 🎨 User Interface
- **Tabbed interface** with dedicated sections
- **Drag & drop file selection**
- **Real-time progress tracking**
- **Activity logging**
- **Settings management**

### 🛠️ Advanced Features
- **Settings export/import**
- **Activity log export**
- **Recent files tracking**
- **Backup creation**
- **Multi-language support** (framework ready)

## Installation

### Basic Installation (Standard Library Only)
```bash
# Clone or download the files
python main.py
```

### Enhanced Installation (with AES-256 support)
```bash
# Install cryptography for AES-256 encryption
pip install cryptography

# Run the application
python main.py
```

## Usage

### Encrypting Files
1. Go to the **🔒 Encrypt** tab
2. Click "Select Files" or "Select Folder"
3. Choose your encryption algorithm
4. Enter a strong password
5. Click "🔒 Encrypt Files"

### Decrypting Files
1. Go to the **🔓 Decrypt** tab
2. Select encrypted files (.enc extension)
3. Choose the same algorithm used for encryption
4. Enter the correct password
5. Click "🔓 Decrypt Files"

### Generating Secure Keys/Passwords
1. Go to the **🔑 Generate** tab
2. Select algorithm for key generation
3. Adjust password length as needed
4. Click generate buttons

## Plugin System

The application uses a modular plugin system for encryption algorithms:

### Available Plugins
- **AES-256**: Advanced Encryption Standard (requires cryptography library)
- **XOR Cipher**: Simple XOR encryption (demo/educational)
- **ROT13**: Caesar cipher variant (demo/educational)

### Adding New Plugins
Create a new plugin class in `encryption_plugins.py`:

```python
class MyCustomPlugin(EncryptionPlugin):
    def __init__(self):
        super().__init__("custom", "My Custom Cipher", "Description", 256)
    
    def encrypt(self, data, password):
        # Your encryption logic
        pass
    
    def decrypt(self, encrypted_data, password):
        # Your decryption logic
        pass
    
    def generate_key(self):
        # Your key generation logic
        pass
```

## File Structure

```
satan-encryptor-suite/
├── main.py                 # Main application entry point
├── encryption_plugins.py   # Plugin system and encryption algorithms
├── crypto_utils.py        # Cryptographic utilities
├── file_handler.py        # File operations
├── logger.py              # Activity logging
├── settings_manager.py    # Settings management
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Security Notes

⚠️ **Important Security Information:**

1. **AES-256 Plugin**: Uses industry-standard encryption (requires cryptography library)
2. **XOR/ROT13 Plugins**: For demonstration only - NOT secure for real data
3. **Password Security**: Use strong, unique passwords for each encryption
4. **Key Storage**: Generated keys should be stored securely
5. **Backup**: Always backup important data before encryption

## Configuration

Settings are stored in `settings.json` and include:
- Theme preferences
- Default encryption algorithm
- Auto-backup options
- Log retention settings
- UI preferences

## Logging

All activities are logged with timestamps:
- File operations
- Encryption/decryption events
- Errors and warnings
- Settings changes

Logs can be exported for audit purposes.

## Development

### Developer Information
- **Created by**: Surya B
- **GitHub**: https://github.com/Suryabx
- **License**: MIT
- **Version**: 1.0.0

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add your encryption plugin or enhancement
4. Test thoroughly
5. Submit a pull request

### Building Executable (Optional)
```bash
# Install PyInstaller
pip install pyinstaller

# Create executable
pyinstaller --onefile --windowed main.py
```

## Limitations

This basic tkinter version has some limitations compared to a full desktop application:
- Basic UI styling (no glassmorphic effects)
- Limited theme options
- No advanced animations
- Standard tkinter widgets only

For a more modern UI, consider upgrading to:
- CustomTkinter
- PyQt/PySide
- Kivy
- Web-based interface (Electron)

## Troubleshooting

### Common Issues

1. **"AES plugin disabled" warning**
   - Install cryptography: `pip install cryptography`

2. **File permission errors**
   - Run as administrator (Windows) or with sudo (Linux/Mac)
   - Check file permissions

3. **Decryption fails**
   - Verify correct password
   - Ensure same algorithm was used for encryption
   - Check if file is corrupted

### Getting Help
- Check the activity log for error details
- Ensure all dependencies are installed
- Verify file paths and permissions

## License

MIT License - see the application's About tab for full details.

---

**Note**: This is a basic implementation using Python's standard library. For production use with sensitive data, consider using the enhanced version with proper cryptographic libraries and additional security measures.
