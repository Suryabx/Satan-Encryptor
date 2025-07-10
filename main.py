#!/usr/bin/env python3
"""
Satan Encryptor Suite - Basic Tkinter Version
A simple encryption application with plugin-based architecture
Developer: Surya B (https://github.com/Suryabx)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import json
import threading
from datetime import datetime
import webbrowser

# Import our modules
from encryption_plugins import PluginManager
from crypto_utils import CryptoUtils
from file_handler import FileHandler
from logger import Logger
from settings_manager import SettingsManager

class SatanEncryptorSuite:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Satan Encryptor Suite v1.0.0")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Initialize components
        self.plugin_manager = PluginManager()
        self.crypto_utils = CryptoUtils()
        self.file_handler = FileHandler()
        self.logger = Logger()
        self.settings_manager = SettingsManager()
        
        # Variables
        self.selected_files = []
        self.current_plugin = tk.StringVar(value="aes256")
        self.password_var = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        
        # Setup UI
        self.setup_ui()
        self.load_settings()
        
        # Log startup
        self.logger.log("Application Started", "Satan Encryptor Suite initialized successfully")
        
    def setup_ui(self):
        """Setup the main user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_generate_tab()
        self.create_plugins_tab()
        self.create_settings_tab()
        self.create_about_tab()
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def create_encrypt_tab(self):
        """Create the encryption tab"""
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="🔒 Encrypt")
        
        # File selection
        file_frame = ttk.LabelFrame(encrypt_frame, text="File Selection")
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(file_frame, text="Select Files", 
                  command=self.select_files).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(file_frame, text="Select Folder", 
                  command=self.select_folder).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(file_frame, text="Clear Selection", 
                  command=self.clear_selection).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Selected files list
        self.files_listbox = tk.Listbox(encrypt_frame, height=6)
        self.files_listbox.pack(fill=tk.X, padx=10, pady=5)
        
        # Encryption settings
        settings_frame = ttk.LabelFrame(encrypt_frame, text="Encryption Settings")
        settings_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Plugin selection
        ttk.Label(settings_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        plugin_combo = ttk.Combobox(settings_frame, textvariable=self.current_plugin, 
                                   values=list(self.plugin_manager.get_plugin_names()))
        plugin_combo.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        plugin_combo.state(['readonly'])
        
        # Password
        ttk.Label(settings_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.password_entry = ttk.Entry(settings_frame, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        self.password_entry.bind('<KeyRelease>', self.update_password_strength)
        
        # Password strength
        self.strength_label = ttk.Label(settings_frame, text="Password Strength: ")
        self.strength_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        
        settings_frame.columnconfigure(1, weight=1)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(encrypt_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Encrypt button
        ttk.Button(encrypt_frame, text="🔒 Encrypt Files", 
                  command=self.encrypt_files).pack(pady=10)
        
        # Log viewer
        log_frame = ttk.LabelFrame(encrypt_frame, text="Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def create_decrypt_tab(self):
        """Create the decryption tab"""
        decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(decrypt_frame, text="🔓 Decrypt")
        
        # Similar structure to encrypt tab but for decryption
        file_frame = ttk.LabelFrame(decrypt_frame, text="Encrypted File Selection")
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(file_frame, text="Select Encrypted Files", 
                  command=self.select_encrypted_files).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(file_frame, text="Clear Selection", 
                  command=self.clear_decrypt_selection).pack(side=tk.LEFT, padx=5, pady=5)
        
        self.decrypt_files_listbox = tk.Listbox(decrypt_frame, height=6)
        self.decrypt_files_listbox.pack(fill=tk.X, padx=10, pady=5)
        
        # Decryption settings
        decrypt_settings_frame = ttk.LabelFrame(decrypt_frame, text="Decryption Settings")
        decrypt_settings_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(decrypt_settings_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.decrypt_plugin_var = tk.StringVar(value="aes256")
        decrypt_plugin_combo = ttk.Combobox(decrypt_settings_frame, textvariable=self.decrypt_plugin_var,
                                           values=list(self.plugin_manager.get_plugin_names()))
        decrypt_plugin_combo.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        decrypt_plugin_combo.state(['readonly'])
        
        ttk.Label(decrypt_settings_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.decrypt_password_var = tk.StringVar()
        ttk.Entry(decrypt_settings_frame, textvariable=self.decrypt_password_var, show="*").grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        
        decrypt_settings_frame.columnconfigure(1, weight=1)
        
        # Decrypt button
        ttk.Button(decrypt_frame, text="🔓 Decrypt Files", 
                  command=self.decrypt_files).pack(pady=10)
        
    def create_generate_tab(self):
        """Create the key generation tab"""
        generate_frame = ttk.Frame(self.notebook)
        self.notebook.add(generate_frame, text="🔑 Generate")
        
        # Key generation
        key_frame = ttk.LabelFrame(generate_frame, text="Key Generation")
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(key_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.gen_plugin_var = tk.StringVar(value="aes256")
        ttk.Combobox(key_frame, textvariable=self.gen_plugin_var,
                    values=list(self.plugin_manager.get_plugin_names())).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        ttk.Button(key_frame, text="Generate Key", 
                  command=self.generate_key).pack(pady=5)
        
        self.generated_key_text = scrolledtext.ScrolledText(key_frame, height=4)
        self.generated_key_text.pack(fill=tk.X, padx=5, pady=5)
        
        key_frame.columnconfigure(1, weight=1)
        
        # Password generation
        password_frame = ttk.LabelFrame(generate_frame, text="Password Generation")
        password_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(password_frame, text="Length:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.password_length_var = tk.IntVar(value=16)
        ttk.Scale(password_frame, from_=8, to=64, variable=self.password_length_var, 
                 orient=tk.HORIZONTAL).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        length_label = ttk.Label(password_frame, text="16")
        length_label.grid(row=0, column=2, padx=5, pady=2)
        
        def update_length_label(*args):
            length_label.config(text=str(self.password_length_var.get()))
        self.password_length_var.trace('w', update_length_label)
        
        ttk.Button(password_frame, text="Generate Password", 
                  command=self.generate_password).pack(pady=5)
        
        self.generated_password_text = scrolledtext.ScrolledText(password_frame, height=3)
        self.generated_password_text.pack(fill=tk.X, padx=5, pady=5)
        
        password_frame.columnconfigure(1, weight=1)
        
    def create_plugins_tab(self):
        """Create the plugins management tab"""
        plugins_frame = ttk.Frame(self.notebook)
        self.notebook.add(plugins_frame, text="🧩 Plugins")
        
        ttk.Label(plugins_frame, text="Available Encryption Plugins", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Plugin list
        for plugin_name in self.plugin_manager.get_plugin_names():
            plugin = self.plugin_manager.get_plugin(plugin_name)
            
            plugin_frame = ttk.LabelFrame(plugins_frame, text=plugin.display_name)
            plugin_frame.pack(fill=tk.X, padx=10, pady=5)
            
            ttk.Label(plugin_frame, text=f"Description: {plugin.description}").pack(anchor=tk.W, padx=5)
            ttk.Label(plugin_frame, text=f"Key Size: {plugin.key_size} bits").pack(anchor=tk.W, padx=5)
            ttk.Label(plugin_frame, text="Status: Active", foreground="green").pack(anchor=tk.W, padx=5)
            
    def create_settings_tab(self):
        """Create the settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Appearance settings
        appearance_frame = ttk.LabelFrame(settings_frame, text="Appearance")
        appearance_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.theme_var = tk.StringVar(value="default")
        ttk.Label(appearance_frame, text="Theme:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Combobox(appearance_frame, textvariable=self.theme_var,
                    values=["default", "dark", "light"]).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # Behavior settings
        behavior_frame = ttk.LabelFrame(settings_frame, text="Behavior")
        behavior_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.auto_clear_logs_var = tk.BooleanVar()
        ttk.Checkbutton(behavior_frame, text="Auto-clear logs on startup", 
                       variable=self.auto_clear_logs_var).pack(anchor=tk.W, padx=5, pady=2)
        
        self.confirm_overwrite_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(behavior_frame, text="Confirm file overwrite", 
                       variable=self.confirm_overwrite_var).pack(anchor=tk.W, padx=5, pady=2)
        
        # Data management
        data_frame = ttk.LabelFrame(settings_frame, text="Data Management")
        data_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(data_frame, text="Export Settings", 
                  command=self.export_settings).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(data_frame, text="Import Settings", 
                  command=self.import_settings).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(data_frame, text="Clear Logs", 
                  command=self.clear_logs).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Save settings button
        ttk.Button(settings_frame, text="Save Settings", 
                  command=self.save_settings).pack(pady=10)
        
    def create_about_tab(self):
        """Create the about tab"""
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="ℹ️ About")
        
        # App info
        info_frame = ttk.LabelFrame(about_frame, text="Application Information")
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text="Satan Encryptor Suite", 
                 font=('Arial', 16, 'bold')).pack(pady=5)
        ttk.Label(info_frame, text="Modern Encryption Application").pack()
        ttk.Label(info_frame, text="Version: 1.0.0").pack()
        ttk.Label(info_frame, text="License: MIT").pack()
        
        # Developer info
        dev_frame = ttk.LabelFrame(about_frame, text="Developer")
        dev_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(dev_frame, text="Surya B", font=('Arial', 12, 'bold')).pack()
        ttk.Label(dev_frame, text="Software Developer").pack()
        
        ttk.Button(dev_frame, text="🔗 View GitHub Profile", 
                  command=self.open_github).pack(pady=5)
        
        # Features
        features_frame = ttk.LabelFrame(about_frame, text="Features")
        features_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        features_text = scrolledtext.ScrolledText(features_frame, height=10, state=tk.DISABLED)
        features_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        features_content = """
• Plugin-based encryption system
• Multiple encryption algorithms (AES-256, ChaCha20, etc.)
• File and folder encryption support
• Secure key generation
• Password strength meter
• Activity logging
• Settings export/import
• Cross-platform compatibility
• No server communication - all local
• Open source (MIT License)
        """
        
        features_text.config(state=tk.NORMAL)
        features_text.insert(tk.END, features_content)
        features_text.config(state=tk.DISABLED)
        
    # Event handlers
    def select_files(self):
        """Select files for encryption"""
        files = filedialog.askopenfilenames(
            title="Select files to encrypt",
            filetypes=[("All files", "*.*")]
        )
        self.selected_files.extend(files)
        self.update_files_listbox()
        self.logger.log("Files Selected", f"Added {len(files)} files for encryption")
        
    def select_folder(self):
        """Select folder for encryption"""
        folder = filedialog.askdirectory(title="Select folder to encrypt")
        if folder:
            files = self.file_handler.get_files_in_directory(folder)
            self.selected_files.extend(files)
            self.update_files_listbox()
            self.logger.log("Folder Selected", f"Added {len(files)} files from folder")
            
    def clear_selection(self):
        """Clear selected files"""
        self.selected_files.clear()
        self.update_files_listbox()
        self.logger.log("Selection Cleared", "Cleared file selection")
        
    def update_files_listbox(self):
        """Update the files listbox"""
        self.files_listbox.delete(0, tk.END)
        for file_path in self.selected_files:
            self.files_listbox.insert(tk.END, os.path.basename(file_path))
            
    def update_password_strength(self, *args):
        """Update password strength indicator"""
        password = self.password_var.get()
        strength = self.crypto_utils.calculate_password_strength(password)
        self.strength_label.config(text=f"Password Strength: {strength['feedback']}")
        
    def encrypt_files(self):
        """Encrypt selected files"""
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select files to encrypt")
            return
            
        if not self.password_var.get():
            messagebox.showwarning("No Password", "Please enter a password")
            return
            
        # Run encryption in separate thread
        threading.Thread(target=self._encrypt_files_thread, daemon=True).start()
        
    def _encrypt_files_thread(self):
        """Encrypt files in separate thread"""
        try:
            plugin = self.plugin_manager.get_plugin(self.current_plugin.get())
            password = self.password_var.get()
            
            total_files = len(self.selected_files)
            
            for i, file_path in enumerate(self.selected_files):
                # Update progress
                progress = (i / total_files) * 100
                self.progress_var.set(progress)
                
                # Encrypt file
                success = self.file_handler.encrypt_file(file_path, password, plugin)
                
                if success:
                    self.logger.log("File Encrypted", f"Successfully encrypted {os.path.basename(file_path)}")
                else:
                    self.logger.log("Encryption Error", f"Failed to encrypt {os.path.basename(file_path)}", "error")
                    
            self.progress_var.set(100)
            self.logger.log("Encryption Complete", f"Processed {total_files} files")
            messagebox.showinfo("Complete", "Encryption completed!")
            
        except Exception as e:
            self.logger.log("Encryption Error", str(e), "error")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        finally:
            self.progress_var.set(0)
            
    def select_encrypted_files(self):
        """Select encrypted files for decryption"""
        files = filedialog.askopenfilenames(
            title="Select encrypted files",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        self.decrypt_files_listbox.delete(0, tk.END)
        for file_path in files:
            self.decrypt_files_listbox.insert(tk.END, os.path.basename(file_path))
        self.selected_decrypt_files = list(files)
        
    def clear_decrypt_selection(self):
        """Clear decrypt file selection"""
        self.decrypt_files_listbox.delete(0, tk.END)
        self.selected_decrypt_files = []
        
    def decrypt_files(self):
        """Decrypt selected files"""
        if not hasattr(self, 'selected_decrypt_files') or not self.selected_decrypt_files:
            messagebox.showwarning("No Files", "Please select encrypted files")
            return
            
        if not self.decrypt_password_var.get():
            messagebox.showwarning("No Password", "Please enter the decryption password")
            return
            
        threading.Thread(target=self._decrypt_files_thread, daemon=True).start()
        
    def _decrypt_files_thread(self):
        """Decrypt files in separate thread"""
        try:
            plugin = self.plugin_manager.get_plugin(self.decrypt_plugin_var.get())
            password = self.decrypt_password_var.get()
            
            for file_path in self.selected_decrypt_files:
                success = self.file_handler.decrypt_file(file_path, password, plugin)
                
                if success:
                    self.logger.log("File Decrypted", f"Successfully decrypted {os.path.basename(file_path)}")
                else:
                    self.logger.log("Decryption Error", f"Failed to decrypt {os.path.basename(file_path)}", "error")
                    
            messagebox.showinfo("Complete", "Decryption completed!")
            
        except Exception as e:
            self.logger.log("Decryption Error", str(e), "error")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            
    def generate_key(self):
        """Generate encryption key"""
        try:
            plugin = self.plugin_manager.get_plugin(self.gen_plugin_var.get())
            key = plugin.generate_key()
            
            self.generated_key_text.delete(1.0, tk.END)
            self.generated_key_text.insert(tk.END, key)
            
            self.logger.log("Key Generated", f"Generated {plugin.display_name} key")
            
        except Exception as e:
            self.logger.log("Key Generation Error", str(e), "error")
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
            
    def generate_password(self):
        """Generate secure password"""
        try:
            length = self.password_length_var.get()
            password = self.crypto_utils.generate_random_password(length)
            
            self.generated_password_text.delete(1.0, tk.END)
            self.generated_password_text.insert(tk.END, password)
            
            self.logger.log("Password Generated", f"Generated secure password with length {length}")
            
        except Exception as e:
            self.logger.log("Password Generation Error", str(e), "error")
            messagebox.showerror("Error", f"Password generation failed: {str(e)}")
            
    def open_github(self):
        """Open GitHub profile"""
        webbrowser.open("https://github.com/Suryabx")
        self.logger.log("GitHub Visited", "Opened developer GitHub profile")
        
    def export_settings(self):
        """Export settings to file"""
        try:
            filename = filedialog.asksaveasfilename(
                title="Export Settings",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            if filename:
                self.settings_manager.export_settings(filename)
                self.logger.log("Settings Exported", f"Settings exported to {filename}")
                messagebox.showinfo("Success", "Settings exported successfully!")
        except Exception as e:
            self.logger.log("Export Error", str(e), "error")
            messagebox.showerror("Error", f"Export failed: {str(e)}")
            
    def import_settings(self):
        """Import settings from file"""
        try:
            filename = filedialog.askopenfilename(
                title="Import Settings",
                filetypes=[("JSON files", "*.json")]
            )
            if filename:
                self.settings_manager.import_settings(filename)
                self.load_settings()
                self.logger.log("Settings Imported", f"Settings imported from {filename}")
                messagebox.showinfo("Success", "Settings imported successfully!")
        except Exception as e:
            self.logger.log("Import Error", str(e), "error")
            messagebox.showerror("Error", f"Import failed: {str(e)}")
            
    def save_settings(self):
        """Save current settings"""
        settings = {
            'theme': self.theme_var.get(),
            'auto_clear_logs': self.auto_clear_logs_var.get(),
            'confirm_overwrite': self.confirm_overwrite_var.get()
        }
        self.settings_manager.save_settings(settings)
        self.logger.log("Settings Saved", "Application settings saved")
        messagebox.showinfo("Success", "Settings saved successfully!")
        
    def load_settings(self):
        """Load saved settings"""
        settings = self.settings_manager.load_settings()
        self.theme_var.set(settings.get('theme', 'default'))
        self.auto_clear_logs_var.set(settings.get('auto_clear_logs', False))
        self.confirm_overwrite_var.set(settings.get('confirm_overwrite', True))
        
    def clear_logs(self):
        """Clear activity logs"""
        self.logger.clear_logs()
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.logger.log("Logs Cleared", "All logs have been cleared")
        
    def run(self):
        """Start the application"""
        # Update log display periodically
        def update_log_display():
            logs = self.logger.get_recent_logs(10)
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            for log in reversed(logs):
                timestamp = log['timestamp'].strftime("%H:%M:%S")
                self.log_text.insert(tk.END, f"[{timestamp}] {log['action']}: {log['details']}\n")
            self.log_text.config(state=tk.DISABLED)
            self.log_text.see(tk.END)
            self.root.after(1000, update_log_display)
            
        update_log_display()
        self.root.mainloop()

if __name__ == "__main__":
    app = SatanEncryptorSuite()
    app.run()