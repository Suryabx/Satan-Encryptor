# ui.py

import customtkinter as ctk
from tkinter import filedialog, messagebox
from crypto_engine import encrypt_file, decrypt_file, encrypt_folder, decrypt_folder
from utils import generate_secure_key, is_file, is_folder, get_filename
from settings import load_settings, save_settings, set_theme
from about import show_about
from log import write_log

class SatanUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        set_theme(self.settings.get("theme", "dark"))

        self.title("Satan - File Encryptor")
        self.geometry("600x400")
        self.minsize(600, 400)

        self.selected_path = ""

        # UI Components
        ctk.CTkLabel(self, text="Satan - AES-256 Encryptor", font=("Arial", 20)).pack(pady=10)

        self.path_entry = ctk.CTkEntry(self, placeholder_text="Choose file or folder...", width=400)
        self.path_entry.pack(pady=5)

        ctk.CTkButton(self, text="📂 Browse", command=self.browse_path).pack()

        self.key_entry = ctk.CTkEntry(self, placeholder_text="Enter or generate a key", width=400, show="*")
        self.key_entry.pack(pady=10)

        ctk.CTkButton(self, text="🔐 Encrypt", command=self.encrypt).pack(pady=4)
        ctk.CTkButton(self, text="🔓 Decrypt", command=self.decrypt).pack(pady=4)
        ctk.CTkButton(self, text="🎲 Generate Key", command=self.generate_key).pack(pady=4)

        self.status = ctk.CTkLabel(self, text="Status: Ready", text_color="gray")
        self.status.pack(pady=10)

        bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", pady=5)

        ctk.CTkButton(bottom_frame, text="About", width=70, command=show_about).pack(side="right", padx=10)

        theme_toggle = ctk.CTkSwitch(
            bottom_frame, text="Dark Mode",
            command=self.toggle_theme,
            variable=ctk.StringVar(value=self.settings.get("theme", "dark")),
            onvalue="dark", offvalue="light"
        )
        theme_toggle.select() if self.settings.get("theme") == "dark" else theme_toggle.deselect()
        theme_toggle.pack(side="left", padx=10)

    def browse_path(self):
        path = filedialog.askopenfilename()
        if not path:
            path = filedialog.askdirectory()
        if path:
            self.selected_path = path
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, path)

    def generate_key(self):
        key = generate_secure_key()
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, key)
        self.status.configure(text="Key generated")

    def encrypt(self):
        path = self.selected_path
        key = self.key_entry.get()
        if not path or not key:
            messagebox.showwarning("Missing", "Select a path and enter a key")
            return

        try:
            if is_file(path):
                out = encrypt_file(path, key)
                self.status.configure(text=f"Encrypted: {get_filename(out)}")
                write_log(f"Encrypted file: {out}")
            elif is_folder(path):
                files = encrypt_folder(path, key)
                self.status.configure(text=f"Encrypted folder: {len(files)} files")
                write_log(f"Encrypted folder: {path} ({len(files)} files)")
            else:
                raise Exception("Invalid path")
        except Exception as e:
            messagebox.showerror("Encrypt Error", str(e))
            write_log(f"Encryption error: {e}", level="ERROR")

    def decrypt(self):
        path = self.selected_path
        key = self.key_entry.get()
        if not path or not key:
            messagebox.showwarning("Missing", "Select a path and enter a key")
            return

        try:
            if is_file(path):
                out = decrypt_file(path, key)
                self.status.configure(text=f"Decrypted: {get_filename(out)}")
                write_log(f"Decrypted file: {out}")
            elif is_folder(path):
                files = decrypt_folder(path, key)
                self.status.configure(text=f"Decrypted folder: {len(files)} files")
                write_log(f"Decrypted folder: {path} ({len(files)} files)")
            else:
                raise Exception("Invalid path")
        except Exception as e:
            messagebox.showerror("Decrypt Error", str(e))
            write_log(f"Decryption error: {e}", level="ERROR")

    def toggle_theme(self):
        new_theme = "light" if self.settings["theme"] == "dark" else "dark"
        self.settings["theme"] = new_theme
        save_settings(self.settings)
        set_theme(new_theme)
        self.destroy()
        app = SatanUI()
        app.mainloop()
