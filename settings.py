# settings.py

import json
import os

CONFIG_FILE = "config.json"

def load_settings():
    """Load settings from config.json, or return defaults if not found."""
    if not os.path.exists(CONFIG_FILE):
        return {
            "theme": "dark",
            "default_path": "",
            "log_enabled": True
        }
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_settings(settings):
    """Save settings to config.json."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def set_theme(mode):
    """Apply theme mode to the customtkinter UI."""
    import customtkinter as ctk
    if mode.lower() == "light":
        ctk.set_appearance_mode("Light")
    else:
        ctk.set_appearance_mode("Dark")
