"""
Settings Manager Module
Handles application settings and configuration
"""

import json
import os
from pathlib import Path

class SettingsManager:
    """Manages application settings and configuration"""
    
    def __init__(self, settings_file="settings.json"):
        self.settings_file = settings_file
        self.default_settings = {
            'theme': 'default',
            'auto_clear_logs': False,
            'confirm_overwrite': True,
            'language': 'en',
            'default_plugin': 'aes256',
            'window_geometry': '900x700',
            'auto_backup': True,
            'log_level': 'info',
            'max_recent_files': 10
        }
        self.settings = self.default_settings.copy()
        self.load_settings()
        
    def load_settings(self):
        """Load settings from file"""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    self.settings.update(loaded_settings)
        except Exception as e:
            print(f"Failed to load settings: {str(e)}")
            self.settings = self.default_settings.copy()
            
    def save_settings(self, new_settings=None):
        """Save settings to file"""
        try:
            if new_settings:
                self.settings.update(new_settings)
                
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            print(f"Failed to save settings: {str(e)}")
            
    def get_setting(self, key, default=None):
        """Get a specific setting"""
        return self.settings.get(key, default)
        
    def set_setting(self, key, value):
        """Set a specific setting"""
        self.settings[key] = value
        self.save_settings()
        
    def reset_settings(self):
        """Reset settings to defaults"""
        self.settings = self.default_settings.copy()
        self.save_settings()
        
    def export_settings(self, export_path):
        """Export settings to a file"""
        try:
            with open(export_path, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except Exception as e:
            print(f"Failed to export settings: {str(e)}")
            return False
            
    def import_settings(self, import_path):
        """Import settings from a file"""
        try:
            with open(import_path, 'r') as f:
                imported_settings = json.load(f)
                
            # Validate imported settings
            if self.validate_settings(imported_settings):
                self.settings.update(imported_settings)
                self.save_settings()
                return True
            else:
                print("Invalid settings file")
                return False
        except Exception as e:
            print(f"Failed to import settings: {str(e)}")
            return False
            
    def validate_settings(self, settings):
        """Validate settings dictionary"""
        try:
            # Check if it's a dictionary
            if not isinstance(settings, dict):
                return False
                
            # Check for required keys and valid values
            valid_themes = ['default', 'dark', 'light']
            if 'theme' in settings and settings['theme'] not in valid_themes:
                return False
                
            valid_languages = ['en', 'es', 'fr', 'de']
            if 'language' in settings and settings['language'] not in valid_languages:
                return False
                
            # Check boolean settings
            boolean_settings = ['auto_clear_logs', 'confirm_overwrite', 'auto_backup']
            for key in boolean_settings:
                if key in settings and not isinstance(settings[key], bool):
                    return False
                    
            return True
        except Exception:
            return False
            
    def get_all_settings(self):
        """Get all settings"""
        return self.settings.copy()
        
    def backup_settings(self, backup_path=None):
        """Create a backup of current settings"""
        try:
            if backup_path is None:
                backup_path = f"{self.settings_file}.backup"
                
            with open(backup_path, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except Exception as e:
            print(f"Failed to backup settings: {str(e)}")
            return False
            
    def restore_settings(self, backup_path=None):
        """Restore settings from backup"""
        try:
            if backup_path is None:
                backup_path = f"{self.settings_file}.backup"
                
            if os.path.exists(backup_path):
                with open(backup_path, 'r') as f:
                    backup_settings = json.load(f)
                    
                if self.validate_settings(backup_settings):
                    self.settings = backup_settings
                    self.save_settings()
                    return True
            return False
        except Exception as e:
            print(f"Failed to restore settings: {str(e)}")
            return False
            
    def get_recent_files(self):
        """Get list of recent files"""
        return self.settings.get('recent_files', [])
        
    def add_recent_file(self, file_path):
        """Add file to recent files list"""
        recent_files = self.get_recent_files()
        
        # Remove if already exists
        if file_path in recent_files:
            recent_files.remove(file_path)
            
        # Add to beginning
        recent_files.insert(0, file_path)
        
        # Keep only max_recent_files
        max_files = self.get_setting('max_recent_files', 10)
        recent_files = recent_files[:max_files]
        
        self.set_setting('recent_files', recent_files)
        
    def clear_recent_files(self):
        """Clear recent files list"""
        self.set_setting('recent_files', [])