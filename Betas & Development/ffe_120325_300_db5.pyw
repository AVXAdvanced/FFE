print("Friend File Encryptor - FFE")
print('Version 3.0.0 "Lyrah" Developer Beta 5')
print("Build: ffe_120325_300_db5")
print("")
print("Terminal Output Established")
print("")
print("Imports will be loaded now.")
print("")
print("""
List of Imports to be loaded:

os
sys
requests
tkinter as tk
from tkinter import messagebox, ttk, simpledialog, Entry, Frame, Label, StringVar, X
textwrap
json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from packaging import version
re
webbrowser
threading
secrets
""")
print("")

import os
import sys
import requests
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, Entry, Frame, Label, StringVar, X
import textwrap
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from packaging import version
import re
import webbrowser
import threading
import secrets

print("Imports have been loaded.")
print("Note: This is not a check that they have actually been loaded, but the code has passed to right below the import section.")
print("From now on, you'll see debug statements about where the code is right now.")
print("For example, if you reach ""def fesys_gen_key"", you'll see a print output ""def fesys_gen_key"" and/or any notable events.")#
print("")

# /n for line break
# /n/n works for double line break (space between line break)

# Please don't remove any wierd looking text formatting, its usually correct for a decent ui.. tkinter is wierd

# Internal To-Do List (i dont feel like doing any of these)

# PRIORITY!!!
# TODO: None.

# Other
# TODO: More Setup Assistant Pages & Features

# "eventually when i feel like it"
# TODO: None


SETTINGS_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'ffeconfig.json')
LEGACY_SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'ffeconfig.json')

print("def_fesys_gen_key")
print("")
def fesys_gen_key():
    print("def fesys_gen_key")
    print("")
    return Fernet.generate_key()

print("def derive_key")
print("")
def derive_key(password: str, salt: bytes, security_level: str = None, app_instance=None) -> bytes:
    """Derive a key from a password using PBKDF2.
    
    Args:
        password: The password to derive the key from
        salt: Random salt (must be at least 16 bytes)
        security_level: Security level - 'fast', 'balanced', or 'secure'
        app_instance: Optional reference to the application instance with settings
        
    Returns:
        bytes: Derived key
        
    Raises:
        ValueError: If password is empty or salt is too short
        TypeError: If password is not a string or salt is not bytes
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt must be bytes and at least 16 bytes long")
        
    # If security_level is not specified, try to get it from settings
    if security_level is None:
        try:
            # Try to get from app instance if provided
            if app_instance is not None and hasattr(app_instance, 'settings'):
                security_level = app_instance.settings.get("encryption", {}).get("security_level", "balanced")
            else:
                security_level = "balanced"
        except Exception as e:
            print(f"Warning: Could not get security level from settings: {e}")
            security_level = "balanced"
    
    # Set iterations based on security level
    iterations = {
        "fast": 25000,      # Less secure, but faster
        "balanced": 400000,  # Good balance (default)
        "secure": 1250000    # More secure, but slower
    }.get(security_level.lower(), 400000)  # Default to balanced if invalid
    
    print(f"Using {security_level} security level with {iterations:,} iterations")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())

print("def generate_salt")
print("")
def generate_salt() -> bytes:
    """Generate a random salt."""
    print("def generate_salt")
    print("")
    return secrets.token_bytes(16)

def fesys_encrypt_with_password(file_path: str, password: str, progress_callback=None, security_level=None) -> str:
    global ctypes, key
    print("def fesys_encrypt_with_password")
    print("")
    """Encrypt a file using a password with AES-GCM.
    
    Args:
        file_path: Path to the file to encrypt
        password: Password for encryption
        progress_callback: Function to call with progress updates
        security_level: Security level - 'fast', 'balanced', or 'secure'
    """
    def update_progress(value, status=None):
        if progress_callback:
            progress_callback(value, status)

    # Convert password to bytes for secure clearing
    password_bytes = password.encode('utf-8')

    try:
        update_progress(5, "Initializing encryption...")

        # Generate a random salt
        salt = generate_salt()

        update_progress(10, "Deriving key...")
        # Derive key from password with specified security level
        key = derive_key(password, salt, security_level)

        # Generate a random nonce (96 bits for GCM)
        nonce = secrets.token_bytes(12)

        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        update_progress(20, "Reading file...")
        # Read file data
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            file_data = f.read()

        update_progress(40, "Encrypting data...")
        # Encrypt the data (GCM handles padding)
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        # Get the authentication tag
        tag = encryptor.tag

        # Create the output data: PWD header (3) + salt (16) + nonce (12) + tag (16) + encrypted_data
        output_data = salt + nonce + tag + encrypted_data

        update_progress(80, "Writing encrypted file...")
        # Save to .enc file
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as f:
            # Store a header to identify password-based encryption
            f.write(b"PWD" + output_data)

        # Securely clear sensitive data from memory
        import ctypes
        import sys

        # Overwrite the password in memory
        if isinstance(password, str):
            # For string objects, we need to create a new string with the same id
            # and then overwrite the internal buffer
            null_terminated = password + '\x00'
            buffer = ctypes.create_string_buffer(null_terminated.encode('utf-8'))
            ctypes.memset(ctypes.addressof(buffer), 0, len(buffer))

        # Also clear the password bytes
        if 'password_bytes' in locals():
            ctypes.memset(ctypes.addressof(ctypes.c_char_p(password_bytes)), 0, len(password_bytes))

        # Overwrite the key in memory
        if 'key' in locals():
            ctypes.memset(ctypes.addressof(ctypes.c_char_p(key)), 0, len(key))

        update_progress(100, "Encryption complete!")
        return f"File '{os.path.basename(file_path)}' successfully encrypted with password!"
    except Exception as e:
        # Ensure we still clean up even if there's an error
        if 'password_bytes' in locals():
            ctypes.memset(ctypes.addressof(ctypes.c_char_p(password_bytes)), 0, len(password_bytes))
        if 'key' in locals():
            ctypes.memset(ctypes.addressof(ctypes.c_char_p(key)), 0, len(key))
        return f"Error during password encryption: {str(e)}"

# gotta hate tkinter

def decrypt_with_password(file_path: str, password: str, progress_callback=None) -> str:
    """Decrypt a file using a password with AES-GCM.
    
    Args:
        file_path: Path to the encrypted file
        password: Password for decryption
        progress_callback: Optional callback for progress updates
    """
    def update_progress(value, status=None):
        if progress_callback:
            progress_callback(value, status)

    try:
        update_progress(5, "Reading encrypted file...")

        # Read the encrypted file
        with open(file_path, "rb") as f:
            # Check if it's a password-encrypted file
            header = f.read(3)
            if header != b"PWD":
                return "Not a password-encrypted file or file is corrupted."

            # Read salt (16), nonce (12), tag (16), and encrypted data
            salt = f.read(16)
            nonce = f.read(12)
            tag = f.read(16)
            encrypted_data = f.read()

        update_progress(20, "Deriving decryption key...")
        # Derive key from password
        key = derive_key(password, salt)

        update_progress(30, "Initializing decryption...")
        # Create cipher and decrypt
        try:
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            update_progress(40, "Decrypting data...")
            # Decrypt the data
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            update_progress(80, "Saving decrypted file...")
            # Save the decrypted data to a new file
            output_path = file_path[:-4]  # Remove .enc extension
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            update_progress(100, "Decryption complete!")
            return f"File '{os.path.basename(file_path)}' successfully decrypted!"
            
        except Exception as e:
            if "decryption failed" in str(e).lower() or "tag" in str(e).lower():
                return "Incorrect password. Decryption failed."
            raise  # Re-raise other exceptions

    except Exception as e:
        if "Incorrect password" in str(e):
            return str(e)
        return f"Error during password decryption: {str(e)}"

# Settings file handling

# noinspection PyBroadException
def load_app_settings():
    print("def load_app_settings")
    print("")
    """Load app settings from JSON file or create default if not exists."""
    # Determine the base directory for settings
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        base_dir = os.path.dirname(sys.executable)
    else:
        # Running as script
        base_dir = os.path.dirname(os.path.abspath(__file__))

    # Define paths relative to the base directory
    settings_file = os.path.join(base_dir, 'ffeconfig.json')
    legacy_settings_file = os.path.join(base_dir, 'ffeconfig.json')  # Same as settings_file in this case

    # ffedata generator
    # default ffeconfig.json is generated based off this data


    defaults = {
        "first_run": True,
        "first_run_chg_inhibit": False,
        "theme": "Ocean Deep",
        "encryption": {
            "default_method": "password"  # password is default. using key_file as the generation default is NOT recommended.
        },
        "stats": {
            "files_encrypted": 0,
            "files_decrypted": 0,
            "files_deleted": 0,
            "forward_count": 0,
            "back_count": 0,
            "refresh_count": 0,
            "theme_changes": 0,
            "theme_usage": {}
        }
    }

    def ensure_settings_file():
        """Ensure the settings file exists with default values if it doesn't exist."""
        try:
            # If neither file exists, create the new one with defaults
            if not os.path.exists(settings_file) and not os.path.exists(legacy_settings_file):
                # Ensure directory exists
                os.makedirs(os.path.dirname(settings_file), exist_ok=True)
                # Write default settings
                with open(settings_file, 'w', encoding='utf-8') as f:
                    json.dump(defaults, f, indent=2)
                print(f"Created new settings file at: {settings_file}")
                return settings_file
            return None
        except Exception as e:
            print(f"Error ensuring settings file: {e}")
            return None

    def load_settings_file(file_path):
        """Helper to load settings from a file path with error handling."""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            return None
        except Exception as e:
            print(f"Error loading settings from {file_path}: {e}")
            return None

    def save_settings(data, file_path):
        """Helper to save settings to a file with error handling."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving settings to {file_path}: {e}")
            return False

    try:
        # holy shit is that debug??
        print(f"Base directory: {base_dir}")
        print(f"Settings file path: {settings_file}")
        print(f"Legacy settings file path: {legacy_settings_file}")

        # First ensure settings file exists (obviously)
        new_file = ensure_settings_file()

        # Determine which file to load
        settings_data = None
        loaded_from = None

        # Try to load from the new settings file first
        if not new_file and os.path.exists(settings_file):
            settings_data = load_settings_file(settings_file)
            if settings_data is not None:
                loaded_from = settings_file

        # If that fails, try the legacy file
        if settings_data is None and os.path.exists(legacy_settings_file):
            settings_data = load_settings_file(legacy_settings_file)
            if settings_data is not None:
                loaded_from = legacy_settings_file
                # Migrate to new location
                if save_settings(settings_data, settings_file):
                    print(f"Migrated settings from {legacy_settings_file} to {settings_file}")

        # If we still don't have data, use defaults
        if settings_data is None:
            print("No settings file found, using defaults")
            settings_data = defaults.copy()
            # Try to save defaults
            if save_settings(settings_data, settings_file):
                print(f"Created new settings file with defaults at {settings_file}")

        # Ensure all default values are present
        for k, v in defaults.items():
            if isinstance(v, dict):
                settings_data.setdefault(k, {})
                # Deep update for nested dictionaries
                for sk, sv in v.items():
                    settings_data[k].setdefault(sk, sv)
            else:
                settings_data.setdefault(k, v)

        # Save the file to ensure any missing defaults are added
        save_settings(settings_data, settings_file)

        return settings_data

    except Exception as e:
        print(f"Error in load_app_settings: {e}")
        # Return defaults if anything goes wrong
        return defaults.copy()


def save_app_settings(settings: dict):
    print("def save_app_settings")
    print("")
    """Persist app settings to settings file safely."""
    try:
        # Determine the base directory for settings
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            base_dir = os.path.dirname(sys.executable)
        else:
            # Running as script
            base_dir = os.path.dirname(os.path.abspath(__file__))

        # Define the settings file path
        settings_file = os.path.join(base_dir, 'ffeconfig.json')

        # Ensure the directory exists
        os.makedirs(os.path.dirname(settings_file), exist_ok=True)

        # Debug info
        print(f"Saving settings to: {settings_file}")
        print(f"Settings to save: {json.dumps(settings, indent=2)}")

        # Save the settings
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)

        print("Settings saved successfully")
        return True

    except Exception as e:
        print(f"Error in save_app_settings: {e}")
        import traceback
        traceback.print_exc()
        return False


def fesys_save_key(key, filename):
    print("def fesys_save_key")
    print("")
    with open(filename, "wb") as key_file:
        key_file.write(key)


def fesys_encrypt_file(file_path: str, main_key: bytes, use_password: bool = False, 
                       password: str = None, progress_callback = None) -> None:
    """Encrypt a file using the provided key or password.
    
    Args:
        file_path: Path to the file to encrypt
        main_key: The encryption key to use
        use_password: Whether to use password-based encryption
        password: Password to use if use_password is True
        progress_callback: Optional callback for progress updates
        
    Raises:
        FileNotFoundError: If the input file doesn't exist
        PermissionError: If there are permission issues
        ValueError: For invalid parameters
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if not isinstance(main_key, bytes):
        raise TypeError("main_key must be bytes")
    if use_password and not password:
        raise ValueError("Password is required when use_password is True")
        
    print("def fesys_encrypt_file")
    print("")
    """
    Encrypt a file using either key file or password.
    
    Args:
        file_path: Path to the file to encrypt
        main_key: The main encryption key (for key file method)
        use_password: If True, use password-based encryption
        password: The password to use (required if use_password is True)
        progress_callback: Callback function to update progress (value, status)
    """
    def update_progress(value, status=None):
        if progress_callback:
            progress_callback(value, status)

    if use_password:
        if not password:
            return "Password is required for password-based encryption."
        return fesys_encrypt_with_password(file_path, password, progress_callback=progress_callback)

    # Default to key file encryption
    try:
        update_progress(5, "Initializing encryption...")
        cipher_main = Fernet(main_key)
        new_key = Fernet.generate_key()
        cipher_file = Fernet(new_key)

        update_progress(10, "Reading file...")
        with open(file_path, "rb") as file:
            file_data = file.read()

        update_progress(30, "Encrypting data...")
        encrypted_data = cipher_file.encrypt(file_data)
        encrypted_key = cipher_main.encrypt(new_key)
        encrypted_file_path = file_path + ".enc"

        update_progress(70, "Writing encrypted file...")
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data + b"|||" + encrypted_key)

        update_progress(100, "Encryption complete!")
        return f"File '{os.path.basename(file_path)}' successfully encrypted with key file!"
    except Exception as e:
        return f"Error during encryption: {str(e)}"


def fesys_decrypt_file(file_path, main_key, progress_callback=None):
    print("def fesys_decrypt_file")
    print("")
    def update_progress(value, status=None):
        if progress_callback:
            progress_callback(value, status)

    try:
        update_progress(5, "Starting decryption...")

        if not file_path.endswith(".enc"):
            return "Only .enc files can be decrypted."

        # Check if it's a password-encrypted file
        with open(file_path, "rb") as f:
            header = f.read(3)
            if header == b"PWD":
                # It's a password-encrypted file, prompt for password
                password = simpledialog.askstring("Password Required",
                                               "Enter password for decryption:",
                                               show='*')
                if not password:
                    return "Decryption cancelled by user."
                
                # Get the parent window for the error dialog
                parent = None
                if progress_callback and hasattr(progress_callback, '__self__'):
                    parent = progress_callback.__self__
                
                result = decrypt_with_password(file_path, password, progress_callback=progress_callback)
                if result and ("Incorrect password" in result or "decryption failed" in result.lower()):
                    if parent:
                        show_neoui_error(parent, "Decryption Failed", "Incorrect password. Please try again.")
                    return result
                return result

        # If we get here, it's a key file-encrypted file
        update_progress(10, "Loading encryption keys...")
        cipher_main = Fernet(main_key)

        with open(file_path, "rb") as encrypted_file:
            full_encrypted_data = encrypted_file.read()

        try:
            update_progress(20, "Processing encrypted data...")
            encrypted_data, encrypted_key = full_encrypted_data.split(b"|||", 1)
        except ValueError:
            return "Error: Encrypted file is corrupted or not in the correct format."

        update_progress(30, "Decrypting file key...")
        decrypted_key = cipher_main.decrypt(encrypted_key)
        cipher_file = Fernet(decrypted_key)

        update_progress(40, "Decrypting file content...")
        decrypted_data = cipher_file.decrypt(encrypted_data)
        decrypted_file_path = file_path[:-4]  # Remove .enc extension

        update_progress(80, f"Saving decrypted file to {os.path.basename(decrypted_file_path)}...")
        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        update_progress(100, "Decryption complete!")
        return None  # No success message for key file decryption
    except Exception as e:
        error_msg = str(e).lower()
        if "invalid signature" in error_msg or "invalid token" in error_msg or "invalid key" in error_msg:
            return "Incorrect Key File\n\nThe key file you selected does not match the one used to encrypt this file.\n\n• Please make sure you're using the correct key file\n• The key file must be the same one used during encryption\n• If you've lost the key file, you won't be able to decrypt the file"
        return f"Error during decryption: {str(e)}"

# i swear if this shit stops working again

class HoverButton(tk.Button):
    def __init__(self, master, **kwargs):
        print("class HoverButton.__init__")
        print("")
        tk.Button.__init__(self, master, **kwargs)
        self.default_bg = self["background"]
        self.bright_bg = self.brighten_color(self.default_bg, 20)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        print("class HoverButton.on_enter")
        print("")
        try:
            self["background"] = self.bright_bg
        except tk.TclError:
            # Widget might be destroyed
            pass

    def on_leave(self, e):
        print("class HoverButton.on_leave")
        print("")
        try:
            self['background'] = self.default_bg
        except tk.TclError:
            # Widget might be destroyed
            pass

    def brighten_color(self, color, brightness_factor):
        print("class HoverButton.brighten_color")
        print("")
        if isinstance(color, str) and color.startswith("#") and len(color) == 7:
            try:
                r, g, b = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
                r = min(255, r + brightness_factor)
                g = min(255, g + brightness_factor)
                b = min(255, b + brightness_factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            except ValueError:
                return color
        else:
            return color

# ooooh colors!

class NeoUIThemes:
    THEMES = {
        "Ocean Deep": {
            "bg": "#0c1920",
            "secondary_bg": "#132b35",
            "accent": "#2d6477",
            "success": "#2d8879",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Depth Blue": {
            "bg": "#0a1124",
            "secondary_bg": "#0f1936",
            "accent": "#2c4580",
            "success": "#2d8879",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Midnight Purple": {
            "bg": "#160c29",
            "secondary_bg": "#25153d",
            "accent": "#5f3a99",
            "success": "#40C28B",
            "error": "#E05268",
            "warning": "#E0903A",
            "text": "white"
        },
        "Forest Green": {
            "bg": "#0a1f0a",
            "secondary_bg": "#122712",
            "accent": "#2d5a2d",
            "success": "#3d7a5f",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Volcanic": {
            "bg": "#1a0f0f",
            "secondary_bg": "#2a1919",
            "accent": "#664040",
            "success": "#5d7a3c",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Arctic Sunlight": {
            "bg": "#769cc2",
            "secondary_bg": "#a6cfff",
            "accent": "#3674c9",
            "success": "#6cebb3",
            "error": "#e84e4a",
            "warning": "#bf8f3b",
            "text": "black"
        },
        "Arctic Stars": {
            "bg": "#0f1419",
            "secondary_bg": "#1a2027",
            "accent": "#3d4a59",
            "success": "#3d7a5f",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Spooky.. 🎃": {
            "bg": "#120C1C",
            "secondary_bg": "#2A1124",
            "accent": "#FF784E",
            "success": "#d9a223",
            "error": "#FF5A5A",
            "warning": "#FF9B4E",
            "text": "white"
        },
        "Cyberpunk": {
            "bg": "#0f0f1a",
            "secondary_bg": "#16162b",
            "accent": "#19bfb7",
            "success": "#00ff9f",
            "error": "#ff003c",
            "warning": "#eb7e02",
            "text": "#00fff2",
            "button_text": "#000000"
        },
        "High Contrast": {
            "bg": "#000000",
            "secondary_bg": "#141414",
            "accent": "#2137cc",
            "success": "#2fa600",
            "error": "#cf2d00",
            "warning": "#e6f200",
            "text": "#ffffff"
        }
    }

    @staticmethod
    def get_dialog_colors(dialog_type, theme_name):
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])
        mapping = {
            "info": theme["accent"],
            "warning": theme["warning"],
            "error": theme["error"],
            "question": theme["success"],
            "accent": theme["accent"],
            "success": theme["success"]
        }
        return mapping.get(dialog_type, theme["accent"])

    @staticmethod
    def get_button_text_color(theme_name, button_type):
        print("class NeoUIThemes.get_button_text_color")
        print("")
        return "white"


DEFAULT_FONT = "Segoe UI"

class ThemeManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ThemeManager, cls).__new__(cls)
            cls._instance._theme_name = "Ocean Deep"
            cls._instance._theme = NeoUIThemes.THEMES["Ocean Deep"]
            cls._instance._widgets = []
            cls._instance._style = None
        return cls._instance
    
    def initialize_style(self, root):
        """Initialize the ttk style"""
        if self._style is None:
            self._style = ttk.Style(root)
            self._style.theme_use('clam')
    
    def get_theme(self):
        """Get current theme name and properties"""
        return self._theme_name, self._theme
    
    def set_theme(self, theme_name, root):
        """Change the current theme and update all registered widgets"""
        if theme_name not in NeoUIThemes.THEMES:
            theme_name = "Ocean Deep"
            
        self._theme_name = theme_name
        self._theme = NeoUIThemes.THEMES[theme_name]
        
        # Update ttk style
        if self._style is None:
            self.initialize_style(root)
            
        # Configure ttk style
        self._style.configure(".", 
                             background=self._theme["secondary_bg"],
                             foreground=self._theme["text"],
                             fieldbackground=self._theme["bg"],
                             selectbackground=self._theme["accent"],
                             selectforeground=self._theme["text"])
        
        # Update all registered widgets
        self._update_widgets()
        
        # Save theme preference if settings are available
        if hasattr(root, 'settings'):
            root.settings['theme'] = theme_name
            save_app_settings(root.settings)
    
    def register_widget(self, widget, config_func):
        """Register a widget and its configuration function"""
        self._widgets.append((widget, config_func))
        # Apply current theme to newly registered widget
        config_func(widget, self._theme_name, self._theme)
    
    def _update_widgets(self):
        """Update all registered widgets with current theme"""
        for widget, config_func in self._widgets:
            try:
                if widget.winfo_exists():
                    config_func(widget, self._theme_name, self._theme)
            except:
                # Remove dead widgets
                self._widgets.remove((widget, config_func))

# Create a global theme manager instance
theme_manager = ThemeManager()


class NeoUIHoverButton(tk.Button):
    def __init__(self, master, **kwargs):
        # Store original colors for theme updates
        self._bg = kwargs.get('bg', '#1a2b5a')
        self._fg = kwargs.get('fg', 'white')
        self._active_bg = kwargs.get('activebackground', '#2a4180')
        self._active_fg = kwargs.get('activeforeground', 'white')
        
        # Set default button styling
        kwargs['height'] = 1
        kwargs['pady'] = 4
        kwargs['relief'] = 'flat'
        kwargs['bd'] = 0
        if 'padx' not in kwargs:
            kwargs['padx'] = 10
        if 'font' not in kwargs:
            kwargs['font'] = (DEFAULT_FONT, 11)
        
        # Apply colors
        kwargs['bg'] = self._bg
        kwargs['fg'] = self._fg
        kwargs['activebackground'] = self._active_bg
        kwargs['activeforeground'] = self._active_fg
        kwargs['highlightthickness'] = 0
        
        # Initialize the button
        tk.Button.__init__(self, master, **kwargs)
        
        # Calculate hover colors
        self._update_hover_colors()
        
        # Bind events
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
    
    def update_theme(self, bg=None, fg=None, active_bg=None, active_fg=None):
        """Update the button's colors and recalculate hover effect"""
        if bg is not None:
            self._bg = bg
        if fg is not None:
            self._fg = fg
        if active_bg is not None:
            self._active_bg = active_bg
        if active_fg is not None:
            self._active_fg = active_fg
            
        # Update the button's appearance
        self.config(
            bg=self._bg,
            fg=self._fg,
            activebackground=self._active_bg,
            activeforeground=self._active_fg
        )
        
        # Update hover colors
        self._update_hover_colors()
    
    def _update_hover_colors(self):
        """Update the hover and active colors based on current background"""
        self.default_bg = self._bg
        self.bright_bg = self._brighten_color(self._bg, 20)
        # Update active background to be slightly darker than the normal background
        self._active_bg = self._darken_color(self._bg, 20)
        self['activebackground'] = self._active_bg
    
    def _on_enter(self, e):
        try:
            if self['state'] != 'disabled':
                self['background'] = self.bright_bg
        except tk.TclError:
            # Widget might be destroyed
            pass

    def _on_leave(self, e):
        if self['state'] != 'disabled':
            self["background"] = self.default_bg
            
    def _on_press(self, e):
        if self['state'] != 'disabled':
            self["background"] = self._active_bg
            
    def _on_release(self, e):
        if self['state'] != 'disabled':
            self["background"] = self.bright_bg

    def _brighten_color(self, color, brightness_factor):
        if isinstance(color, str) and color.startswith("#") and len(color) == 7:
            try:
                r, g, b = tuple(int(color[i:i+2], 16) for i in (1, 3, 5))
                r = min(255, r + brightness_factor)
                g = min(255, g + brightness_factor)
                b = min(255, b + brightness_factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            except ValueError:
                return color
        return color
        
    def _darken_color(self, color, darkness_factor):
        if isinstance(color, str) and color.startswith("#") and len(color) == 7:
            try:
                r, g, b = tuple(int(color[i:i+2], 16) for i in (1, 3, 5))
                r = max(0, r - darkness_factor)
                g = max(0, g - darkness_factor)
                b = max(0, b - darkness_factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            except ValueError:
                return color
        return color


class ProgressDialog(tk.Toplevel):
    def __init__(self, parent, title="Processing..."):
        print("class ProgressDialog.__init__")
        print("")
        super().__init__(parent)
        self.title(title)

        # Get theme
        theme_name = getattr(parent, 'current_theme', 'Ocean Deep')
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        # Configure window
        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)

        # Main frame
        main_frame = tk.Frame(self, bg=theme["secondary_bg"], padx=20, pady=20)
        main_frame.pack(expand=True, fill="both")

        # Title
        self.title_label = tk.Label(
            main_frame,
            text=title,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 16, "bold"),
            justify="left"
        )
        self.title_label.pack(anchor="w", pady=(0, 15))

        # Progress bar
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Custom.Horizontal.TProgressbar",
                       troughcolor=theme["bg"],
                       background=theme["accent"],
                       bordercolor=theme["accent"],
                       lightcolor=theme["accent"],
                       darkcolor=theme["accent"])

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame,
            orient="horizontal",
            length=400,
            mode='determinate',
            variable=self.progress_var,
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(fill="x", pady=(0, 15))

        # Status label
        self.status_var = tk.StringVar(value="Initializing...")
        self.status_label = tk.Label(
            main_frame,
            textvariable=self.status_var,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10),
            justify="left"
        )
        self.status_label.pack(anchor="w")

        # Center on screen
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

        # Make it modal
        self.grab_set()
        self.focus_set()

    def update_progress(self, value, status=None):
        print("class ProgressDialog.update_progress")
        print("")
        """Update progress bar value (0-100) and status text."""
        self.progress_var.set(min(100, max(0, value)))
        if status is not None:
            self.status_var.set(status)
        self.update_idletasks()


class neouiDialog(tk.Toplevel):
    TITLE_FONT_SIZE = 29
    VERSION_FONT_SIZE = 16
    CONTENT_FONT_SIZE = 11

    def __init__(self, parent, title, message, dialog_type="info", title_font_size=None):
        print("class neouiDialog.__init__")
        print("")
        super().__init__(parent)
        self.result = None

        # Theme
        theme_name = getattr(parent, 'current_theme', 'Ocean Deep')
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])
        accent_color = NeoUIThemes.get_dialog_colors(dialog_type, theme_name)

        # Window setup
        self.title(title)
        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)

        # Sizes
        self.title_font_size = title_font_size if title_font_size is not None else self.TITLE_FONT_SIZE

        # Main frame
        main = tk.Frame(self, bg=theme["secondary_bg"], padx=20, pady=20)
        main.pack(expand=True, fill="both")

        # Title
        title_label = tk.Label(main, text=title, bg=theme["secondary_bg"], fg=theme["text"],
                               font=(DEFAULT_FONT, self.title_font_size, "bold"), justify="left")
        title_label.pack(anchor="w")

        # Message
        clean_message = textwrap.dedent(message).lstrip("\n")
        msg = tk.Label(main, text=clean_message, bg=theme["secondary_bg"], fg=theme["text"],
                       font=(DEFAULT_FONT, self.CONTENT_FONT_SIZE), justify="left", wraplength=480)
        msg.pack(pady=(10, 20), anchor="w")

        # Buttons
        btn_frame = tk.Frame(main, bg=theme["secondary_bg"])
        btn_frame.pack(fill="x")

        if dialog_type == "question":
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.grid_columnconfigure(1, weight=1)

            yes_btn = NeoUIHoverButton(btn_frame, text="✓", command=self._yes, bg=accent_color,
                                        fg=NeoUIThemes.get_button_text_color(theme_name, "success"),
                                        font=(DEFAULT_FONT, 11), relief="flat")
            yes_btn.grid(row=0, column=0, sticky="ew", padx=2, pady=5)

            no_btn = NeoUIHoverButton(btn_frame, text="❌", command=self._no, bg=theme["accent"],
                                       fg=NeoUIThemes.get_button_text_color(theme_name, "accent"),
                                       font=(DEFAULT_FONT, 11), relief="flat")
            no_btn.grid(row=0, column=1, sticky="ew", padx=2, pady=5)
        else:
            ok_btn = NeoUIHoverButton(btn_frame, text="✓", command=self._ok, bg=accent_color,
                                       fg=NeoUIThemes.get_button_text_color(theme_name, dialog_type),
                                       font=(DEFAULT_FONT, 11), relief="flat")
            ok_btn.pack(fill="x", padx=5, pady=5)

        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

        self.grab_set()
        # For question dialogs, treat window close (X) as 'No'
        if hasattr(self, '_no'):
            self.protocol("WM_DELETE_WINDOW", self._no)
        else:
            self.protocol("WM_DELETE_WINDOW", self._ok)
        self.focus_set()

    def _ok(self):
        print("class neouiDialog._ok")
        print("")
        self.result = True
        self.destroy()

    def _yes(self):
        print("class neouiDialog._yes")
        print("")
        self.result = True
        self.destroy()

    def _no(self):
        print("class neouiDialog._no")
        print("")
        self.result = False
        self.destroy()


class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt, confirm=False):
        print("class PasswordDialog.__init__")
        print("")
        super().__init__(parent)
        self.title(title)
        self.result = None
        self.confirm = confirm
        self.password = StringVar()
        self.confirm_password = StringVar() if confirm else None

        # Get theme
        theme_name = getattr(parent, 'current_theme', 'Ocean Deep')
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        # Configure window
        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)

        # Main frame
        main_frame = Frame(self, bg=theme["secondary_bg"], padx=20, pady=20)
        main_frame.pack(expand=True, fill="both")

        # Title
        title_label = Label(
            main_frame,
            text=title,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 16, "bold"),
            justify="left"
        )
        title_label.pack(anchor="w", pady=(0, 10))

        # Prompt with wrapping
        prompt_label = Label(
            main_frame,
            text=prompt,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11),
            justify="left",
            wraplength=350  # Set a fixed wrap length to ensure text fits
        )
        prompt_label.pack(anchor="w", pady=(0, 15), fill="x", padx=5)

        # Password entry
        entry_frame = Frame(main_frame, bg=theme["secondary_bg"])
        entry_frame.pack(fill="x", pady=(0, 15))

        self.entry = Entry(
            entry_frame,
            textvariable=self.password,
            show="*",
            font=(DEFAULT_FONT, 11),
            bg=theme["bg"],
            fg=theme["text"],
            insertbackground=theme["text"],
            relief="flat"
        )
        self.entry.pack(fill="x", ipady=5)

        # Confirm password if needed
        if confirm:
            confirm_frame = Frame(main_frame, bg=theme["secondary_bg"])
            confirm_frame.pack(fill="x", pady=(0, 15))

            confirm_label = Label(
                confirm_frame,
                text="Confirm Password:",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11),
                justify="left"
            )
            confirm_label.pack(anchor="w", pady=(10, 5))

            self.confirm_entry = Entry(
                confirm_frame,
                textvariable=self.confirm_password,
                show="*",
                font=(DEFAULT_FONT, 11),
                bg=theme["bg"],
                fg=theme["text"],
                insertbackground=theme["text"],
                relief="flat"
            )
            self.confirm_entry.pack(fill="x", ipady=5)

        # Buttons
        btn_frame = Frame(main_frame, bg=theme["secondary_bg"])
        btn_frame.pack(fill="x")

        # Cancel button
        cancel_btn = NeoUIHoverButton(
            btn_frame,
            text="✕",
            command=self._cancel,
            bg=theme["error"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "error"),
            font=(DEFAULT_FONT, 11),
            relief="flat"
        )
        cancel_btn.pack(side="right", padx=5)

        # OK button
        ok_btn = NeoUIHoverButton(
            btn_frame,
            text="✓",
            command=self._ok,
            bg=NeoUIThemes.get_dialog_colors("info", theme_name),
            fg=NeoUIThemes.get_button_text_color(theme_name, "info"),
            font=(DEFAULT_FONT, 11),
            relief="flat"
        )
        ok_btn.pack(side="right", padx=5)

        # Bind Enter key to OK
        self.entry.bind('<Return>', lambda e: self._ok())
        if confirm:
            self.confirm_entry.bind('<Return>', lambda e: self._ok())

        # Center on screen
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"400x{max(200, h)}+{x}+{y}")

        # Focus the entry
        self.entry.focus_set()
        self.grab_set()

    def _ok(self):
        print("class PasswordDialog._ok")
        print("")
        if self.confirm and self.password.get() != self.confirm_password.get():
            show_neoui_error(self, "Error", "Passwords do not match!")
            return
        if not self.password.get():
            show_neoui_error(self, "Error", "Password cannot be empty!")
            return
        self.result = self.password.get()
        self.destroy()

    def _cancel(self):
        print("class PasswordDialog._cancel")
        print("")
        try:
            self.result = None
            self.destroy()
        except tk.TclError:
            # Window already destroyed
            pass


def show_neoui_info(parent, title, message):
    print("def show_neoui_info")
    print("")
    d = neouiDialog(parent, title, message, "info")
    d.wait_window()
    return d.result


def show_neoui_warning(parent, title, message):
    print("def show_neoui_warning")
    print("")
    d = neouiDialog(parent, title, message, "warning")
    d.wait_window()
    return d.result


def show_neoui_error(parent, title, message):
    print("def show_neoui_error")
    print("")
    d = neouiDialog(parent, title, message, "error")
    d.wait_window()
    return d.result


def show_neoui_question(parent, title, message):
    print("def show_neoui_question")
    print("")
    d = neouiDialog(parent, title, message, "question")
    d.wait_window()
    return d.result

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        if not hasattr(parent, 'current_theme'):
            raise ValueError("Parent must have 'current_theme' attribute")
            
        super().__init__(parent)
        self.parent = parent
        self.title("Settings")
        
        # Cleanup handler
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.original_theme = parent.current_theme
        self.current_theme = parent.current_theme  # Track current theme for this window
        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)

        main_frame = tk.Frame(self, bg=theme["secondary_bg"], padx=20, pady=20)
        main_frame.pack(expand=True, fill="both")

        title_label = tk.Label(
            main_frame,
            text="Settings",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 24, "bold"),
            justify="left",
        )
        title_label.pack(anchor="w")

        tk.Frame(main_frame, height=3, bg=theme["accent"]).pack(fill="x", pady=(10, 15))

        # Create a container frame for the notebook and selector
        notebook_container = tk.Frame(main_frame, bg=theme["secondary_bg"])
        notebook_container.pack(fill="both", expand=True)

        # Create a container for the notebook to ensure proper expansion
        notebook_frame = tk.Frame(notebook_container, bg=theme["secondary_bg"])
        notebook_frame.pack(fill="both", expand=True)

        # Notebook with tabs (we will hide native tabs and use our custom selector)
        notebook = ttk.Notebook(notebook_frame)
        notebook.pack(expand=True, fill="both")

        # Apply base notebook style (for panel area)
        self._apply_notebook_style(self.parent.current_theme)
        self.notebook = notebook

        # Create frames per tab (only required tabs)
        self.general_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
        self.themes_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
        self.encryption_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
        self.stats_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
        self.update_frame = tk.Frame(notebook, bg=theme["secondary_bg"])

        # Add tabs
        notebook.add(self.general_frame, text='General')
        notebook.add(self.themes_frame, text='Themes')
        notebook.add(self.encryption_frame, text='Encryption')
        notebook.add(self.stats_frame, text='Stats')
        notebook.add(self.update_frame, text='Update')

        # Now that frames are created, build the custom selector bar
        self._build_selector_bar(notebook_container, theme)

        # Create a separator line under the tabs
        separator = tk.Frame(notebook_container, height=1, bg=theme["accent"])
        separator.pack(fill="x", pady=(0, 10))

        # Hide native tabs since we're using our custom selector
        try:
            for tab_id in list(notebook.tabs()):
                notebook.hide(tab_id)
        except Exception:
            pass

        # Populate all tabs
        self._populate_na_tab(self.general_frame, theme)
        self._populate_themes_tab(self.themes_frame, theme)
        self._populate_na_tab(self.encryption_frame, theme)
        self._populate_stats_tab(self.stats_frame, theme)
        self._populate_update_tab(self.update_frame, theme)

        # Show the General tab by default
        self.notebook.select(self.general_frame)

        # Buttons container - full width checkmark button
        btn_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        btn_frame.pack(fill="x", pady=(15, 5))
        
        # Store original theme when dialog opens
        self.original_theme = self.parent.current_theme
        
        # Full width checkmark button with standard NeoUI dimensions
        apply_btn = NeoUIHoverButton(
            btn_frame,
            text="✓",
            command=self.destroy,
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
            font=(DEFAULT_FONT, 11, "bold"),
            relief="flat",
            width=15,
            padx=20,
            pady=4,  # Standard pady from NeoUIHoverButton
            anchor="center"
        )
        apply_btn.pack(fill="x", pady=5, expand=True)

        # Center on screen and modal
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.grab_set()
        self.focus_set()

    def open_file_in_default_editor(self, filename):
        try:
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
            if os.path.exists(file_path):
                os.startfile(file_path)
            else:
                messagebox.showerror("Error", f"File not found: {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {str(e)}")

    def _play_flappy_bird(self):
        """Open an optimized Flappy Bird game in a separate window with improved performance."""
        import random
        import threading
        import time
        import math
        from tkinter import Tk, Toplevel, Canvas, StringVar, Label, PhotoImage
        
        class FlappyBirdGame:
            def __init__(self, root):
                self.root = root
                self.root.title("Flappy Bird")
                self.root.resizable(False, False)
                
                # Set window position (center on screen)
                screen_width = self.root.winfo_screenwidth()
                screen_height = self.root.winfo_screenheight()
                self.WIDTH = 400
                self.HEIGHT = 600
                x = (screen_width - self.WIDTH) // 2
                y = (screen_height - self.HEIGHT) // 2
                self.root.geometry(f"{self.WIDTH}x{self.HEIGHT}+{x}+{y}")
                
                # Game constants
                self.GRAVITY = 0.45
                self.FLAP_STRENGTH = -7.5
                self.PIPE_SPEED = 3.5
                self.PIPE_GAP = 200
                self.PIPE_FREQUENCY = 1600  # milliseconds
                self.FRAME_DELAY = 16  # ~60 FPS
                
                # Colors and styling
                self.SKY_BLUE = "#87CEEB"
                self.GRASS_GREEN = "#7CFC00"
                self.PIPE_GREEN = "#228B22"
                self.BIRD_YELLOW = "#FFD700"
                self.BIRD_ORANGE = "#FFA500"
                self.WHITE = "#FFFFFF"
                self.BLACK = "#000000"
                
                # Game variables
                self.score = 0
                self.high_score = self.load_high_score()
                self.game_over = False
                self.running = True
                self.last_frame_time = time.time()
                self.pipes = []
                
                # Double buffering setup
                self.canvas = Canvas(root, width=self.WIDTH, height=self.HEIGHT, bg=self.SKY_BLUE, highlightthickness=0)
                self.canvas.pack()
                
                # Create off-screen buffer
                self.buffer = PhotoImage(width=self.WIDTH, height=self.HEIGHT)
                self.buffer_canvas = Canvas(width=self.WIDTH, height=self.HEIGHT, bg=self.SKY_BLUE, highlightthickness=0)
                
                # Score display
                self.score_var = StringVar()
                self.update_score_display()
                self.score_label = Label(root, textvariable=self.score_var, font=('Arial', 16, 'bold'), 
                                      bg=self.SKY_BLUE, fg='white', bd=0)
                self.score_label.place(x=10, y=10)
                
                # Bird properties
                self.bird_size = 24
                self.bird_x = 100
                self.bird_y = self.HEIGHT // 2
                self.bird_velocity = 0
                self.bird_rotation = 0
                self.bird_flap = 0
                
                # Draw initial game elements
                self.draw_background()
                self.draw_bird()
                
                # Bind keys
                self.root.bind("<space>", self.flap)
                self.root.bind("<Up>", self.flap)
                self.root.bind("<Escape>", self.quit_game)
                
                # Start game loop in a separate thread
                self.game_thread = threading.Thread(target=self.game_loop, daemon=True)
                self.game_thread.start()
                
                # Start pipe generation
                self.root.after(1000, self.generate_pipe)
                
                # Handle window close
                self.root.protocol("WM_DELETE_WINDOW", self.cleanup)
            
            def load_high_score(self):
                try:
                    with open('flappy_highscore.txt', 'r') as f:
                        return int(f.read())
                except (FileNotFoundError, ValueError):
                    return 0
            
            def save_high_score(self):
                with open('flappy_highscore.txt', 'w') as f:
                    f.write(str(max(self.score, self.high_score)))
            
            def update_score_display(self):
                self.score_var.set(f"Score: {self.score}  |  High: {max(self.score, self.high_score)}")
            
            def draw_background(self):
                # Sky
                self.canvas.create_rectangle(0, 0, self.WIDTH, self.HEIGHT, fill=self.SKY_BLUE, outline="")
                
                # Ground
                ground_height = 100
                self.canvas.create_rectangle(0, self.HEIGHT - ground_height, self.WIDTH, self.HEIGHT, 
                                          fill=self.GRASS_GREEN, outline="")
                
                # Sun
                self.canvas.create_oval(self.WIDTH - 80, 40, self.WIDTH - 20, 100, 
                                     fill="#FFD700", outline="")
            
            def draw_bird(self):
                # Delete previous bird if it exists
                if hasattr(self, 'bird_item'):
                    self.canvas.delete(self.bird_item)
                
                # Calculate wing flap animation
                wing_offset = math.sin(self.bird_flap) * 3
                self.bird_flap += 0.3
                
                # Calculate rotation based on velocity
                self.bird_rotation = max(-30, min(30, self.bird_velocity * 3))
                rad = math.radians(self.bird_rotation)
                
                # Bird body
                x1, y1 = self.bird_x, self.bird_y
                x2, y2 = x1 + self.bird_size, y1 + self.bird_size
                
                # Create bird with rotation
                self.bird_item = self.canvas.create_polygon(
                    x1 + self.bird_size//2, y1 + wing_offset,  # Top center (beak)
                    x2, y1 + self.bird_size//3,               # Right wing tip
                    x2 - self.bird_size//3, y1 + self.bird_size//2,  # Right body
                    x2, y2 - self.bird_size//3,               # Right wing bottom
                    x1 + self.bird_size//2, y2 - wing_offset,  # Bottom center (tail)
                    x1 + self.bird_size//3, y2 - self.bird_size//3,  # Left wing bottom
                    x1, y1 + self.bird_size//2,               # Left wing tip
                    x1 + self.bird_size//3, y1 + self.bird_size//3,  # Left body
                    fill=self.BIRD_YELLOW, outline=self.BLACK, width=1
                )
                
                # Add eye
                eye_x = x1 + self.bird_size * 0.6
                eye_y = y1 + self.bird_size * 0.3
                self.canvas.create_oval(eye_x, eye_y, eye_x + 4, eye_y + 4, 
                                     fill=self.BLACK, outline="")
            
            def flap(self, event=None):
                if not self.game_over:
                    self.bird_velocity = self.FLAP_STRENGTH
                    self.bird_flap = 0  # Reset wing flap animation
                else:
                    self.reset_game()
            
            def generate_pipe(self):
                if not self.game_over and self.running:
                    gap_y = random.randint(150, self.HEIGHT - 150)
                    
                    # Create top pipe with a cap
                    top_pipe = self.canvas.create_rectangle(
                        self.WIDTH, 0,
                        self.WIDTH + 60, gap_y - self.PIPE_GAP // 2,
                        fill=self.PIPE_GREEN, outline=""
                    )
                    self.canvas.create_rectangle(
                        self.WIDTH - 5, gap_y - self.PIPE_GAP // 2 - 20,
                        self.WIDTH + 65, gap_y - self.PIPE_GAP // 2,
                        fill=self.PIPE_GREEN, outline=""
                    )
                    
                    # Create bottom pipe with a cap
                    bottom_pipe = self.canvas.create_rectangle(
                        self.WIDTH, gap_y + self.PIPE_GAP // 2,
                        self.WIDTH + 60, self.HEIGHT,
                        fill=self.PIPE_GREEN, outline=""
                    )
                    self.canvas.create_rectangle(
                        self.WIDTH - 5, gap_y + self.PIPE_GAP // 2,
                        self.WIDTH + 65, gap_y + self.PIPE_GAP // 2 + 20,
                        fill=self.PIPE_GREEN, outline=""
                    )
                    
                    self.pipes.append({
                        'top': top_pipe,
                        'bottom': bottom_pipe,
                        'x': self.WIDTH,
                        'gap_y': gap_y,
                        'passed': False,
                        'top_cap': top_pipe + 1,
                        'bottom_cap': bottom_pipe + 1
                    })
                    
                    # Schedule next pipe
                    if self.running and not self.game_over:
                        self.root.after(self.PIPE_FREQUENCY, self.generate_pipe)
            
            def game_loop(self):
                last_time = time.time()
                while self.running:
                    current_time = time.time()
                    delta_time = (current_time - last_time) * 60  # Normalize to 60 FPS
                    last_time = current_time
                    
                    if not self.game_over:
                        # Update bird
                        self.bird_velocity += self.GRAVITY * delta_time
                        self.bird_y += self.bird_velocity
                        
                        # Keep bird on screen
                        if self.bird_y < 0:
                            self.bird_y = 0
                            self.bird_velocity = 0
                        
                        # Check for ground collision
                        if self.bird_y > self.HEIGHT - self.bird_size - 100:  # 100 is ground height
                            self.bird_y = self.HEIGHT - self.bird_size - 100
                            self.game_over = True
                        
                        # Update bird position and rotation
                        self.root.after(0, self.update_bird_position)
                        
                        # Update pipes
                        self.update_pipes(delta_time)
                        
                        # Check for game over
                        if self.game_over:
                            self.root.after(0, self.show_game_over)
                    
                    # Cap the frame rate
                    time.sleep(max(0, (1/60) - (time.time() - current_time)))
            
            def update_bird_position(self):
                if not self.running:
                    return
                self.draw_bird()
            
            def update_pipes(self, delta_time):
                for pipe in self.pipes[:]:
                    if not self.running:
                        return
                        
                    # Move pipe with smooth delta time
                    pipe_speed = self.PIPE_SPEED * delta_time
                    pipe['x'] -= pipe_speed
                    
                    # Update pipe positions
                    self.canvas.move(pipe['top'], -pipe_speed, 0)
                    self.canvas.move(pipe['bottom'], -pipe_speed, 0)
                    self.canvas.move(pipe['top_cap'], -pipe_speed, 0)
                    self.canvas.move(pipe['bottom_cap'], -pipe_speed, 0)
                    
                    # Check for scoring
                    if pipe['x'] + 50 < self.bird_x and not pipe['passed']:
                        pipe['passed'] = True
                        self.score += 1
                        self.update_score_display()
                        
                        # Visual feedback for scoring
                        self.score_label.config(fg='#FFD700')
                        self.root.after(100, lambda: self.score_label.config(fg='white'))
                    
                    # Check for collisions
                    if not self.game_over and self.check_collision(pipe):
                        self.game_over = True
                        self.root.after(0, self.show_game_over)
                        return
                    
                    # Remove off-screen pipes
                    if pipe['x'] < -100:
                        self.canvas.delete(pipe['top'])
                        self.canvas.delete(pipe['bottom'])
                        self.canvas.delete(pipe['top_cap'])
                        self.canvas.delete(pipe['bottom_cap'])
                        self.pipes.remove(pipe)
            
            def check_collision(self, pipe):
                # Get bird's bounding box with a bit of padding
                bird_bbox = [
                    self.bird_x + 5,
                    self.bird_y + 5,
                    self.bird_x + self.bird_size - 5,
                    self.bird_y + self.bird_size - 5
                ]
                
                # Get pipe's bounding boxes
                top_bbox = self.canvas.bbox(pipe['top'])
                bottom_bbox = self.canvas.bbox(pipe['bottom'])
                
                # Check for collision with top pipe
                if (bird_bbox[2] > top_bbox[0] and bird_bbox[0] < top_bbox[2] and
                    bird_bbox[3] > top_bbox[1] and bird_bbox[1] < top_bbox[3]):
                    return True
                
                # Check for collision with bottom pipe
                if (bird_bbox[2] > bottom_bbox[0] and bird_bbox[0] < bottom_bbox[2] and
                    bird_bbox[3] > bottom_bbox[1] and bird_bbox[1] < bottom_bbox[3]):
                    return True
                
                return False
            
            def show_game_over(self):
                if not self.running or not hasattr(self, 'canvas'):
                    return
                    
                # Save high score if needed
                if self.score > self.high_score:
                    self.high_score = self.score
                    self.save_high_score()
                
                # Create semi-transparent overlay
                overlay = self.canvas.create_rectangle(
                    0, 0, self.WIDTH, self.HEIGHT,
                    fill="black", stipple="gray50"
                )
                self.canvas.itemconfig(overlay, state='normal')
                
                # Game over text
                self.canvas.create_text(
                    self.WIDTH // 2, self.HEIGHT // 2 - 50,
                    text="GAME OVER",
                    font=('Arial', 32, 'bold'),
                    fill="#FF3333",
                    justify='center'
                )
                
                # Score display
                self.canvas.create_text(
                    self.WIDTH // 2, self.HEIGHT // 2 + 10,
                    text=f"Score: {self.score}\nHigh Score: {self.high_score}",
                    font=('Arial', 18, 'bold'),
                    fill="white",
                    justify='center'
                )
                
                # Instructions
                self.canvas.create_text(
                    self.WIDTH // 2, self.HEIGHT - 80,
                    text="Press SPACE to restart\nESC to quit",
                    font=('Arial', 14),
                    fill="white",
                    justify='center'
                )
            
            def reset_game(self):
                # Clear the canvas
                self.canvas.delete("all")
                
                # Reset game variables
                self.score = 0
                self.update_score_display()
                self.game_over = False
                self.pipes = []
                
                # Reset bird
                self.bird_y = self.HEIGHT // 2
                self.bird_velocity = 0
                self.bird_rotation = 0
                
                # Redraw background and bird
                self.draw_background()
                self.draw_bird()
                
                # Restart pipe generation
                self.root.after(1000, self.generate_pipe)
            
            def quit_game(self, event=None):
                self.cleanup()
            
            def cleanup(self):
                self.running = False
                if hasattr(self, 'root') and self.root.winfo_exists():
                    # Save high score before quitting
                    if hasattr(self, 'score') and hasattr(self, 'high_score'):
                        self.save_high_score()
                    self.root.destroy()
        
        # Create a new thread for the game window
        def start_game():
            game_root = Tk()
            game_root.withdraw()  # Hide the root window
            
            # Create and start the game
            game_window = Toplevel(game_root)
            game = FlappyBirdGame(game_window)
            
            # Handle window close
            def on_close():
                game.cleanup()
                game_root.destroy()
            
            game_window.protocol("WM_DELETE_WINDOW", on_close)
            
            # Start the game's main loop
            game_root.mainloop()
        
        # Start the game in a separate thread
        game_thread = threading.Thread(target=start_game, daemon=True)
        game_thread.start()
    
    def _populate_na_tab(self, frame, theme):
        if frame == self.encryption_frame:
            self._populate_encryption_tab(frame, theme)
            return

        inner = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=20)
        inner.pack(expand=True, fill="both")

        if frame == self.general_frame:
            # Add Play a Game button
            play_game_btn = NeoUIHoverButton(
                inner,
                text="Play a Game",
                command=self._play_flappy_bird,
                bg=theme["accent"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11, "bold"),
                relief="flat",
                padx=15,
                pady=8
            )
            play_game_btn.pack(pady=(0, 10), fill="x")
            
            open_ffedata_btn = NeoUIHoverButton(
                inner,
                text="Open Configuration File",
                command=lambda: self.open_file_in_default_editor("ffeconfig.json"),
                bg=theme["accent"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11, "bold"),
                relief="flat",
                padx=15,
                pady=8
            )
            open_ffedata_btn.pack(pady=(0, 10), fill="x")

            clear_key_btn = NeoUIHoverButton(
                inner,
                text="Clear & Regenerate Key",
                command=self._clear_key,
                bg=theme["warning"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11, "bold"),
                relief="flat",
                padx=15,
                pady=8
            )
            clear_key_btn.pack(pady=(0, 10), fill="x")

            clear_data_btn = NeoUIHoverButton(
                inner,
                text="Clear Data",
                command=self._clear_data,
                bg=theme["error"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11, "bold"),
                relief="flat",
                padx=15,
                pady=8
            )
            clear_data_btn.pack(pady=(0, 10), fill="x")

            close_gen_btn = NeoUIHoverButton(
                inner,
                text="Force Quit",
                command=sys.exit,
                bg=theme["error"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11, "bold"),
                relief="flat",
                padx=15,
                pady=8
            )
            close_gen_btn.pack(pady=(0, 10), fill="x")

            info_label = tk.Label(
                inner,
                text="\nOpen Configuration File: Opens the configuration file in the default text editor\nClear & Regenerate Key: Deletes and generates a new encryption key\nClear Data: Resets all settings to default\nForce Quit: Forcefully quits the application",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 9),
                justify="left"
            )
            info_label.pack(pady=(20, 0), anchor="w")

    def _on_security_radio_change(self, level):
        """Handle changes to the security level radio buttons."""
        # Update the security level variable (already set by the radio button)
        # Just need to update the settings
        self._update_encryption_default()

    def _update_encryption_default(self, *args):
        """Update the default encryption settings."""
        if not hasattr(self, 'parent'):
            return

        # Ensure encryption settings exist
        if "encryption" not in self.parent.settings:
            self.parent.settings["encryption"] = {}

        # Update encryption method if the variable exists
        if hasattr(self, 'default_enc_method'):
            method = self.default_enc_method.get().lower().replace(' ', '_')  # Convert to lowercase with underscores
            self.parent.settings["encryption"]["default_method"] = method
            
        # Update security level if it exists
        if hasattr(self, 'security_level'):
            self.parent.settings["encryption"]["security_level"] = self.security_level.get()
            
            # For backward compatibility, also update the faster_mode setting
            faster_mode = (self.security_level.get() == "fast")
            self.parent.settings["encryption"]["faster_mode"] = faster_mode

        # Debug output
        print(f"Saving encryption settings: {self.parent.settings.get('encryption', {})}")

        # Save the settings
        if not save_app_settings(self.parent.settings):
            print("Warning: Failed to save encryption settings")

    def _populate_encryption_tab(self, frame, theme):
        container = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=10)
        container.pack(expand=True, fill="both")
        # Title
        tk.Label(
            container,
            text="Encryption Settings",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
        ).pack(anchor="w", pady=(0, 15))

        # Default Encryption Method Section
        default_frame = tk.Frame(container, bg=theme["secondary_bg"])
        default_frame.pack(fill="x", pady=(0, 15))

        tk.Label(
            default_frame,
            text="Default Encryption Method:",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11, "bold"),
        ).pack(anchor="w", pady=(0, 5))

        # Get the current default method from settings
        default_method = self.parent.settings.get("encryption", {}).get("default_method", "password")
        self.default_enc_method = tk.StringVar(value="Password" if default_method == "password" else "Key File")
        self.default_enc_method.trace_add("write", lambda *args: self._update_encryption_default())

        # Method selection
        method_frame = tk.Frame(default_frame, bg=theme["secondary_bg"])
        method_frame.pack(fill="x", pady=5)

        # Password option first
        password_rb = tk.Radiobutton(
            method_frame,
            text="Password",
            variable=self.default_enc_method,
            value="Password",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            selectcolor=theme["accent"],
            activebackground=theme["secondary_bg"],
            activeforeground=theme["text"],
            font=(DEFAULT_FONT, 11),
        )
        password_rb.pack(side="left", padx=(0, 20))

        # Key File option second
        key_file_rb = tk.Radiobutton(
            method_frame,
            text="Key File",
            variable=self.default_enc_method,
            value="Key File",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            selectcolor=theme["accent"],
            activebackground=theme["secondary_bg"],
            activeforeground=theme["text"],
            font=(DEFAULT_FONT, 11),
        )
        key_file_rb.pack(side="left")

        # Password Security Level Section
        security_frame = tk.Frame(container, bg=theme["secondary_bg"])
        security_frame.pack(fill="x", pady=(15, 0))

        # Label for the security level
        tk.Label(
            security_frame,
            text="Password Security Level:",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11, "bold"),
        ).pack(anchor="w", pady=(0, 5))

        # Get current security level from settings
        security_level = self.parent.settings.get("encryption", {}).get("security_level", "balanced")
        self.security_level = tk.StringVar(value=security_level)
        self.security_level.trace_add("write", lambda *args: self._update_encryption_default())
        
        # Create a frame for the radio buttons
        radio_frame = tk.Frame(security_frame, bg=theme["secondary_bg"])
        radio_frame.pack(fill="x", pady=5)

        security_levels = [
            ("fast", "Fast", "25,000 iterations", "Less secure, but faster"),
            ("balanced", "Balanced", "400,000 iterations", "Good balance (recommended)"),
            ("secure", "Secure", "1,250,000 iterations", "More secure, but slower")
        ]
        
        # Create radio buttons for each security level
        for level, name, iters, desc in security_levels:
            # Create a frame for each radio button and its description
            level_frame = tk.Frame(radio_frame, bg=theme["secondary_bg"])
            level_frame.pack(fill="x", pady=3, padx=5)
            
            # Radio button
            rb = tk.Radiobutton(
                level_frame,
                text=name,
                variable=self.security_level,
                value=level,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["secondary_bg"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["accent"],
                font=(DEFAULT_FONT, 10, "bold" if level == security_level else "normal"),
                indicatoron=1,
                command=lambda l=level: self._on_security_radio_change(l)
            )
            rb.pack(anchor="w")
            
            # Description frame for indentation
            desc_frame = tk.Frame(level_frame, bg=theme["secondary_bg"])
            desc_frame.pack(fill="x", padx=20, pady=(0, 5))
            
            # Iteration count and description
            tk.Label(
                desc_frame,
                text=f"{iters} • {desc}",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 9),
                justify="left"
            ).pack(anchor="w")
            
            # Add a separator between options
            if level != "secure":  # Don't add after the last option
                tk.Frame(
                    level_frame,
                    height=1,
                    bg=theme["bg"],
                ).pack(fill="x", pady=5, padx=5)

        # Info text
        tk.Label(
            container,
            text="This sets the default method and security level used when encrypting files.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
        ).pack(anchor="w", pady=(15, 5))

        # Additional info text
        tk.Label(
            container,
            text="Higher security levels use more iterations for key derivation, making them more secure but slower.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
        ).pack(anchor="w", pady=(0, 0))

    def _populate_themes_tab(self, frame, theme):
        container = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=10)
        container.pack(expand=True, fill="both")

        tk.Label(
            container,
            text="Interface Theme",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        self.theme_var = tk.StringVar(value=self.parent.current_theme)

        # List of disabled themes
        # DO NOT DISABLE DEFAULT THEME (i.e. Ocean Deep)
        self.disabled_themes = [""]

        # Get all available themes
        themes = list(NeoUIThemes.THEMES.keys())

        # Ensure current theme is not disabled
        if self.parent.current_theme in self.disabled_themes:
            self.theme_var.set("Ocean Deep")
            self.parent.current_theme = "Ocean Deep"

        cols = tk.Frame(container, bg=theme["secondary_bg"])
        cols.pack(fill="x")
        left = tk.Frame(cols, bg=theme["secondary_bg"])
        left.pack(side="left", expand=True, fill="both", padx=(0, 10))
        right = tk.Frame(cols, bg=theme["secondary_bg"])
        right.pack(side="left", expand=True, fill="both")

        mid = (len(themes) + 1) // 2
        for i, name in enumerate(themes):
            parent_col = left if i < mid else right
            row = tk.Frame(parent_col, bg=theme["secondary_bg"])
            row.pack(fill="x", pady=2)

            # Determine if this theme should be disabled
            is_disabled = name in self.disabled_themes

            # Create the radio button
            rb = tk.Radiobutton(
                row,
                text=name,
                variable=self.theme_var,
                value=name,
                bg=theme["secondary_bg"],
                fg=theme["text"] if not is_disabled else "#666666",  # Grey out text if disabled
                selectcolor=theme["accent"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"] if not is_disabled else "#666666",
                font=(DEFAULT_FONT, 11, "italic" if is_disabled else "normal"),
                pady=3,
                command=self._on_theme_change,
                state="disabled" if is_disabled else "normal"
            )
            rb.pack(side="left", anchor="w")

            # Add a small indicator for disabled themes
            if is_disabled:
                tk.Label(
                    row,
                    text="(coming soon)",
                    bg=theme["secondary_bg"],
                    fg="#666666",
                    font=(DEFAULT_FONT, 8, "italic"),
                ).pack(side="left", padx=(5, 0))

        hint = tk.Label(
            container,
            text="Changing the theme may require you to close and re-open the Settings menu.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
        )
        hint.pack(anchor="w", pady=(8, 0))

    def _on_theme_change(self):
        chosen = self.theme_var.get()
        if chosen in self.disabled_themes:
            self.theme_var.set(self.original_theme)  # Reset to original theme
            return
            
        # Store the chosen theme for preview
        self.preview_theme = chosen
        
    def _update_theme_preview(self, theme_name):
        """Update the preview to show the selected theme colors without applying them."""
        # This is a no-op now since we're not previewing in the settings window
        pass
        
    def _apply_theme_changes(self):
        """Apply the selected theme to the entire application and save the settings."""
        # Get the currently selected theme
        chosen = self.theme_var.get()
        if chosen in self.disabled_themes:
            return
            
        # Only proceed if the theme has actually changed
        if chosen == self.original_theme and not hasattr(self, 'preview_theme'):
            return
            
        # Update theme in parent
        self.parent.current_theme = chosen

        # Persist theme selection
        if not hasattr(self.parent, 'settings') or not isinstance(self.parent.settings, dict):
            self.parent.settings = {}
        self.parent.settings["theme"] = chosen

        # Update stats for theme changes and usage
        stats = self.parent.settings.setdefault("stats", {})
        stats["theme_changes"] = stats.get("theme_changes", 0) + 1
        theme_usage = stats.setdefault("theme_usage", {})
        theme_usage[chosen] = theme_usage.get(chosen, 0) + 1
        save_app_settings(self.parent.settings)

        # Apply theme to main window and all widgets
        if hasattr(self.parent, 'apply_theme'):
            self.parent.apply_theme()
            
        # Update the settings window to match the new theme
        self._update_settings_window_theme(chosen)
        
        # Clear the preview theme
        if hasattr(self, 'preview_theme'):
            delattr(self, 'preview_theme')
            
    def _on_cancel(self):
        """Revert to the original theme and close the dialog."""
        # No need to revert theme changes as they were only applied to the preview
        self.destroy()
        
    def destroy(self):
        """Apply theme changes before destroying the dialog."""
        self._apply_theme_changes()
        super().destroy()

    def _update_settings_window_theme(self, theme_name):
        """Update the settings window to use the specified theme.
        This is only called when applying the theme, not for preview."""
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])
        
        # Update window background
        self.configure(bg=theme["secondary_bg"])

        # Update notebook style
        self._apply_notebook_style(theme_name)

        # Update all widgets in the main frame
        for widget in self.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg=theme["secondary_bg"])
                for child in widget.winfo_children():
                    self._update_widget_theme(child, theme)

        # Update selector bar
        self._style_selector(theme)
        
        # Force update the window
        self.update_idletasks()

    def _update_widget_theme(self, widget, theme):
        """Update widget and its children to match the new theme."""
        try:
            if 'bg' in widget.keys():
                widget.configure(bg=theme["secondary_bg"])
            if 'fg' in widget.keys():
                widget.configure(fg=theme["text"])
            if 'selectcolor' in widget.keys():
                widget.configure(selectcolor=theme["accent"])
            if 'activebackground' in widget.keys():
                widget.configure(activebackground=theme["secondary_bg"])
            if 'activeforeground' in widget.keys():
                widget.configure(activeforeground=theme["text"])
        except Exception:
            pass

        # Update children
        for child in widget.winfo_children():
            self._update_widget_theme(child, theme)

    def _populate_stats_tab(self, frame, theme):
        container = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=10)
        container.pack(expand=True, fill="both")

        tk.Label(
            container,
            text="Usage Statistics",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        stats = (getattr(self.parent, 'settings', {}) or {}).get("stats", {})
        fe = stats.get("files_encrypted", 0)
        fd = stats.get("files_decrypted", 0)
        fdel = stats.get("files_deleted", 0)
        fwd = stats.get("forward_count", 0)
        back = stats.get("back_count", 0)
        ref = stats.get("refresh_count", 0)
        tch = stats.get("theme_changes", 0)
        tusage = stats.get("theme_usage", {})

        most_used_theme = "N/A"
        if isinstance(tusage, dict) and tusage:
            most_used_theme = max(tusage.items(), key=lambda kv: (kv[1], kv[0]))[0]

        items = [
            ("Files Encrypted", fe),
            ("Files Decrypted", fd),
            ("Files Deleted", fdel),
            ("Times Went Forward", fwd),
            ("Times Went Back", back),
            ("Times Refreshed", ref),
            ("Theme Changes", tch),
            ("Most Used Theme", most_used_theme),
        ]

        for name, val in items:
            row = tk.Frame(container, bg=theme["secondary_bg"]) ; row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{name}:", bg=theme["secondary_bg"], fg=theme["text"], font=(DEFAULT_FONT, 11, "bold")).pack(side="left")
            tk.Label(row, text=str(val), bg=theme["secondary_bg"], fg=theme["text"], font=(DEFAULT_FONT, 11)).pack(side="left", padx=(6,0))

    def _populate_update_tab(self, frame, theme):
        container = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=10)
        container.pack(expand=True, fill="both")

        tk.Label(
            container,
            text="Updates",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        desc = tk.Label(
            container,
            text="""Check for FFE Updates to add new features, fix bugs, and improve stability and security.

Current Version: 3.0.0 "Lyrah" Developer Beta 5
Current Build: ffe_120325_300_db5

Caution! This is a beta build that cannot update.
Utilize the GitHub to manually download the next beta or stable release.
            
            """,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10),
        )
        desc.pack(anchor="w", pady=(0, 10))

        check_btn = NeoUIHoverButton(
            container,
            text="                                              Check For Updates                                              ",
            command=self.parent.update_ffe,
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
        )
        check_btn.pack(anchor="w")

    def _update_selector_active(self):
        if not hasattr(self, 'tab_buttons') or not self.tab_buttons:
            return

        theme = NeoUIThemes.THEMES.get(self.parent.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        accent = theme["accent"]
        norm_fg = theme["text"]
        sel_fg = theme["text"]
        bg = theme["secondary_bg"]

        # First, hide all indicators and reset button styles
        for name, obj in self.tab_buttons.items():
            btn = obj["button"]
            ind = obj["indicator"]
            btn.configure(bg=bg, fg=norm_fg, font=(DEFAULT_FONT, 11))
            ind.pack_forget()  # Hide all indicators

        # Then show the selected tab's indicator and update its style
        if hasattr(self, 'selected_tab_name'):
            selected_obj = self.tab_buttons.get(self.selected_tab_name)
            if selected_obj:
                btn = selected_obj["button"]
                ind = selected_obj["indicator"]
                btn.configure(bg=bg, fg=sel_fg, font=(DEFAULT_FONT, 11, "bold"))
                ind.pack(fill="x", expand=True, pady=(3, 0))  # Show indicator for selected tab

    def _build_selector_bar(self, parent, theme):
        # Create the main selector bar with a subtle border at the bottom
        bar = tk.Frame(parent, bg=theme["secondary_bg"])
        bar.pack(fill="x", pady=(0, 0), padx=0)
        self.selector_bar = bar
        self.tab_buttons = {}

        tabs = [
            ("General", self.general_frame),
            ("Themes", self.themes_frame),
            ("Encryption", self.encryption_frame),
            ("Stats", self.stats_frame),
            ("Update", self.update_frame),
        ]

        def make_handler(name, frame):
            def _h():
                try:
                    self.notebook.select(frame)
                except Exception:
                    pass
                self.selected_tab_name = name
                self._update_selector_active()
            return _h

        # Create a frame to contain the tab buttons and center them
        tabs_container = tk.Frame(bar, bg=theme["secondary_bg"])
        tabs_container.pack(fill="x", expand=True, padx=20, pady=(10, 0))

        # Add a left padding to center the tabs
        left_pad = tk.Frame(tabs_container, width=0, bg=theme["secondary_bg"])
        left_pad.pack(side="left", expand=True)

        for name, frame in tabs:
            # Create a container frame for each tab to handle the indicator
            tab_frame = tk.Frame(tabs_container, bg=theme["secondary_bg"])
            tab_frame.pack(side="left", padx=(0, 8), pady=0)

            btn = NeoUIHoverButton(
                tab_frame,
                text=name,
                command=make_handler(name, frame),
                bg=theme["secondary_bg"],
                fg=theme["text"],
                relief="flat",
                font=(DEFAULT_FONT, 11, "bold"),
                padx=10,
                pady=8
            )
            btn.pack(fill="x", expand=True)

            # Accent indicator line under each button (shown only for selected)
            indicator = tk.Frame(tab_frame, bg=theme["accent"], height=3)
            indicator.pack(fill="x", expand=True, pady=(3, 0))
            indicator.pack_forget()  # Hide by default, shown for active tab

            self.tab_buttons[name] = {"button": btn, "indicator": indicator}

        # Add right padding to balance the left padding
        right_pad = tk.Frame(tabs_container, width=0, bg=theme["secondary_bg"])
        right_pad.pack(side="left", expand=True)

        # Default selection: show General page immediately
        self.selected_tab_name = "General"
        try:
            self.notebook.select(self.general_frame)
        except Exception:
            pass
        self._update_selector_active()
        
        # Set window close behavior to match cancel
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _style_selector(self, theme):
        if hasattr(self, 'selector_bar') and self.selector_bar:
            self.selector_bar.configure(bg=theme["secondary_bg"])
        if hasattr(self, 'tab_buttons'):
            for name, obj in self.tab_buttons.items():
                btn = obj["button"]
                ind = obj["indicator"]
                btn.configure(bg=theme["secondary_bg"], fg=theme["text"])

    # i needed this because i kept misclicking and bombing my entire ffeconfig.json. lovely.
    # writing this comments keeps throwing text issues in pycharm.. i gotta go back to primary school ig
    # never mind, the ignore button exists. this is a case where i can run from my problems instead of actually fixing them. yay.

    def _reset_settings(self):
        if show_neoui_question(
            self,
            "Confirm Reset",
            "Are you sure you want to reset all settings to default?\n\nThis will reset all your preferences and statistics."
        ):
            try:
                # Reset settings to default
                default_settings = {
                    "theme": "Ocean Deep",
                    "stats": {
                        "files_encrypted": 0,
                        "files_decrypted": 0,
                        "files_deleted": 0,
                        "forward_count": 0,
                        "back_count": 0,
                        "refresh_count": 0,
                        "theme_changes": 0,
                        "theme_usage": {}
                    }
                }
                with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(default_settings, f, indent=2)

                # Update current theme in parent
                self.parent.current_theme = "Ocean Deep"
                self.parent.settings = default_settings

                # Update theme immediately
                self._update_settings_window_theme(NeoUIThemes.THEMES["Ocean Deep"])

                show_neoui_info(self, "Success", "All settings have been reset to default.")
            except Exception as e:
                show_neoui_error(self, "Error", f"Failed to reset settings: {str(e)}")

    def _clear_key(self):
        """Delete and generate a new encryption key"""
        if show_neoui_question(
            self,
            "Confirm Key Regeneration",
            "WARNING: This will delete your current encryption key and generate a new one.\n\n"
            "Any files encrypted with the old key will no longer be decryptable.\n\n"
            "Make sure you have decrypted all your files before proceeding.\n\n"
            "Are you sure you want to continue?"
        ):
            try:
                key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "main_key.key")
                if os.path.exists(key_path):
                    os.remove(key_path)

                # Generate a new key
                self.parent.main_key = self.parent.load_main_key()
                show_neoui_info(
                    self,
                    "Success",
                    "A new encryption key has been generated.\n\n"
                    "Please make sure to back up the new key file (main_key.key)."
                )
            except Exception as e:
                show_neoui_error(self, "Error", f"Failed to regenerate encryption key: {str(e)}")

    def _clear_data(self):
        """Clear all application data and settings"""
        if show_neoui_question(
            self,
            "Confirm Data Deletion",
            "WARNING: This will delete all application data and settings.\n\n"
            "This includes:\n"
            "- All settings and preferences\n"
            "- Statistics and usage data\n"
            "- Any custom configurations\n\n"
            "This action cannot be undone. Are you sure you want to continue?"
        ):
            try:
                # Paths to clear
                data_files = [
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffeconfig.json"),
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffeconfig.json")
                ]

                # Remove data files
                for file_path in data_files:
                    if os.path.exists(file_path):
                        os.remove(file_path)

                # Reset in-memory settings
                if hasattr(self.parent, 'settings'):
                    self.parent.settings = self.parent.load_settings()

                show_neoui_info(
                    self,
                    "Data Cleared",
                    "All application data and settings have been cleared.\n\n"
                    "The application will now restart to apply changes."
                )

                # Restart the application
                self.parent.restart_application()

            except Exception as e:
                show_neoui_error(
                    self,
                    "Error",
                    f"Failed to clear application data: {str(e)}"
                )

    def _apply_notebook_style(self, theme_name):
        style = ttk.Style()
        # Prefer 'clam' if available for better ttk visuals
        if 'clam' in style.theme_names():
            style.theme_use('clam')
        else:
            style.theme_use('default')

        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])
        style.configure('TNotebook', background=theme["secondary_bg"], borderwidth=0)
        style.configure('TNotebook.Tab',
                        background=theme["secondary_bg"],
                        foreground=theme["text"],
                        borderwidth=0,
                        padding=[38, 8],
                        font=(DEFAULT_FONT, 10))
        style.map('TNotebook.Tab',
                  background=[('selected', theme["accent"])],
                  foreground=[('selected', theme["text"])])

        # Hide native tab headers entirely; we use our custom selector bar
        try:
            style.layout('TNotebook.Tab', [])
        except Exception:
            pass


class FileContextMenu(tk.Menu):
    def __init__(self, parent, theme):
        super().__init__(parent, tearoff=0)
        self.parent = parent
        self.theme = theme
        self.configure(
            bg=theme["secondary_bg"],
            fg=theme["text"],
            activebackground=theme["accent"],
            activeforeground=theme["text"],
            bd=1,
            relief="solid"
        )

        # Add submenu for encryption options
        self.encrypt_menu = tk.Menu(self, tearoff=0, bg=theme["secondary_bg"], fg=theme["text"],
                                  activebackground=theme["accent"], activeforeground=theme["text"])
        self.encrypt_menu.add_command(
            label="With Key File",
            command=self.encrypt_with_key_file,
            foreground=theme["success"]
        )
        self.encrypt_menu.add_command(
            label="With Password",
            command=self.fesys_encrypt_with_password,
            foreground=theme["success"]
        )
        self.add_cascade(label="Encrypt", menu=self.encrypt_menu, foreground=theme["success"])
        self.add_command(
            label="Decrypt",
            command=self.decrypt_file,
            foreground=theme["accent"]
        )
        self.add_separator()
        # Add Info button with info color from theme
        self.add_command(
            label="Info",
            command=self.show_file_info,
            foreground=NeoUIThemes.get_dialog_colors("info", getattr(parent, 'current_theme', 'Ocean Deep'))
        )
        self.add_separator()
        self.add_command(
            label="Rename",
            command=self.rename_file,
            foreground=theme["text"]
        )
        self.add_command(
            label="Delete",
            command=self.delete_file,
            foreground=theme["error"]
        )

    def show(self, event):
        try:
            # Select the item under the cursor
            index = self.parent.file_listbox.nearest(event.y)
            if index >= 0:
                self.parent.file_listbox.selection_clear(0, tk.END)
                self.parent.file_listbox.selection_set(index)
                self.parent.file_listbox.activate(index)
                self.tk_popup(event.x_root, event.y_root)
        finally:
            self.grab_release()

    def get_selected_file(self):
        try:
            selected_index = self.parent.file_listbox.curselection()[0]
            return self.parent.file_paths[selected_index]
        except (IndexError, AttributeError):
            return None

    def encrypt_with_key_file(self):
        file_path = self.get_selected_file()
        if file_path and os.path.isfile(file_path):
            self.parent.encrypt_with_key_file()

    def fesys_encrypt_with_password(self):
        file_path = self.get_selected_file()
        if file_path and os.path.isfile(file_path):
            self.parent.fesys_encrypt_with_password()

    def decrypt_file(self):
        file_path = self.get_selected_file()
        if file_path and os.path.isfile(file_path):
            self.parent.decrypt_file()

    def rename_file(self):
        file_path = self.get_selected_file()
        if file_path:
            old_name = os.path.basename(file_path)
            # Use neoui dialog for renaming
            dialog = neouiDialog(
                self.parent,
                "Rename File",
                f"Enter new name for:\n{old_name}",
                dialog_type="info"
            )
            new_name = dialog.result
            if new_name and new_name != old_name:
                try:
                    new_path = os.path.join(os.path.dirname(file_path), new_name)
                    os.rename(file_path, new_path)
                    self.parent.refresh_view()
                except Exception as e:
                    show_neoui_error(self.parent, "Error", f"Failed to rename: {str(e)}")

    def get_file_info(self, file_path):
        """Get formatted information about a file."""
        if not file_path or not os.path.exists(file_path):
            return None

        is_encrypted = file_path.lower().endswith('.enc')
        is_dir = os.path.isdir(file_path)

        # Get file size
        if is_dir:
            size = "<DIR>"
        else:
            size = self._format_size(os.path.getsize(file_path))

        # Get file type
        file_type = "Directory" if is_dir else "File"
        if not is_dir:
            _, ext = os.path.splitext(file_path)
            if ext:
                file_type += f" ({ext.upper().lstrip('.')})"

        # Get last modified time
        mtime = os.path.getmtime(file_path)
        from datetime import datetime
        last_modified = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

        # Check if it's a password-encrypted file
        encryption_type = "None"
        if is_encrypted and not is_dir:
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(3)
                    if header == b"PWD":
                        encryption_type = "Password (AES-GCM)"
                    else:
                        encryption_type = "Key File (AES-256)"
            except:
                encryption_type = "Unknown"

        return {
            'name': os.path.basename(file_path),
            'path': file_path,
            'type': file_type,
            'size': size,
            'encryption': encryption_type,
            'modified': last_modified
        }

    def _format_size(self, size_bytes):
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    def show_file_info(self):
        """Show file information in a neoui dialog."""
        file_path = self.get_selected_file()
        if not file_path:
            return

        info = self.get_file_info(file_path)
        if not info:
            show_neoui_error(self.parent, "Error", "Could not retrieve file information.")
            return

        # Format the message with file information
        message = (
            f"Name: {info['name']}\n"
            f"Type: {info['type']}\n"
            f"Size: {info['size']}\n"
            f"Encryption: {info['encryption']}\n"
            f"Modified: {info['modified']}\n"
            f"\nLocation:\n{info['path']}"
        )

        # Show the information in a neoui dialog
        dialog = neouiDialog(
            self.parent,
            "File Information",
            message,
            dialog_type="info"
        )

    def show_delete_dialog(self, file_path):
        """Show a dialog with options for normal or secure delete."""
        if not file_path:
            return

        filename = os.path.basename(file_path)

        # Create a custom dialog for delete options
        dialog = tk.Toplevel(self.parent)
        dialog.title("Delete File")
        dialog.resizable(False, False)
        dialog.transient(self.parent)
        dialog.grab_set()

        # Get theme
        theme = NeoUIThemes.THEMES.get(getattr(self.parent, 'current_theme', 'Ocean Deep'),
                                           NeoUIThemes.THEMES["Ocean Deep"])
        accent_color = NeoUIThemes.get_dialog_colors("info", self.parent.current_theme)

        # Configure dialog
        dialog.configure(bg=theme["secondary_bg"])

        # Create main frame with consistent padding
        main_frame = tk.Frame(dialog, bg=theme["secondary_bg"], padx=25, pady=20)
        main_frame.pack(expand=True, fill="both")

        # Title
        title_label = tk.Label(
            main_frame,
            text=f"Delete '{filename}'?",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=("Segoe UI", 14, "bold"),
            justify="left"
        )
        title_label.pack(anchor="w", pady=(0, 15))

        # Message
        msg_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        msg_frame.pack(fill="x", pady=(0, 15))

        msg = tk.Label(
            msg_frame,
            text="How would you like to delete this file?",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=("Segoe UI", 11),
            justify="left"
        )
        msg.pack(anchor="w")

        # Buttons frame (for consistent button sizing)
        buttons_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        buttons_frame.pack(fill="x", pady=(15, 10))  # Added top padding to compensate for removed warning

        # Button style configuration - matching the app's standard button style
        btn_font = ("Segoe UI", 11)  # Slightly larger font like other buttons
        btn_pady = 8  # More padding for taller buttons
        btn_height = 1  # Standard height
        
        # Button frame with consistent padding
        action_buttons_frame = tk.Frame(buttons_frame, bg=theme["secondary_bg"])
        action_buttons_frame.pack(fill="x", pady=(0, 10))

        # Secure Delete button - Success style (left side)
        secure_btn = NeoUIHoverButton(
            action_buttons_frame,
            text="   Secure Delete   ",  # Added padding with spaces for better width
            command=lambda: self._perform_delete(file_path, secure=True, dialog=dialog),
            bg=NeoUIThemes.get_dialog_colors("success", self.parent.current_theme),
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "success"),
            font=btn_font,
            relief="flat",
            height=btn_height,
            pady=btn_pady
        )
        secure_btn.pack(side="left", expand=True, fill="x", padx=(0, 10))

        # Normal Delete button - Warning style (right side)
        normal_btn = NeoUIHoverButton(
            action_buttons_frame,
            text=" Delete ",  # Added padding with spaces for better width
            command=lambda: self._perform_delete(file_path, secure=False, dialog=dialog),
            bg=theme["warning"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "warning"),
            font=btn_font,
            relief="flat",
            height=btn_height,
            pady=btn_pady
        )
        normal_btn.pack(side="left", expand=True, fill="x")

        # Cancel button (full width, below) - Using accent color like other dialogs
        cancel_btn = NeoUIHoverButton(
            main_frame,
            text="Cancel",
            command=dialog.destroy,
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
            font=btn_font,
            relief="flat",
            height=btn_height,
            pady=btn_pady
        )
        cancel_btn.pack(fill="x", pady=(5, 0))

        # Center the dialog
        dialog.update_idletasks()
        w = 400
        h = 243
        x = (dialog.winfo_screenwidth() // 2) - (w // 2)
        y = (dialog.winfo_screenheight() // 2) - (h // 2)
        dialog.geometry(f"{w}x{h}+{x}+{y}")

        # Set focus to dialog and bind Escape key to cancel
        dialog.focus_set()
        dialog.bind('<Escape>', lambda e: dialog.destroy())

    def _perform_delete(self, file_path, secure=False, dialog=None):
        """Perform the actual file deletion with optional secure delete."""
        try:
            if not os.path.exists(file_path):
                show_neoui_error(self.parent, "Error", "File not found or already deleted.")
                if dialog:
                    dialog.destroy()
                return

            if secure:
                # Secure delete by overwriting with random data before deletion
                try:
                    file_size = os.path.getsize(file_path)
                    with open(file_path, 'rb+') as f:
                        # Overwrite with random data (3 passes for basic security)
                        for _ in range(3):
                            f.seek(0)
                            f.write(os.urandom(file_size))
                            f.flush()
                            os.fsync(f.fileno())
                except Exception as e:
                    show_neoui_error(self.parent, "Error", f"Secure delete failed: {str(e)}\nFalling back to normal delete.")

            # Delete the file
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)

            # Update UI
            self.parent.refresh_view()

            # Close the dialog if it's open
            if dialog:
                dialog.destroy()

        except Exception as e:
            show_neoui_error(self.parent, "Error", f"Failed to delete file: {str(e)}")
            if dialog:
                dialog.destroy()

    def delete_file(self):
        file_path = self.get_selected_file()
        if file_path:
            self.show_delete_dialog(file_path)


class WelcomeWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Setup Assistant")
        self.parent = parent
        self.current_page = 0

        # Get theme
        theme_name = getattr(parent, 'current_theme', 'Ocean Deep')
        self.theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        # Configure window
        self.configure(bg=self.theme["secondary_bg"])
        self.minsize(650, 850)
        self.maxsize(650,850)
        self.resizable(False, False)
        self.transient(parent)

        # Main container
        self.container = tk.Frame(self, bg=self.theme["secondary_bg"])
        self.container.pack(fill="both", expand=True, padx=20, pady=20)

        # Create pages
        self.pages = []
        self._create_welcome_page()
        self._create_theme_page()
        self._create_encryption_page()
        self._create_finish_page()

        # Navigation frame - this will contain our navigation controls
        self.nav_frame = tk.Frame(self.container, bg=self.theme["secondary_bg"])
        self.nav_frame.pack(fill="x", side="bottom", pady=(0, 10))

        # Navigation buttons container with consistent padding
        self.nav_buttons_container = tk.Frame(self.nav_frame, bg=self.theme["secondary_bg"])
        self.nav_buttons_container.pack(fill="x", padx=10, pady=5)
        
        # Left side container for Previous button
        left_frame = tk.Frame(self.nav_buttons_container, bg=self.theme["secondary_bg"])
        left_frame.pack(side="left", fill="x", expand=True)
        
        # Previous button (initially hidden)
        self.prev_btn = NeoUIHoverButton(
            left_frame,
            text="← Previous",
            command=self.prev_page,
            bg=self.theme["bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 10),
            state="disabled",
            width=15,
            padx=10
        )
        self.prev_btn.pack(side="left")

        # Right side container for Next button
        right_frame = tk.Frame(self.nav_buttons_container, bg=self.theme["secondary_bg"])
        right_frame.pack(side="right", fill="x", expand=True)

        # Next/Finish button with consistent styling
        self.next_btn = NeoUIHoverButton(
            right_frame,
            text="Next →",
            command=self.next_page,
            bg=self.theme["accent"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "accent"),
            font=(DEFAULT_FONT, 10, "bold"),
            width=15,
            padx=10
        )
        self.next_btn.pack(side="right")

        # Show first page
        self.show_page(0)

        # Center on screen
        self.update_idletasks()
        w, h = 650, 800
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

        # Make it modal and disable close button (X)
        self.grab_set()
        self.focus_set()
        # Prevent closing with the X button
        self.protocol("WM_DELETE_WINDOW", lambda: None)

    def _create_welcome_page(self):
        # Create main container with border and padding
        page = tk.Frame(self.container, bg=self.theme["secondary_bg"])

        #7689SP69109109101

        # Create a frame for the main content that will expand to fill space
        content_frame = tk.Frame(page, bg=self.theme["secondary_bg"])
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Header with accent color
        header = tk.Frame(content_frame, bg=self.theme["accent"])
        header.pack(fill=tk.X, pady=(0, 20))
        
        # Title in header
        title_label = tk.Label(
            header,
            text="Welcome to FFE",
            bg=self.theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
            font=(DEFAULT_FONT, 20, "bold"),
            pady=15
        )
        title_label.pack()

        # Content frame with flexible space above and below
        content = tk.Frame(content_frame, bg=self.theme["secondary_bg"])
        content.pack(fill="both", expand=True)

        # Version info
        version_label = tk.Label(
            content,
            text="Version 3.0.0 \"Lyrah\" Developer Beta 5",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 12)
        )
        version_label.pack(pady=(0, 20))

        # Welcome message in a frame with subtle border
        msg_frame = tk.Frame(content, bg=self.theme["bg"], bd=1, relief="solid")
        msg_frame.pack(fill="x", pady=10, padx=10, ipadx=10, ipady=10)
        
        welcome_text = (
            "Thank you for choosing Friend File Encryptor!\n\n"
            "This setup will help you configure FFE to your preferences. "
            "You'll be able to choose your preferred theme and set up encryption options.\n"
            "\n"
            "Version 3.0.0 Changelog:\n"
            "\n"
            "- New Settings Menu\n"
            "- Theme Support\n"
            "- New UI Design\n"
            "- Password Encryption Support\n"
            "- Better Encryption\n"
            "- Right Click Context Menu Support\n"
            "- New Setup Assistant\n"
            "\n"
            "\n"
            "Caution! You will not be able to close or use FFE until setup is complete."
        )

        welcome_label = tk.Label(
            msg_frame,
            text=welcome_text,
            bg=self.theme["bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 11),
            justify="left",
            wraplength=500
        )
        welcome_label.pack(pady=10, padx=10)
        
        # Create a bottom frame for the buttons
        bottom_frame = tk.Frame(page, bg=self.theme["secondary_bg"])
        bottom_frame.pack(fill="x", side="bottom", pady=(0, 20))
        
        # Create a container frame for the buttons to center them
        button_container = tk.Frame(bottom_frame, bg=self.theme["secondary_bg"])
        button_container.pack(pady=(20, 0))
        
        # Add the Exit button
        self.exit_btn = NeoUIHoverButton(
            button_container,
            text="Exit",
            command=self.parent.destroy,  # Close the entire application
            bg=self.theme["error"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "error"),
            font=(DEFAULT_FONT, 12, "bold"),
            padx=50,
            pady=10
        )
        self.exit_btn.pack(side="left", padx=10)
        
        # Add the Get Started button
        self.get_started_btn = NeoUIHoverButton(
            button_container,
            text="Get Started",
            command=lambda: self.show_page(1),  # Skip directly to page 2 (index 1)
            bg=self.theme["success"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "success"),
            font=(DEFAULT_FONT, 12, "bold"),
            padx=155,
            pady=10
        )
        self.get_started_btn.pack(side="left", padx=10)
        
        # Initially hidden, will be shown only on first page
        self.get_started_btn.pack_forget()
        
        # Add the page to our pages list
        self.pages.append(page)


    def _create_theme_page(self):
        page = tk.Frame(self.container, bg=self.theme["secondary_bg"], padx=20, pady=10)
        
        # Title with consistent spacing
        title_label = tk.Label(
            page,
            text="Choose a Theme",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
            pady=10,
            anchor="w"
        )
        title_label.pack(fill="x", pady=(0, 10))
        
        # Description in a frame with subtle background
        desc_frame = tk.Frame(page, bg=self.theme["bg"], bd=1, relief="solid")
        desc_frame.pack(fill="x", pady=(0, 20), padx=10, ipadx=10, ipady=10)
        
        desc = tk.Label(
            desc_frame,
            text="Select a theme that matches your style. You can change this later in settings.",
            bg=self.theme["bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 11),
            justify="left"
        )
        desc.pack(anchor="w")

        # Theme selection frame
        main_frame = tk.Frame(page, bg=self.theme["secondary_bg"])
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create theme buttons in a grid
        theme_frame = tk.Frame(main_frame, bg=self.theme["secondary_bg"])
        theme_frame.pack(fill="both", expand=True)
        
        self.theme_var = tk.StringVar(value=getattr(self.parent, 'current_theme', 'Ocean Deep'))
        theme_names = list(NeoUIThemes.THEMES.keys())
        
        # Calculate number of rows needed (2 columns)
        num_rows = (len(theme_names) + 1) // 2
        
        # Configure grid weights
        for i in range(2):
            theme_frame.columnconfigure(i, weight=1, uniform="themes")
        for i in range(num_rows):
            theme_frame.rowconfigure(i, weight=1)

        # Create 2 columns for themes with better styling
        for i, theme_name in enumerate(theme_names):
            row = i // 2
            col = i % 2
            theme = NeoUIThemes.THEMES[theme_name]
            
            # Create a frame for each theme option
            theme_btn_frame = tk.Frame(
                theme_frame, 
                bg=self.theme["secondary_bg"],
                padx=5,
                pady=5
            )
            theme_btn_frame.grid(row=row, column=col, sticky="nsew", padx=5, pady=2)
            
            # Store theme preview frames for later updates
            if not hasattr(self, 'theme_preview_frames'):
                self.theme_preview_frames = {}
            
            # Radio button with custom styling
            btn = tk.Radiobutton(
                theme_btn_frame,
                text=theme_name,
                variable=self.theme_var,
                value=theme_name,
                bg=self.theme["secondary_bg"],
                fg=self.theme["text"],
                selectcolor=self.theme["accent"],
                activebackground=self.theme["secondary_bg"],
                activeforeground=self.theme["text"],
                font=(DEFAULT_FONT, 10, "bold"),
                indicatoron=1,
                command=lambda t=theme_name: self._preview_theme(t)
            )
            btn.pack(anchor="w", fill="x", padx=5, pady=2)
            
            # Add a small preview of the theme colors
            preview_frame = tk.Frame(theme_btn_frame, height=15, bg=theme["accent"], bd=1, relief="solid")
            preview_frame.pack(fill="x", pady=(0, 2))
            self.theme_preview_frames[theme_name] = preview_frame

        # Preview frame with better styling
        preview_frame = tk.Frame(
            page, 
            bg=self.theme["bg"], 
            bd=1, 
            relief="solid",
            padx=15,
            pady=15
        )
        preview_frame.pack(fill="x", pady=(20, 10), padx=10)

        self.preview_label = tk.Label(
            preview_frame,
            text="Theme Preview",
            bg=self.theme["bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 12, "bold"),
            anchor="w"
        )
        self.preview_label.pack(fill="x", pady=(0, 10))

        # Add sample UI elements for preview
        sample_frame = tk.Frame(preview_frame, bg=self.theme["bg"])
        sample_frame.pack(fill="x")
        
        # Sample button
        sample_btn = NeoUIHoverButton(
            sample_frame,
            text="Sample Button",
            bg=self.theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
            font=(DEFAULT_FONT, 10)
        )
        sample_btn.pack(side="left", padx=5, pady=5)
        
        # Sample text
        sample_text = tk.Label(
            sample_frame,
            text="This is sample text in the selected theme.",
            bg=self.theme["bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 10)
        )
        sample_text.pack(side="left", padx=10)
        
        # Store preview widgets for theme updates
        self.preview_widgets = {
            'frame': preview_frame,
            'sample_btn': sample_btn,
            'sample_text': sample_text
        }

        self.pages.append(page)

    def _update_encryption_settings(self):
        """Update encryption settings in ffeconfig.json"""
        try:
            # Load current settings
            settings = load_app_settings()
            
            # Update encryption settings
            if 'encryption' not in settings:
                settings['encryption'] = {}
                
            # Update default encryption method
            method = self.encryption_var.get()
            settings['encryption']['default_method'] = method
            
            # Update faster mode setting if it exists
            if hasattr(self, 'faster_mode_var'):
                settings['encryption']['faster_mode'] = self.faster_mode_var.get()
            
            # Save the updated settings
            save_app_settings(settings)
            
            # If parent has settings, update them too
            if hasattr(self.parent, 'settings'):
                self.parent.settings = settings
                
        except Exception as e:
            print(f"Error updating encryption settings: {e}")

    def _create_encryption_page(self):
        page = tk.Frame(self.container, bg=self.theme["secondary_bg"], padx=20, pady=10)
        
        # Title with consistent spacing
        title_label = tk.Label(
            page,
            text="Encryption Settings",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
            pady=10,
            anchor="w"
        )
        title_label.pack(fill="x", pady=(0, 10))
        
        # Description in a frame with subtle background
        desc_frame = tk.Frame(page, bg=self.theme["bg"], bd=1, relief="solid")
        desc_frame.pack(fill="x", pady=(0, 20), padx=10, ipadx=10, ipady=10)
        
        desc = tk.Label(
            desc_frame,
            text="Configure how you want to encrypt your files. These settings can be changed later in the settings menu.",
            bg=self.theme["bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 11),
            justify="left",
            wraplength=500
        )
        desc.pack(anchor="w")

        # Main content frame
        content_frame = tk.Frame(page, bg=self.theme["secondary_bg"])
        content_frame.pack(fill="both", expand=True, pady=10)

        # Encryption method section
        method_frame = tk.LabelFrame(
            content_frame,
            text=" Default Encryption Method ",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 11, "bold"),
            padx=15,
            pady=10,
            bd=1,
            relief="solid"
        )
        method_frame.pack(fill="x", pady=(0, 20))

        # Add some padding inside the frame
        method_inner = tk.Frame(method_frame, bg=self.theme["secondary_bg"], padx=10, pady=5)
        method_inner.pack(fill="x")

        # Load current settings
        settings = load_app_settings()
        encryption_settings = settings.get('encryption', {})
        default_method = encryption_settings.get('default_method', 'key_file')
        
        self.encryption_var = tk.StringVar(value=default_method)

        # Password option with icon
        pass_frame = tk.Frame(method_inner, bg=self.theme["secondary_bg"])
        pass_frame.pack(fill="x", pady=5)

        pass_icon = tk.Label(
            pass_frame,
            text="🔒",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 12)
        )
        pass_icon.pack(side="left", padx=(0, 10))

        password_btn = tk.Radiobutton(
            pass_frame,
            text="Password (Recommended)",
            variable=self.encryption_var,
            value="password",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            selectcolor=self.theme["accent"],
            activebackground=self.theme["secondary_bg"],
            activeforeground=self.theme["text"],
            font=(DEFAULT_FONT, 11),
            cursor="hand2"
        )
        password_btn.pack(side="left", anchor="w")

        # Key file option with icon
        key_frame = tk.Frame(method_inner, bg=self.theme["secondary_bg"])
        key_frame.pack(fill="x", pady=5)
        
        key_icon = tk.Label(
            key_frame,
            text="🔑",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 12)
        )
        key_icon.pack(side="left", padx=(0, 10))
        
        key_file_btn = tk.Radiobutton(
            key_frame,
            text="Key File",
            variable=self.encryption_var,
            value="key_file",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            selectcolor=self.theme["accent"],
            activebackground=self.theme["secondary_bg"],
            activeforeground=self.theme["text"],
            font=(DEFAULT_FONT, 11),
            cursor="hand2"
        )
        key_file_btn.pack(side="left", anchor="w")
        
        # Performance options section
        perf_frame = tk.LabelFrame(
            content_frame,
            text=" Performance Options ",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 11, "bold"),
            padx=15,
            pady=10,
            bd=1,
            relief="solid"
        )
        perf_frame.pack(fill="x", pady=(0, 20))
        
        perf_inner = tk.Frame(perf_frame, bg=self.theme["secondary_bg"], padx=10, pady=5)
        perf_inner.pack(fill="x")
        
        # Faster mode option
        self.faster_mode_var = tk.BooleanVar(value=encryption_settings.get('faster_mode', False))
        
        faster_frame = tk.Frame(perf_inner, bg=self.theme["secondary_bg"])
        faster_frame.pack(fill="x", pady=5)
        
        faster_icon = tk.Label(
            faster_frame,
            text="⚡",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 12)
        )
        faster_icon.pack(side="left", padx=(0, 10))
        
        faster_cb = tk.Checkbutton(
            faster_frame,
            text="Faster encryption (less secure)",
            variable=self.faster_mode_var,
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            selectcolor=self.theme["accent"],
            activebackground=self.theme["secondary_bg"],
            activeforeground=self.theme["text"],
            font=(DEFAULT_FONT, 11),
            cursor="hand2"
        )
        faster_cb.pack(side="left", anchor="w")
        
        faster_help = tk.Label(
            perf_inner,
            text="Enabling faster mode reduces key derivation iterations for quicker encryption/decryption,\nbut makes it easier for attackers to brute force your password.",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
            justify="left"
        )
        faster_help.pack(fill="x", pady=(5, 0), padx=5, anchor="w")

        self.pages.append(page)

    def _create_finish_page(self):
        page = tk.Frame(self.container, bg=self.theme["secondary_bg"], padx=20, pady=10)

        # Title with consistent spacing
        title_label = tk.Label(
            page,
            text="Setup Complete!",
            bg=self.theme["secondary_bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
            pady=10,
            anchor="w"
        )
        title_label.pack(fill="x", pady=(0, 10))
        
        # Content frame
        content = tk.Frame(page, bg=self.theme["secondary_bg"])
        content.pack(expand=True, fill="both", pady=10)

        # Completion message in a frame with subtle border
        complete_frame = tk.Frame(content, bg=self.theme["bg"], bd=1, relief="solid")
        complete_frame.pack(fill="x", pady=10, padx=10, ipadx=10, ipady=10)
        
        complete_text = (
            "You're all set to use Friend File Encryptor!\n\n"
            "Your preferences have been saved. You can always change these settings "
            "later in the Settings menu (⚙️).\n\n"
            "Click 'Finish' to start using FFE!"
        )

        complete_label = tk.Label(
            complete_frame,
            text=complete_text,
            bg=self.theme["bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 11),
            justify="left",
            wraplength=500
        )
        complete_label.pack(pady=10, padx=10)

        # Features list in a frame with subtle background
        features_frame = tk.Frame(content, bg=self.theme["bg"], bd=1, relief="solid")
        features_frame.pack(fill="x", pady=20, padx=10, ipadx=10, ipady=10)

        # needed some wierd formatting to achieve a decent ui

        # title for whats next section in last page of setup
        features_title = tk.Label(
            features_frame,
            text="""       
        What's Next?
        """,
            bg=self.theme["bg"],
            fg=self.theme["text"],
            font=(DEFAULT_FONT, 12, "bold"),
            anchor="w"
        )
        features_title.pack(fill="x", pady=(0, 10))

        # features with icons for last page of setup
        features = [
            ("        🔒", "Secure file encryption with industry-standard algorithms"),
            ("        🎨", "Multiple theme options for a personalized experience"),
            ("        ✨", "Easy-to-use interface for all your encryption needs"),
            ("        ⚡", "Fast and efficient file processing"),
            ("        🔧", "Customizable settings to fit your workflow")
        ]

        for icon, text in features:
            feature_frame = tk.Frame(features_frame, bg=self.theme["bg"])
            feature_frame.pack(fill="x", pady=3)
            
            icon_label = tk.Label(
                feature_frame,
                text=icon,
                bg=self.theme["bg"],
                fg=self.theme["text"],
                font=(DEFAULT_FONT, 12)
            )
            icon_label.pack(side="left", padx=(0, 10))
            
            text_label = tk.Label(
                feature_frame,
                text=text,
                bg=self.theme["bg"],
                fg=self.theme["text"],
                font=(DEFAULT_FONT, 10),
                anchor="w"
            )
            text_label.pack(side="left", fill="x", expand=True)

        self.pages.append(page)

    def show_page(self, page_num):
        # Hide all pages
        for page in self.pages:
            page.pack_forget()

        # Show the selected page
        self.pages[page_num].pack(fill="both", expand=True)
        
        # Update navigation buttons based on current page
        if page_num == 0:  # First page
            # Hide regular nav buttons, show large Get Started button
            self.nav_buttons_container.pack_forget()
            self.get_started_btn.pack(pady=20)
            
            # Update navigation buttons for first page
            
        else:  # Other pages
            # Show regular nav buttons, hide Get Started button
            self.nav_buttons_container.pack(fill="x")
            self.get_started_btn.pack_forget()
            
            # Update navigation buttons
            self.prev_btn.config(state="normal" if page_num > 1 else "disabled")  # Disable prev on page 1
            
            # Update next/finish button
            if page_num == len(self.pages) - 1:
                self.next_btn.config(text="Finish", command=self._finish_setup)
            else:
                self.next_btn.config(text="Next →", command=self.next_page)
            
            # Update navigation buttons for other pages
        
        # Update current page
        self.current_page = page_num

    def next_page(self):
        if self.current_page < len(self.pages) - 1:
            # Skip page 1 (index 0) if we're on page 0
            next_page = 1 if self.current_page == 0 else self.current_page + 1
            self.show_page(next_page)

    def prev_page(self):
        if self.current_page > 1:  # Can't go back to first page
            self.show_page(self.current_page - 1)
            
    def _preview_theme(self, theme_name):
        # Get the new theme first
        new_theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])
        
        # Update the parent's current_theme
        self.parent.current_theme = theme_name
        self.parent.settings["theme"] = theme_name
        
        # Save the theme preference
        save_app_settings(self.parent.settings)
        
        # Update the current theme in the welcome window
        self.theme = new_theme
        
        # Update the main application's theme
        self.parent.apply_theme()
        
        # Update the welcome window's theme
        self.apply_theme_to_window(new_theme)
        
        # Update the root window's theme
        self._update_widget_theme(self, new_theme)
        
        # Update preview widgets if they exist
        if hasattr(self, 'preview_widgets'):
            try:
                # Update the preview frame and widgets
                self.preview_widgets['frame'].config(bg=new_theme["bg"])
                self.preview_widgets['sample_btn'].config(
                    bg=new_theme["accent"],
                    fg=NeoUIThemes.get_button_text_color(theme_name, "accent")
                )
                self.preview_widgets['sample_text'].config(
                    bg=new_theme["bg"],
                    fg=new_theme["text"]
                )
            except tk.TclError:
                # Widget might have been destroyed, recreate it
                pass
        
        # Update the preview label and text if they exist
        if hasattr(self, 'preview_label') and hasattr(self, 'preview_text'):
            try:
                self.preview_label.config(
                    bg=new_theme["bg"],
                    fg=new_theme["text"]
                )
                self.preview_text.config(
                    bg=new_theme["bg"],
                    fg=new_theme["text"]
                )
            except tk.TclError:
                # Widgets might have been destroyed
                pass
        
        # Update the theme color previews in the grid
        if hasattr(self, 'theme_preview_frames'):
            for theme_name, preview_frame in self.theme_preview_frames.items():
                try:
                    theme = NeoUIThemes.THEMES.get(theme_name, {})
                    preview_frame.config(bg=theme.get('accent', '#000000'))
                except (tk.TclError, AttributeError):
                    continue
        
        # Force update the UI
        self.update()
        self.update_idletasks()
    
    def _update_widget_theme(self, widget, theme):
        """Recursively update a widget and its children with the new theme"""
        try:
            # Skip if widget is None or already destroyed
            if not widget or not widget.winfo_exists():
                return
                
            # Update the widget's appearance based on its type
            if isinstance(widget, (tk.Frame, tk.LabelFrame)):
                widget.configure(bg=theme["secondary_bg"])
                
            elif isinstance(widget, tk.Label):
                if hasattr(self, 'preview_label') and widget == self.preview_label:
                    widget.configure(bg=theme["bg"], fg=theme["text"])
                else:
                    widget.configure(bg=theme["secondary_bg"], fg=theme["text"])
                    
            elif isinstance(widget, tk.Radiobutton):
                widget.configure(
                    bg=theme["secondary_bg"],
                    fg=theme["text"],
                    selectcolor=theme["bg"],
                    activebackground=theme["secondary_bg"],
                    activeforeground=theme["text"],
                    highlightthickness=0
                )
                
            elif isinstance(widget, tk.Checkbutton):
                widget.configure(
                    bg=theme["secondary_bg"],
                    fg=theme["text"],
                    selectcolor=theme["bg"],
                    activebackground=theme["secondary_bg"],
                    activeforeground=theme["text"],
                    highlightthickness=0
                )
                
            elif isinstance(widget, (tk.Button, NeoUIHoverButton)):
                if isinstance(widget, NeoUIHoverButton):
                    widget.update_theme(
                        bg=theme["accent"],
                        fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
                        active_bg=theme["accent"],
                        active_fg=theme["text"]
                    )
                else:
                    widget.configure(
                        bg=theme["accent"],
                        fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
                        activebackground=theme["accent"],
                        activeforeground=theme["text"],
                        highlightthickness=0
                    )
            
            # Recursively update all children
            for child in widget.winfo_children():
                self._update_widget_theme(child, theme)
                
        except Exception as e:
            # Skip any errors to prevent crashing
            pass
        
    def apply_theme_to_window(self, theme):
        # Apply theme to the welcome window
        self.configure(bg=theme["secondary_bg"])
        
        # Update main container
        self.container.configure(bg=theme["secondary_bg"])
        
        # Update navigation frame and buttons
        if hasattr(self, 'nav_frame'):
            self.nav_frame.configure(bg=theme["secondary_bg"])
            
        if hasattr(self, 'prev_btn') and isinstance(self.prev_btn, NeoUIHoverButton):
            self.prev_btn.update_theme(
                bg=theme["bg"],
                fg=theme["text"],
                active_bg=theme["accent"],
                active_fg=theme["text"]
            )
            
        if hasattr(self, 'next_btn') and isinstance(self.next_btn, NeoUIHoverButton):
            is_last_page = self.current_page == len(self.pages) - 1
            btn_bg = theme["accent"] if not is_last_page else theme["success"]
            btn_fg = NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent" if not is_last_page else "success")
            self.next_btn.update_theme(
                bg=btn_bg,
                fg=btn_fg,
                active_bg=theme["accent"],
                active_fg=theme["text"]
            )
            
        if hasattr(self, 'page_indicator'):
            self.page_indicator.configure(
                bg=theme["secondary_bg"],
                fg=theme["text"]
            )
        
        # Update all pages and their widgets
        for page in self.pages:
            try:
                page.configure(bg=theme["secondary_bg"])
                
                # Update all widgets in the page
                for widget in page.winfo_children():
                    try:
                        # Update frames and containers
                        if isinstance(widget, (tk.Frame, tk.LabelFrame)):
                            widget.configure(bg=theme["secondary_bg"])
                            
                        # Update labels
                        elif isinstance(widget, tk.Label):
                            if hasattr(self, 'preview_label') and widget == self.preview_label:
                                widget.configure(bg=theme["bg"], fg=theme["text"])
                            else:
                                widget.configure(bg=theme["secondary_bg"], fg=theme["text"])
                        
                        # Update radio buttons
                        elif isinstance(widget, tk.Radiobutton):
                            widget.configure(
                                bg=theme["secondary_bg"],
                                fg=theme["text"],
                                selectcolor=theme["bg"],
                                activebackground=theme["secondary_bg"],
                                activeforeground=theme["text"],
                                highlightthickness=0
                            )
                            
                        # Update checkbuttons
                        elif isinstance(widget, tk.Checkbutton):
                            widget.configure(
                                bg=theme["secondary_bg"],
                                fg=theme["text"],
                                selectcolor=theme["bg"],
                                activebackground=theme["secondary_bg"],
                                activeforeground=theme["text"],
                                highlightthickness=0
                            )
                            
                        # Update buttons and NeoUIHoverButton instances
                        elif isinstance(widget, (tk.Button, NeoUIHoverButton)):
                            if isinstance(widget, NeoUIHoverButton):
                                widget.update_theme(
                                    bg=theme["accent"],
                                    fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
                                    active_bg=theme["accent"],
                                    active_fg=theme["text"]
                                )
                            else:
                                widget.configure(
                                    bg=theme["accent"],
                                    fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
                                    activebackground=theme["accent"],
                                    activeforeground=theme["text"],
                                    highlightthickness=0
                                )
                        
                        # Update Entry widgets
                        elif isinstance(widget, tk.Entry):
                            widget.configure(
                                bg=theme["bg"],
                                fg=theme["text"],
                                insertbackground=theme["text"],
                                selectbackground=theme["accent"],
                                selectforeground=theme["text"],
                                highlightthickness=1,
                                highlightcolor=theme["accent"],
                                highlightbackground=theme["secondary_bg"]
                            )
                            
                        # Update Text widgets
                        elif isinstance(widget, tk.Text):
                            widget.configure(
                                bg=theme["bg"],
                                fg=theme["text"],
                                insertbackground=theme["text"],
                                selectbackground=theme["accent"],
                                selectforeground=theme["text"],
                                highlightthickness=1,
                                highlightcolor=theme["accent"],
                                highlightbackground=theme["secondary_bg"]
                            )
                            
                        # Update Listbox widgets
                        elif isinstance(widget, tk.Listbox):
                            widget.configure(
                                bg=theme["bg"],
                                fg=theme["text"],
                                selectbackground=theme["accent"],
                                selectforeground=theme["text"],
                                highlightthickness=1,
                                highlightcolor=theme["accent"],
                                highlightbackground=theme["secondary_bg"]
                            )
                            
                        # Update Combobox widgets (ttk)
                        elif hasattr(widget, 'configure') and 'combobox' in str(widget).lower():
                            style = ttk.Style()
                            style.configure('TCombobox', 
                                         fieldbackground=theme["bg"],
                                         background=theme["bg"],
                                         foreground=theme["text"],
                                         selectbackground=theme["accent"],
                                         selectforeground=theme["text"],
                                         arrowcolor=theme["text"])
                            
                    except Exception as e:
                        continue
                        
            except Exception as e:
                continue
                
        # Update the preview frame and its contents
        if hasattr(self, 'preview_frame'):
            self.preview_frame.configure(bg=theme["bg"])
            
        if hasattr(self, 'preview_label'):
            self.preview_label.config(
                bg=theme["bg"],
                fg=theme["text"]
            )
            
        if hasattr(self, 'preview_text'):
            self.preview_text.config(
                bg=theme["bg"],
                fg=theme["text"]
            )
        
        # Update the theme radio buttons in the theme page
        if hasattr(self, 'theme_var') and hasattr(self, 'pages') and len(self.pages) > 1:
            theme_frame = None
            for child in self.pages[1].winfo_children():
                if isinstance(child, tk.Frame) and child.winfo_children() and isinstance(child.winfo_children()[0], tk.Radiobutton):
                    theme_frame = child
                    break
                    
            if theme_frame:
                for widget in theme_frame.winfo_children():
                    if isinstance(widget, tk.Radiobutton):
                        widget.configure(
                            bg=theme["secondary_bg"],
                            fg=theme["text"],
                            selectcolor=theme["bg"],
                            activebackground=theme["secondary_bg"],
                            activeforeground=theme["text"],
                            highlightthickness=0
                        )
        
        # Force update the UI
        self.update()
        self.update_idletasks()

    def _finish_setup(self):
        # Save settings
        settings = load_app_settings()

        # Save theme
        theme_name = self.theme_var.get()
        settings["theme"] = theme_name

        # Initialize encryption settings if they don't exist
        if "encryption" not in settings:
            settings["encryption"] = {}

        # Save default encryption method
        if hasattr(self, 'encryption_var'):
            settings["encryption"]["default_method"] = self.encryption_var.get()

        # Save faster mode setting if it exists
        if hasattr(self, 'faster_mode_var'):
            settings["encryption"]["faster_mode"] = self.faster_mode_var.get()

        # Save settings
        save_app_settings(settings)
        
        # Update parent's settings reference
        self.parent.settings = settings

        # Apply theme to parent
        if hasattr(self.parent, 'apply_theme'):
            self.parent.current_theme = theme_name
            self.parent.apply_theme()
            
            # Force update the UI
            self.parent.update_idletasks()

        # Close the welcome window
        self.destroy()


class FFEApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Friend File Encryptor")
        self.geometry("1070x800")
        self.configure(bg="#0a1124")
        self.minsize(1070, 800)
        
        # Set the taskbar icon using resource_path for PyInstaller compatibility
        def resource_path(relative_path):
            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.abspath(os.path.dirname(__file__))
            return os.path.join(base_path, relative_path)

        try:
            icon_abs_path = resource_path('ffeicon.ico')
            if os.path.exists(icon_abs_path):
                self.iconbitmap(icon_abs_path)
        except Exception:
            pass

        # Load saved settings (theme persistence)
        self.settings = load_app_settings()
        self.current_theme = self.settings.get("theme", "Ocean Deep")

        # Check if this is the first run and show welcome window if needed
        if self.settings.get("first_run", True):
            # Only update first_run flag if change is not inhibited (for debugging)
            if not self.settings.get("first_run_chg_inhibit", False):
                self.settings["first_run"] = False
                save_app_settings(self.settings)

            # Show welcome window after a short delay to allow main window to initialize
            self.after(500, self.show_welcome_window)
        self.main_key = self.load_main_key()

        self.current_path = "C:/"
        self.history = [self.current_path]
        self.history_index = 0
        self.file_listbox = tk.Listbox(self, bg="#0f1936", fg="white", selectmode=tk.SINGLE, font=("Segoe UI", 12),
                                     selectbackground="#2a4180", selectforeground="white")
        self.file_listbox.bind("<Double-1>", self.file_dc_act)
        self.context_menu = None  # Will be initialized after theme is set

        # Sort settings
        self.sort_method = 'name'  # 'name', 'size', or 'date'
        self.sort_ascending = True  # True for ascending, False for descending

        self.create_widgets()
        # Apply initial theme to the whole app (main window only; dialogs already themed)
        self.apply_theme()
        self.acc_files()
        self.decrypting = False
        self.hovered_index = None
        self.brighten_factor = 20

        self.ffe_websrv_chk("https://www.github.com/AVXAdvanced/FFE", self.no_ffe_web)

    def no_ffe_web(self):
        show_neoui_warning(self, "Online Features Unavailable", """FFE's Online Features aren't available.

This means that certain features such as Updates may
not be available. 

This problem may be caused by the following:

- You aren't connected to the Internet
- You're using a VPN
- Your Internet Settings are misconfigured
- GitHub is experiencing issues
- The FFE GitHub is unavailable due to repo settings

Check the items listed above. If you
cannot resolve the issue yourself,
try again later.

Error Code: FxNG82933217

You can continue using FFE while Online Features are unavailable.
        """)

    def show_welcome_window(self):
        """Display the welcome window for first-time users."""
        welcome = WelcomeWindow(self)
        # The window is modal and will block until closed
        self.wait_window(welcome)

    def ffe_websrv_chk(self, url, on_failure):
        # noinspection PyTypeChecker
        def check_web():
            try:
                requests.get(url, timeout=4.273)
            except requests.exceptions.RequestException as e:
                if hasattr(on_failure, '__self__'):  # It's a bound method
                    self.after(0, on_failure)
                else:  # It's a regular function
                    self.after(0, lambda: on_failure(self))

        thread = threading.Thread(target=check_web)
        thread.daemon = True
        thread.start()

    def brighten_color(self, color_hex, factor):
        if isinstance(color_hex, str) and color_hex.startswith("#") and len(color_hex) == 7:
            try:
                r, g, b = tuple(int(color_hex[i:i + 2], 16) for i in (1, 3, 5))
                r = min(255, r + factor)
                g = min(255, g + factor)
                b = min(255, b + factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            except ValueError:
                return color_hex
        return color_hex

    def on_select(self, event):
        try:
            selected_index = self.file_listbox.curselection()[0]
            file_path = self.file_paths[selected_index]
            # File selection handler - no status update needed
            pass

        except IndexError:
            pass

    def fesys_load_key(self, filename):
        with open(filename, "rb") as key_file:
            return key_file.read()

    # noinspection PyTypeChecker
    def create_widgets(self):  # toolbar_ui_crt_def (act on stup)
        toolbar = tk.Frame(self, bg="#0a1124")
        # Align toolbar with file listbox
        toolbar.pack(fill=X, padx=10, pady=0)
        # Keep a reference for later theming
        self.toolbar = toolbar
        toolbar.columnconfigure(3, weight=1)

        self.back_button = HoverButton(toolbar, text=" Back ", command=self.go_back, state=tk.DISABLED,
                                     bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.back_button.pack(side=tk.LEFT, padx=5)

        self.up_button = HoverButton(toolbar, text=" Up ", command=self.go_up, bg="#203161", 
                                   fg="white", relief="flat", font=("Segoe UI", 11))
        self.up_button.pack(side=tk.LEFT, padx=5)

        self.forward_button = HoverButton(toolbar, text=" Forward ", command=self.go_forward, state=tk.DISABLED,
                                        bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.forward_button.pack(side=tk.LEFT, padx=5)

        # Refresh button
        self.refresh_button = HoverButton(toolbar, text=" Refresh ", command=self.refresh_view, bg="#203161", fg="white",
                                        relief="flat", font=("Segoe UI", 11))
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        # Folder dropdown button
        self.folder_button = HoverButton(toolbar, text=" Folder ▼ ", command=self.show_folder_menu,
                                       bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.folder_button.pack(side=tk.LEFT, padx=5)

        # Add sort button next to folder button
        self.sort_button = HoverButton(toolbar, text="Sort ▼", command=self.show_sort_menu,
                                     bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.sort_button.pack(side=tk.LEFT, padx=5)

        # Create sort menu with proper theming
        self.sort_menu = tk.Menu(self, tearoff=0)
        # Get current theme colors
        theme_colors = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        self.sort_menu.configure(
            bg=theme_colors["secondary_bg"],
            fg=theme_colors["text"],
            font=("Segoe UI", 11),
            activebackground=theme_colors["accent"],
            activeforeground=theme_colors["text"],
            selectcolor=theme_colors["accent"],
            bd=0
        )

        # Create a single StringVar to manage the radio button selection
        self.sort_var = tk.StringVar()
        current_sort = f"{self.sort_method}_{'asc' if self.sort_ascending else 'desc'}"
        self.sort_var.set(current_sort)

        # Add sort options with proper radio button behavior
        sort_options = [
            ("Name (A-Z)", 'name_asc'),
            ("Name (Z-A)", 'name_desc'),
            ("Size (Smallest first)", 'size_asc'),
            ("Size (Largest first)", 'size_desc'),
            ("Date (Oldest first)", 'date_asc'),
            ("Date (Newest first)", 'date_desc')
        ]

        # Add a separator after name and size options
        for i, (label, value) in enumerate(sort_options):
            if i in [2, 4]:  # Add separators before size and date sections
                self.sort_menu.add_separator()

            # Get the current theme colors
            theme_colors = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
            self.sort_menu.add_radiobutton(
                label=label,
                command=lambda v=value: self._on_sort_option_selected(v),
                variable=self.sort_var,
                value=value,
                selectcolor=theme_colors["accent"]
            )

        # Create folder menu
        self.folder_menu = tk.Menu(self, tearoff=0)
        self.folder_menu.configure(bg="#2a1f3a", fg="white", font=("Segoe UI", 11),
                                 activebackground="#614885", activeforeground="white")

        # Add special folders to menu
        special_folders = [
            ("This PC", os.path.expanduser("~")),
            ("Desktop", os.path.join(os.path.expanduser("~"), "Desktop")),
            ("Documents", os.path.join(os.path.expanduser("~"), "Documents")),
            ("Downloads", os.path.join(os.path.expanduser("~"), "Downloads")),
            ("Pictures", os.path.join(os.path.expanduser("~"), "Pictures")),
            ("Music", os.path.join(os.path.expanduser("~"), "Music")),
            ("Videos", os.path.join(os.path.expanduser("~"), "Videos"))
        ]

        for name, path in special_folders:
            if os.path.exists(path):
                self.folder_menu.add_command(
                    label=name,
                    command=lambda p=path: self.navigate_to_folder(p)
                )

        # Create a frame to contain the drive button and make it expandable
        drive_frame = tk.Frame(toolbar, bg="#0a1124")
        drive_frame.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        # Drive dropdown button - now inside the expandable frame
        self.drive_button = HoverButton(drive_frame, text=" Drives ▼", command=self.show_drive_menu,
                                      bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.drive_button.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Create drive menu
        self.drive_menu = tk.Menu(self, tearoff=0)
        self.drive_menu.configure(bg="#2a1f3a", fg="white", font=("Segoe UI", 11),
                                activebackground="#614885", activeforeground="white")

        # File listbox (packed first to be above the directory bar)
        self.file_listbox.pack(pady=(0, 0), padx=15, expand=True, fill=tk.BOTH)
        self.file_listbox.bind("<Double-1>", self.file_dc_act)

        # Directory bar at the bottom
        self.dir_frame = tk.Frame(self, bg="#0a1124")
        self.dir_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(0, 0))

        # Directory label
        self.dir_label = tk.Label(
            self.dir_frame,
            text="Directory:",
            bg="#0a1124",
            fg="white",
            font=("Segoe UI", 10)
        )
        self.dir_label.pack(side=tk.LEFT, padx=(15, 5), pady=5)

        # Directory entry with theme colors
        self.dir_entry = tk.Entry(
            self.dir_frame,
            bg="#0f1936",
            fg="white",
            insertbackground="white",
            relief="flat",
            font=("Segoe UI", 10),
            bd=0,
            highlightthickness=1,
            highlightbackground="#2a4180",
            highlightcolor="#2a4180"
        )
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), pady=5)
        self.dir_entry.bind("<Return>", lambda e: self.navigate_to_folder(self.dir_entry.get()))

        # Go button with theme colors
        self.go_btn = HoverButton(
            self.dir_frame,
            text="Go",
            command=lambda: self.navigate_to_folder(self.dir_entry.get()),
            bg="#203161",
            fg="white",
            relief="flat",
            font=("Segoe UI", 9)
        )
        self.go_btn.pack(side=tk.LEFT, padx=(0, 15), pady=5)

        # Encrypt button with dropdown
        encrypt_frame = tk.Frame(toolbar, bg="#0a1124")
        encrypt_frame.pack(side=tk.LEFT, padx=5, pady=8)

        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        self.encrypt_button = HoverButton(
            encrypt_frame,
            text=" Encrypt ",
            command=self.encrypt_file,
            bg=theme["success"],
            fg="white",
            relief="flat",
            font=("Segoe UI", 11)
        )
        self.encrypt_button.pack(side=tk.LEFT)

        # Dropdown arrow button
        self.encrypt_dropdown_btn = HoverButton(
            encrypt_frame,
            text="▼",
            command=self.show_encrypt_dropdown,
            bg=theme["success"],
            fg="white",
            relief="flat",
            font=("Segoe UI", 9),
            width=2
        )
        self.encrypt_dropdown_btn.pack(side=tk.LEFT, fill=tk.Y)

        # Store reference to the dropdown menu
        self.encrypt_dropdown = None

        decrypt_button = HoverButton(toolbar, text=" Decrypt ", command=self.decrypt_file, bg=theme["success"], fg="white",
                                     relief="flat", font=("Segoe UI", 11))
        decrypt_button.pack(side=tk.LEFT, padx=5, pady=8)

        delete_button = HoverButton(toolbar, text=" Delete ", command=self.del_f, bg="#bf3e3b", fg="white",
                                    relief="flat", font=("Segoe UI", 11))
        delete_button.pack(side=tk.LEFT, padx=5, pady=8)

        settings_button = HoverButton(toolbar, text=" Settings ", command=self.open_settings, bg="#203161", fg="white",
                                      relief="flat", font=("Segoe UI", 11))
        settings_button.pack(side=tk.LEFT, padx=5, pady=8)

        help_button = HoverButton(toolbar, text=" Help ", command=self.show_help, bg="#203161", fg="white",
                                  relief="flat", font=("Segoe UI", 11))
        help_button.pack(side=tk.LEFT, padx=5, pady=8)

        about_button = HoverButton(toolbar, text=" About ", command=self.show_about, bg="#203161", fg="white",
                                   relief="flat", font=("Segoe UI", 11))
        about_button.pack(side=tk.LEFT, padx=5, pady=8)

        # Status label has been removed as per user request

    def acc_hdd(self):
        drives = [chr(drive) + ":\\" for drive in range(65, 91) if os.path.exists(chr(drive) + ":\\")]
        return drives

    # noinspection PyTypeChecker
    def acc_files(self):
        try:
            self.file_listbox.delete(0, tk.END)
            file_entries = []

            for entry in os.listdir(self.current_path):
                full_path = os.path.join(self.current_path, entry)

                if entry.startswith('.') or (os.name == 'nt' and os.stat(full_path).st_file_attributes & 2):
                    continue

                # Get file stats for sorting
                try:
                    stat_info = os.stat(full_path)
                    is_dir = os.path.isdir(full_path)

                    if is_dir:
                        display_name = f"📁 {entry}/"
                    elif entry.endswith(".enc"):
                        display_name = f"🔒 {entry}"
                    else:
                        display_name = f"📄 {entry}"

                    file_entries.append({
                        'path': full_path,
                        'name': entry,
                        'display_name': display_name,
                        'size': 0 if is_dir else stat_info.st_size,
                        'mtime': stat_info.st_mtime,
                        'is_dir': is_dir
                    })
                except Exception as e:
                    print(f"Error getting file info for {full_path}: {e}")
                    continue

            # Sort files based on current sort method
            self._sort_file_entries(file_entries)

            # Add to listbox
            for entry in file_entries:
                self.file_listbox.insert(tk.END, entry['display_name'])

            # Store full paths for later use
            self.file_paths = [entry['path'] for entry in file_entries]

            # Update directory bar with current path
            if hasattr(self, 'dir_entry'):
                self.dir_entry.delete(0, tk.END)
                self.dir_entry.insert(0, self.current_path)

            # Update navigation buttons state
            self.back_button.config(state=tk.NORMAL if self.history_index > 0 else tk.DISABLED)
            self.forward_button.config(state=tk.NORMAL if self.history_index < len(self.history) - 1 else tk.DISABLED)
            # Disable Up button if at root directory
            parent_dir = os.path.dirname(self.current_path)
            self.up_button.config(state=tk.DISABLED if not parent_dir or parent_dir == self.current_path else tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load files: {str(e)}")

    def _sort_file_entries(self, file_entries):
        """Sort file entries based on current sort method and order."""
        if self.sort_method == 'name':
            file_entries.sort(key=lambda x: x['name'].lower(), reverse=not self.sort_ascending)
        elif self.sort_method == 'size':
            # Sort directories first, then by size
            file_entries.sort(key=lambda x: (x['is_dir'], x['size']), reverse=not self.sort_ascending)
        elif self.sort_method == 'date':
            # Sort directories first, then by modification time
            file_entries.sort(key=lambda x: (x['is_dir'], x['mtime']), reverse=not self.sort_ascending)

    def set_sort_method(self, method, ascending):
        """Set the sort method and refresh the view."""
        self.sort_method = method
        self.sort_ascending = ascending
        self.acc_files()  # Refresh the view with new sort order

    def file_dc_act(self, event):  # file doubleclick act (on act enbl)
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isfile(full_path):
                self.status_label.config(text=f"Selected file: {full_path}")
            elif os.path.isdir(full_path):
                self.current_path = full_path
                self.history.append(self.current_path)
                self.history_index += 1
                self.acc_files()
            else:
                messagebox.showerror("Error", f"Invalid selection: {self.file_listbox.get(selected_index)}")

        except IndexError:
            pass  # No selection, so nothing to do
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {str(e)}")

    def go_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.current_path = self.history[self.history_index]
            self.acc_files()
            self.inc_stat("back_count", 1)

    def show_folder_menu(self, event=None):
        """Show the folder dropdown menu"""
        try:
            self.folder_menu.tk_popup(
                self.folder_button.winfo_rootx(),
                self.folder_button.winfo_rooty() + self.folder_button.winfo_height(),
                0
            )
        finally:
            self.folder_menu.grab_release()

    def _on_sort_option_selected(self, value):
        """Handle sort option selection from the menu"""
        method, order = value.split('_')
        self.sort_method = method
        self.sort_ascending = (order == 'asc')
        self.acc_files()  # Refresh the view with new sort order

    def show_sort_menu(self, event=None):
        """Show the sort dropdown menu"""
        try:
            # Update the sort variable to reflect current state
            current_sort = f"{self.sort_method}_{'asc' if self.sort_ascending else 'desc'}"
            self.sort_var.set(current_sort)

            # Show the menu
            self.sort_menu.tk_popup(
                self.sort_button.winfo_rootx(),
                self.sort_button.winfo_rooty() + self.sort_button.winfo_height(),
                0
            )
        finally:
            self.sort_menu.grab_release()

    def navigate_to_folder(self, folder_path):
        """Navigate to the specified folder"""
        if os.path.isdir(folder_path):
            self.current_path = folder_path
            self.history = self.history[:self.history_index + 1]
            self.history.append(self.current_path)
            self.history_index = len(self.history) - 1
            # acc_files will update the navigation buttons
            self.acc_files()

    def refresh_view(self):
        """Refresh the current directory view"""
        self.acc_files()
        self.inc_stat("refresh_count", 1)

    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.current_path = self.history[self.history_index]
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, self.current_path)
            self.acc_files()
            self.inc_stat("forward_count", 1)
            self.refresh_view()

    def go_up(self):
        """Navigate to the parent directory"""
        parent_dir = os.path.dirname(self.current_path)
        if parent_dir and os.path.exists(parent_dir):
            self.current_path = parent_dir
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, self.current_path)
            self.acc_files()
            self.inc_stat("up_count", 1)
            self.refresh_view()

    def open_settings(self):
        SettingsDialog(self)

    def apply_theme(self):
        """Apply current_theme colors to the main window widgets."""
        try:
            theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

            # Update root window
            self.configure(bg=theme["bg"])

            # Update toolbar and its children
            if hasattr(self, 'toolbar') and self.toolbar:
                self.toolbar.configure(bg=theme["bg"])
                self.style_toolbar_children(theme)

            # Update file listbox
            self.update_file_listbox_theme(theme)

            # Update encrypt/dropdown buttons if they exist
            self.update_encrypt_buttons_theme(theme)

            # Update directory bar if it exists
            if hasattr(self, 'dir_frame') and self.dir_frame:
                self.dir_frame.configure(bg=theme["bg"])
                if hasattr(self, 'dir_label'):
                    self.dir_label.configure(
                        bg=theme["bg"],
                        fg=theme["text"]
                    )
                if hasattr(self, 'dir_entry'):
                    self.dir_entry.configure(
                        bg=theme["secondary_bg"],
                        fg=theme["text"],
                        insertbackground=theme["text"],
                        highlightbackground=theme["accent"],
                        highlightcolor=theme["accent"]
                    )
                if hasattr(self, 'go_btn'):
                    self.go_btn.configure(
                        bg=theme["accent"],
                        fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                        activebackground=theme["accent"],
                        activeforeground=NeoUIThemes.get_button_text_color(self.current_theme, "accent")
                    )
                    # Update hover colors for Go button
                    if hasattr(self.go_btn, 'default_bg'):
                        self.go_btn.default_bg = theme["accent"]
                        try:
                            # Brighten the color for hover effect
                            r, g, b = tuple(int(theme["accent"][i:i+2], 16) for i in (1, 3, 5))
                            r = min(255, r + 20); g = min(255, g + 20); b = min(255, b + 20)
                            self.go_btn.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                        except Exception:
                            self.go_btn.bright_bg = theme["accent"]

            # Update folder button
            if hasattr(self, 'folder_button'):
                self.folder_button.configure(
                    bg=theme["accent"],
                    fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                    activebackground=theme["accent"],
                    activeforeground=NeoUIThemes.get_button_text_color(self.current_theme, "accent")
                )
                # Update hover colors for folder button
                if hasattr(self.folder_button, 'default_bg'):
                    self.folder_button.default_bg = theme["accent"]
                    try:
                        # Brighten the color for hover effect
                        r, g, b = tuple(int(theme["accent"][i:i+2], 16) for i in (1, 3, 5))
                        r = min(255, r + 20); g = min(255, g + 20); b = min(255, b + 20)
                        self.folder_button.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                    except Exception:
                        self.folder_button.bright_bg = theme["accent"]

            # Update drive button
            if hasattr(self, 'drive_button'):
                self.drive_button.configure(
                    bg=theme["accent"],
                    fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                    activebackground=theme["accent"],
                    activeforeground=NeoUIThemes.get_button_text_color(self.current_theme, "accent")
                )
                # Update hover colors for drive button
                if hasattr(self.drive_button, 'default_bg'):
                    self.drive_button.default_bg = theme["accent"]
                    try:
                        # Brighten the color for hover effect
                        r, g, b = tuple(int(theme["accent"][i:i+2], 16) for i in (1, 3, 5))
                        r = min(255, r + 20); g = min(255, g + 20); b = min(255, b + 20)
                        self.drive_button.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                    except Exception:
                        self.drive_button.bright_bg = theme["accent"]

            # Update folder menu
            if hasattr(self, 'folder_menu'):
                self.folder_menu.configure(
                    bg=theme["secondary_bg"],
                    fg=theme["text"],
                    activebackground=theme["accent"],
                    activeforeground=theme["text"]
                )

            # Update sort menu
            if hasattr(self, 'sort_menu'):
                self.sort_menu.configure(
                    bg=theme["secondary_bg"],
                    fg=theme["text"],
                    activebackground=theme["accent"],
                    activeforeground=theme["text"]
                )

            # Update context menu
            if hasattr(self, 'context_menu'):
                self.context_menu = FileContextMenu(self, theme)

            # Update status bar
            if hasattr(self, 'status_bar'):
                self.status_bar.configure(
                    bg=theme["secondary_bg"],
                    fg=theme["text"]
                )

            # Force update of all widgets
            self.update_idletasks()

            # Refresh the file list to ensure all elements are properly updated
            if hasattr(self, 'refresh_view'):
                self.after(100, self.refresh_view)

        except Exception as e:
            print(f"Error applying theme: {e}")

        # Force a complete redraw of the window
        self.update()

        # Update sort button
        if hasattr(self, 'sort_button'):
            self.sort_button.configure(
                bg=theme["accent"],
                fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                activebackground=theme["accent"],
                activeforeground=NeoUIThemes.get_button_text_color(self.current_theme, "accent")
            )
            # Update hover colors for sort button
            if hasattr(self.sort_button, 'default_bg'):
                self.sort_button.default_bg = theme["accent"]
                try:
                    # Brighten the color for hover effect
                    r, g, b = tuple(int(theme["accent"][i:i+2], 16) for i in (1, 3, 5))
                    r = min(255, r + 20); g = min(255, g + 20); b = min(255, b + 20)
                    self.sort_button.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                except Exception:
                    self.sort_button.bright_bg = theme["accent"]

        # Update drive menu
        if hasattr(self, 'drive_menu'):
            self.drive_menu.configure(
                bg=theme["secondary_bg"],
                fg=theme["text"],
                activebackground=theme["accent"],
                activeforeground=theme["text"]
            )

        # Initialize or update context menu
        if hasattr(self, 'context_menu') and self.context_menu is not None:
            self.context_menu.destroy()
        self.context_menu = FileContextMenu(self, theme)
        self.file_listbox.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """Show the context menu at the current mouse position."""
        if hasattr(self, 'context_menu'):
            self.context_menu.show(event)

        # Flush pending UI updates to reflect theme changes instantly
        try:
            self.update_idletasks()
        except Exception:
            pass

    def style_toolbar_children(self, theme):
        """Apply theme to all toolbar children."""
        for child in self.toolbar.winfo_children():
            if isinstance(child, tk.Frame):
                # Handle frames in the toolbar (like the encrypt button frame)
                child.configure(bg=theme["bg"])
                for subchild in child.winfo_children():
                    self.style_button(subchild, theme)
            else:
                self.style_button(child, theme)

    def style_button(self, widget, theme):
        """Apply theme to a button widget."""
        if isinstance(widget, tk.Button):
            text = widget.cget("text").strip().lower()
            if "delete" in text:
                bg = theme["error"]
            elif "encrypt" in text or "decrypt" in text:
                bg = theme["success"]
            else:
                bg = theme["accent"]

            widget.configure(bg=bg, fg=theme.get("button_text", theme["text"]))

            # Update hover colors if it's a HoverButton
            if hasattr(widget, 'default_bg'):
                widget.default_bg = bg
                try:
                    # Brighten the color for hover effect
                    r, g, b = tuple(int(bg[i:i+2], 16) for i in (1, 3, 5))
                    r = min(255, r + 20); g = min(255, g + 20); b = min(255, b + 20)
                    widget.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                except Exception:
                    widget.bright_bg = bg
        elif isinstance(widget, tk.OptionMenu):
            widget.configure(bg=theme["accent"], fg=theme["text"], highlightthickness=0)
            try:
                widget["menu"].configure(bg=theme["accent"], fg=theme["text"])
            except Exception:
                pass

    def update_encrypt_buttons_theme(self, theme):
        """Update theme for encrypt and decrypt buttons."""
        if hasattr(self, 'encrypt_button'):
            self.encrypt_button.configure(bg=theme["success"])
            if hasattr(self.encrypt_button, 'default_bg'):
                self.encrypt_button.default_bg = theme["success"]
                try:
                    r, g, b = tuple(int(theme["success"][i:i+2], 16) for i in (1, 3, 5))
                    r = min(255, r + 20); g = min(255, g + 20); b = min(255, b + 20)
                    self.encrypt_button.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                except Exception:
                    self.encrypt_button.bright_bg = theme["success"]

        if hasattr(self, 'encrypt_dropdown_btn'):
            self.encrypt_dropdown_btn.configure(bg=theme["success"])
            if hasattr(self.encrypt_dropdown_btn, 'default_bg'):
                self.encrypt_dropdown_btn.default_bg = theme["success"]
                try:
                    r, g, b = tuple(int(theme["success"][i:i+2], 16) for i in (1, 3, 5))
                    r = min(255, r + 20); g = min(255, g + 20); b = min(255, b + 20)
                    self.encrypt_dropdown_btn.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                except Exception:
                    self.encrypt_dropdown_btn.bright_bg = theme["success"]

    def update_file_listbox_theme(self, theme):
        """Update theme for the file listbox."""
        try:
            self.file_listbox.configure(
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectbackground=theme["accent"],
                selectforeground=theme["text"]
            )
        except Exception:
            pass

    # Status label related code has been removed

    # noinspection PyTypeChecker
    def inc_stat(self, key: str, amount: int = 1):
        """Increment a usage statistic and persist to ffeconfig.json."""
        try:
            if not hasattr(self, 'settings') or not isinstance(self.settings, dict):
                self.settings = load_app_settings()
            stats = self.settings.setdefault("stats", {})
            stats[key] = stats.get(key, 0) + amount
            save_app_settings(self.settings)
        except Exception:
            # Non-fatal; ignore stats errors
            pass

    # noinspection PyUnresolvedReferences
    def show_drive_menu(self, event=None):
        """Show the drive dropdown menu"""
        # Clear existing menu items
        self.drive_menu.delete(0, tk.END)

        # Get available drives
        drives = self.acc_hdd()

        # Add drives to menu
        for drive in drives:
            # Get drive name and icon based on drive type
            if drive == os.path.expanduser("~"):
                display_name = "This PC"
            elif drive == os.path.join(os.path.expanduser("~"), "Desktop"):
                display_name = "Desktop"
            else:
                # Try to get the volume name
                try:
                    import ctypes
                    volume_name = ctypes.create_unicode_buffer(1024)
                    file_system_name = ctypes.create_unicode_buffer(1024)
                    ctypes.windll.kernel32.GetVolumeInformationW(
                        drive, volume_name, ctypes.sizeof(volume_name),
                        None, None, None, file_system_name, ctypes.sizeof(file_system_name)
                    )
                    vol_name = volume_name.value
                    display_name = f"{drive} ({vol_name})" if vol_name else drive
                except:
                    display_name = drive

            self.drive_menu.add_command(
                label=display_name,
                command=lambda d=drive: self.update_drive(d)
            )

        # Show the menu
        try:
            self.drive_menu.tk_popup(
                self.drive_button.winfo_rootx(),
                self.drive_button.winfo_rooty() + self.drive_button.winfo_height(),
                0
            )
        finally:
            self.drive_menu.grab_release()

    def update_drive(self, new_drive):
        """Update the current drive and refresh the view"""
        if new_drive and os.path.exists(new_drive):
            self.current_path = new_drive
            self.history = [new_drive]  # Reset history with the new path
            self.history_index = 0
            self.acc_files()  # This will update the UI and navigation buttons
        self.acc_files()

    def load_main_key(self):
        # Get the directory where the executable is located
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            app_dir = os.path.dirname(sys.executable)
        else:
            # Running as script
            app_dir = os.path.dirname(os.path.abspath(__file__))

        key_file_path = os.path.join(app_dir, "main_key.key")

        try:
            # Debug: Show where we're trying to create/load the key file
            print(f"Key file path: {key_file_path}")
            print(f"Directory exists: {os.path.exists(os.path.dirname(key_file_path))}")

            if not os.path.exists(key_file_path):
                print("Key file not found, generating new key...")
                key = Fernet.generate_key()
                try:
                    # Ensure directory exists
                    os.makedirs(os.path.dirname(key_file_path), exist_ok=True)

                    # Create the key file
                    with open(key_file_path, "wb") as key_file:
                        key_file.write(key)
                    print(f"Key file created at: {key_file_path}")

                    # Show success message
                    self.after(1000, lambda: show_neoui_warning(
                        self,
                        "Key File Created",
                        f"""FFE has created a new Key File.

A new encryption key has been generated and saved as:
"{key_file_path}"

Please keep this file safe as it is required to decrypt your files.
                        """
                    ))
                    return key

                except Exception as e:
                    error_msg = f"Error creating key file: {str(e)}\n\n"
                    error_msg += f"Working directory: {os.getcwd()}\n"
                    error_msg += f"Target path: {key_file_path}\n"
                    error_msg += "Using a temporary key for this session."

                    print(error_msg)
                    self.after(1000, lambda: show_neoui_error(
                        self,
                        "Key File Error",
                        error_msg
                    ))
                    return key  # Return the in-memory key

            # If we get here, the key file exists - try to load it
            print(f"Loading existing key from: {key_file_path}")
            key = self.fesys_load_key(key_file_path)
            return key

        except Exception as e:
            error_msg = f"Error in load_main_key: {str(e)}\n\n"
            error_msg += f"Working directory: {os.getcwd()}\n"
            error_msg += f"Key file path: {key_file_path}\n"
            error_msg += "Using a temporary key for this session."

            print(error_msg)
            self.after(1000, lambda: show_neoui_error(
                self,
                "Key Error",
                error_msg
            ))
            return Fernet.generate_key()  # Return a new key as fallback

    # noinspection PyTypeChecker
    def show_encrypt_dropdown(self):
        """Show the encryption options dropdown menu."""
        if self.encrypt_dropdown is not None:
            self.encrypt_dropdown.destroy()
            self.encrypt_dropdown = None
            return

        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

        # Create a toplevel window for the dropdown
        x = self.encrypt_button.winfo_rootx()
        y = self.encrypt_button.winfo_rooty() + self.encrypt_button.winfo_height()

        self.encrypt_dropdown = tk.Toplevel(self)
        self.encrypt_dropdown.wm_overrideredirect(True)
        self.encrypt_dropdown.wm_geometry(f"+{x}+{y}")

        # Make it look like a dropdown menu
        frame = tk.Frame(
            self.encrypt_dropdown,
            bg=theme["secondary_bg"],
            bd=1,
            relief=tk.SOLID,
            highlightbackground=theme["accent"]
        )
        frame.pack()

        # Add options
        options = [
            ("🔑 Key File", "key_file"),
            ("🔑 Password", "password"),
        ]

        for text, method in options:
            btn = tk.Button(
                frame,
                text=text,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                relief=tk.FLAT,
                font=("Segoe UI", 11),
                command=lambda m=method: self.on_encrypt_method_selected(m)
            )
            btn.pack(fill=tk.X, pady=1)

            # Add hover effect
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=theme["accent"]))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=theme["secondary_bg"]))

        # Close dropdown when clicking outside
        self.encrypt_dropdown.bind("<FocusOut>", lambda e: self.close_encrypt_dropdown())

        # Set focus to the dropdown
        self.encrypt_dropdown.focus_set()

    # <3 LYEE (why tf did i put this here i should stop making comments omfg)

    def close_encrypt_dropdown(self):
        """Close the encryption dropdown menu."""
        if self.encrypt_dropdown:
            self.encrypt_dropdown.destroy()
            self.encrypt_dropdown = None

    def on_encrypt_method_selected(self, method):
        """Handle selection of encryption method from dropdown."""
        self.close_encrypt_dropdown()

        # Update the default method in settings if needed
        if "encryption" not in self.settings:
            self.settings["encryption"] = {}
        self.settings["encryption"]["default_method"] = method
        save_app_settings(self.settings)

        # Show appropriate UI based on method
        if method == "password":
            self.fesys_encrypt_with_password()
        else:
            self.encrypt_with_key_file()

    def encrypt_with_key_file(self):
        """Encrypt the selected file using the key file."""
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_neoui_error(self, "Nope", "Can't encrypt a directory. Select a file.")
                return

            def encrypt_operation(update_progress):
                result = fesys_encrypt_file(
                    full_path,
                    self.main_key,
                    use_password=False,
                    progress_callback=update_progress
                )
                success = isinstance(result, str) and "successfully encrypted" in result.lower()
                return success, result

            def on_encrypt_complete(result):
                if hasattr(self, 'status_label'):
                    self.status_label.config(text=result)
                self.acc_files()
                if isinstance(result, str) and "successfully encrypted" in result.lower():
                    self.inc_stat("files_encrypted", 1)

            self._run_with_progress(
                "Encrypting File...",
                encrypt_operation,
                on_encrypt_complete
            )

        except IndexError:
            show_neoui_error(self, "Error",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_neoui_error(self, "Nope", f"Welp, we couldn't encrypt that one: {str(e)}")

    def fesys_encrypt_with_password(self):
        """Encrypt the selected file using a password."""
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_neoui_error(self, "Error", "Can't encrypt a directory. Please select a file.")
                return
                
            # Show password dialog with standard NeoUI buttons
            password = None
            dialog = tk.Toplevel(self)
            dialog.title("Encrypt with Password")
            dialog.resizable(False, False)
            dialog.transient(self)
            
            # Get theme
            theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
            dialog.configure(bg=theme["secondary_bg"])
            
            # Main container
            container = tk.Frame(dialog, bg=theme["secondary_bg"], padx=20, pady=20)
            container.pack(expand=True, fill="both")
            
            # Title
            title_label = tk.Label(
                container,
                text="Encrypt with Password",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 16, "bold"),
                justify="left"
            )
            title_label.pack(anchor="w", pady=(0, 15))
            
            # Message
            message = "Enter a password to encrypt the file.\nMake sure to remember this password!"
            msg_label = tk.Label(
                container,
                text=message,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11),
                justify="left"
            )
            msg_label.pack(anchor="w", pady=(0, 15))
            
            # Password entry
            password_var = tk.StringVar()
            entry_frame = tk.Frame(container, bg=theme["secondary_bg"])
            entry_frame.pack(fill="x", pady=(0, 10))
            
            entry = tk.Entry(
                entry_frame,
                textvariable=password_var,
                show="*",
                font=(DEFAULT_FONT, 11),
                bg=theme["bg"],
                fg=theme["text"],
                insertbackground=theme["text"],
                relief="flat"
            )
            entry.pack(fill="x", ipady=5)
            
            # Confirm password entry
            confirm_var = tk.StringVar()
            confirm_frame = tk.Frame(container, bg=theme["secondary_bg"])
            confirm_frame.pack(fill="x", pady=(0, 15))
            
            confirm_entry = tk.Entry(
                confirm_frame,
                textvariable=confirm_var,
                show="*",
                font=(DEFAULT_FONT, 11),
                bg=theme["bg"],
                fg=theme["text"],
                insertbackground=theme["text"],
                relief="flat"
            )
            confirm_entry.pack(fill="x", ipady=5)
            
            # Buttons frame
            btn_frame = tk.Frame(container, bg=theme["secondary_bg"])
            btn_frame.pack(fill="x")
            
            # Submit button
            def on_submit():
                nonlocal password
                if not password_var.get():
                    show_neoui_error(dialog, "Error", "Password cannot be empty.")
                    return
                if password_var.get() != confirm_var.get():
                    show_neoui_error(dialog, "Error", "Passwords do not match.")
                    return
                password = password_var.get()
                dialog.destroy()
            
            # Cancel button (X)
            cancel_btn = NeoUIHoverButton(
                btn_frame,
                text="✕",
                command=dialog.destroy,
                bg=theme["error"],
                fg=NeoUIThemes.get_button_text_color(self.current_theme, "error"),
                font=(DEFAULT_FONT, 11, "bold"),
                relief="flat"
            )
            cancel_btn.pack(side="left", expand=True, fill="x", padx=2, pady=5)
            
            # Submit button (✓)
            submit_btn = NeoUIHoverButton(
                btn_frame,
                text="✓",
                command=on_submit,
                bg=theme["accent"],
                fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                font=(DEFAULT_FONT, 11, "bold"),
                relief="flat"
            )
            submit_btn.pack(side="left", expand=True, fill="x", padx=2, pady=5)
            
            # Bind Enter key to submit
            entry.bind('<Return>', lambda e: on_submit())
            confirm_entry.bind('<Return>', lambda e: on_submit())
            
            # Center on screen
            dialog.update_idletasks()
            w, h = 400, 300
            x = (dialog.winfo_screenwidth() // 2) - (w // 2)
            y = (dialog.winfo_screenheight() // 2) - (h // 2)
            dialog.geometry(f"{w}x{h}+{x}+{y}")
            
            # Focus the entry and make dialog modal
            entry.focus_set()
            dialog.grab_set()
            dialog.wait_window()
            
            # Clear password from memory after use
            password = password_var.get()
            password_var.set("")
            confirm_var.set("")
            
            if not password:
                return  # User cancelled

            def encrypt_operation(update_progress):
                result = fesys_encrypt_with_password(
                    full_path,
                    password,
                    progress_callback=update_progress
                )
                success = isinstance(result, str) and "successfully encrypted" in result.lower()
                return success, result

            def on_encrypt_complete(result):
                if hasattr(self, 'status_label'):
                    self.status_label.config(text=result)
                self.acc_files()
                if isinstance(result, str) and "successfully encrypted" in result.lower():
                    self.inc_stat("files_encrypted", 1)

            self._run_with_progress(
                "Encrypting with Password...",
                encrypt_operation,
                on_encrypt_complete
            )

        except IndexError:
            show_neoui_error(self, "Error",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_neoui_error(self, "Nope", f"Welp, we couldn't encrypt that one: {str(e)}")

    def encrypt_file(self):
        """Encrypt the selected file using the default method."""
        # Get default encryption method from settings
        default_method = self.settings.get("encryption", {}).get("default_method", "key_file")

        if default_method == "password":
            self.fesys_encrypt_with_password()
        else:
            self.encrypt_with_key_file()
            
    def _update_progress(self, progress_dialog, value, status=None):
        """Update progress dialog from a background thread."""
        if not progress_dialog or not progress_dialog.winfo_exists():
            return False
            
        progress_dialog.after(0, lambda: progress_dialog.update_progress(value, status))
        return True

    def _run_with_progress(self, title, operation_callback, success_callback=None):
        """Run an operation with a progress dialog.
        
        Args:
            title: Title for the progress dialog
            operation_callback: Function that takes a progress callback and returns (success, result)
            success_callback: Optional function to call on success with the result
        """
        # Create progress dialog
        progress_dialog = ProgressDialog(self, title=title)
        
        # Create a reference to self for use in the thread
        app = self
        
        def run_operation():
            try:
                # Run the operation with progress updates
                success, result = operation_callback(
                    lambda v, s=None: app._update_progress(progress_dialog, v, s)
                )
                
                # Schedule UI updates on the main thread
                app.after(0, lambda s=success, r=result: on_operation_complete(s, r))
            except Exception as e:
                app.after(0, lambda: on_operation_complete(False, str(e)))
            finally:
                # Ensure dialog is closed
                app.after(0, lambda: progress_dialog.destroy() if progress_dialog.winfo_exists() else None)
        
        def on_operation_complete(success, result):
            if success:
                if success_callback:
                    # Call the success callback with the app instance bound
                    app.after(0, lambda: success_callback(result) if success_callback else None)
            else:
                error_msg = str(result) if result else "An unknown error occurred"
                if "incorrect password" in error_msg.lower():
                    show_neoui_error(
                        app,
                        "Password Incorrect",
                        "❌  The password you entered is incorrect.\n\nPlease check the following:\n\n• Ensure Caps Lock is off\n• Check for typos\n• Try a different password",
                    )
                else:
                    show_neoui_error(app, "Decryption Failed", f"The file could not be decrypted.\n\nError details: {error_msg}")
        
        # Start the operation in a separate thread
        import threading
        thread = threading.Thread(target=run_operation, daemon=True)
        thread.start()
        
        # Show the progress dialog (modal)
        self.wait_window(progress_dialog)

    def on_decrypt_complete(self, result):
        """Handle decryption completion with proper error handling.
        
        Args:
            result: A tuple of (success, message) where success is a boolean indicating
                   if the operation was successful, and message is a string with the result.
        """
        success, message = result if isinstance(result, tuple) and len(result) == 2 else (False, str(result))
        
        try:
            # Update status label if it exists
            if hasattr(self, 'status_label') and hasattr(self.status_label, 'config'):
                self.status_label.config(text=message)
            
            # Show error dialog if decryption failed
            if not success:
                show_neoui_error(self, "Decryption Failed", message)
            else:
                # Update stats if decryption was successful
                if hasattr(self, 'inc_stat'):
                    self.inc_stat("files_decrypted", 1)
            
            # Always refresh file list
            if hasattr(self, 'acc_files'):
                self.acc_files()
                
        except Exception as e:
            print(f"Error in on_decrypt_complete: {e}")
            # If something goes wrong in the handler, show a generic error
            if not success:
                show_neoui_error(self, "Error", "Failed to complete decryption. Please try again.")

    def decrypt_file(self):
        if self.decrypting:
            return
            
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_neoui_error(self, "Nope", "Can't decrypt a directory. Please select a file.")
                return

            if not full_path.endswith(".enc"):
                show_neoui_error(self, "Invalid File Type", "Only .enc files can be decrypted.\n\nPlease select an encrypted file with the .enc extension.")
                return

            # Check if file is password protected
            is_password_protected = False
            try:
                with open(full_path, 'rb') as f:
                    header = f.read(3)
                    if header == b"PWD":
                        is_password_protected = True
            except Exception as e:
                show_neoui_error(self, "Error", f"Could not read file: {str(e)}")
                return

            if is_password_protected:
                # Show password dialog with standard NeoUI buttons
                password = None
                dialog = tk.Toplevel(self)
                dialog.title("Password Required")
                dialog.resizable(False, False)
                dialog.transient(self)
                
                # Get theme
                theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
                dialog.configure(bg=theme["secondary_bg"])
                
                # Main container
                container = tk.Frame(dialog, bg=theme["secondary_bg"], padx=20, pady=20)
                container.pack(expand=True, fill="both")
                
                # Title
                title_label = tk.Label(
                    container,
                    text="Password Required",
                    bg=theme["secondary_bg"],
                    fg=theme["text"],
                    font=(DEFAULT_FONT, 16, "bold"),
                    justify="left"
                )
                title_label.pack(anchor="w", pady=(0, 15))
                
                # Message
                message = "This file is password protected.\nPlease enter the password to continue."
                msg_label = tk.Label(
                    container,
                    text=message,
                    bg=theme["secondary_bg"],
                    fg=theme["text"],
                    font=(DEFAULT_FONT, 11),
                    justify="left"
                )
                msg_label.pack(anchor="w", pady=(0, 15))
                
                # Password entry
                password_var = tk.StringVar()
                entry_frame = tk.Frame(container, bg=theme["secondary_bg"])
                entry_frame.pack(fill="x", pady=(0, 15))
                
                entry = tk.Entry(
                    entry_frame,
                    textvariable=password_var,
                    show="*",
                    font=(DEFAULT_FONT, 11),
                    bg=theme["bg"],
                    fg=theme["text"],
                    insertbackground=theme["text"],
                    relief="flat"
                )
                entry.pack(fill="x", ipady=5)
                
                # Buttons frame
                btn_frame = tk.Frame(container, bg=theme["secondary_bg"])
                btn_frame.pack(fill="x")
                
                # Submit button
                def on_submit():
                    nonlocal password
                    password = password_var.get()
                    dialog.destroy()
                
                # Cancel button (X)
                cancel_btn = NeoUIHoverButton(
                    btn_frame,
                    text="✕",
                    command=dialog.destroy,
                    bg=theme["error"],
                    fg=NeoUIThemes.get_button_text_color(self.current_theme, "error"),
                    font=(DEFAULT_FONT, 11, "bold"),
                    relief="flat"
                )
                cancel_btn.pack(side="left", expand=True, fill="x", padx=2, pady=5)
                
                # Submit button (✓)
                submit_btn = NeoUIHoverButton(
                    btn_frame,
                    text="✓",
                    command=on_submit,
                    bg=theme["accent"],
                    fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                    font=(DEFAULT_FONT, 11, "bold"),
                    relief="flat"
                )
                submit_btn.pack(side="left", expand=True, fill="x", padx=2, pady=5)
                
                # Bind Enter key to submit
                entry.bind('<Return>', lambda e: on_submit())
                
                # Center on screen
                dialog.update_idletasks()
                w, h = 400, 250
                x = (dialog.winfo_screenwidth() // 2) - (w // 2)
                y = (dialog.winfo_screenheight() // 2) - (h // 2)
                dialog.geometry(f"{w}x{h}+{x}+{y}")
                
                # Focus the entry and make dialog modal
                entry.focus_set()
                dialog.grab_set()
                dialog.wait_window()
                
                # Clear password from memory after use
                password = password_var.get()
                password_var.set("")
                
                if not password:
                    return  # User cancelled
                
                # Define the decryption operation
                def decrypt_operation(update_progress):
                    try:
                        # Use the standalone decrypt_with_password function
                        result = decrypt_with_password(
                            full_path,
                            password,
                            progress_callback=update_progress
                        )
                        
                        # Check if decryption was successful
                        if isinstance(result, str):
                            if "successfully decrypted" in result.lower():
                                return True, result
                            if any(msg in result.lower() for msg in ["error", "wrong password", "incorrect password", "invalid password", "decryption failed"]):
                                return False, ("Incorrect Password\n\n"
                                             "The password you entered does not match the one used to encrypt this file. "
                                             "Please check for typos and try again.\n\n"
                                             "• Make sure Caps Lock is turned off\n"
                                             "• Check for any extra spaces before or after the password\n"
                                             "• If you've forgotten the password, you'll need to obtain the correct one to decrypt this file")
                        return False, result or "Decryption failed. The password may be incorrect or the file may be corrupted."
                    except Exception as e:
                        error_msg = str(e).lower()
                        if any(msg in error_msg for msg in ["wrong password", "incorrect password", "invalid password", "decryption failed", "invalid tag"]):
                            return False, "Incorrect password. Please try again."
                        return False, f"Decryption failed: {str(e)}"
                    
                # Run with progress and handle completion
                self.decrypting = True
                try:
                    # Create progress dialog
                    progress_dialog = ProgressDialog(self, "Decrypting File")
                    
                    # Run decryption in a separate thread to keep UI responsive
                    import threading
                    
                    def run_decryption():
                        try:
                            success, result = decrypt_operation(
                                lambda value, status=None: self.after(10, lambda: progress_dialog.update_progress(value, status or "Decrypting..."))
                            )
                            self.after(10, lambda: self.on_decrypt_complete((success, result)))
                        except Exception as e:
                            self.after(10, lambda: show_neoui_error(self, "Decryption Error", f"Failed to decrypt file: {str(e)}"))
                        finally:
                            self.after(10, progress_dialog.destroy)
                    
                    # Start the decryption thread
                    threading.Thread(target=run_decryption, daemon=True).start()
                    
                except Exception as e:
                    self.decrypting = False
                    show_neoui_error(self, "Error", f"Failed to start decryption: {str(e)}")
            else:
                # Use key file decryption
                if not hasattr(self, 'main_key') or not self.main_key:
                    show_neoui_error(self, "Error", "No key file loaded. Please load a key file first.")
                    return
                    
                def decrypt_operation(update_progress):
                    try:
                        result = fesys_decrypt_file(
                            full_path,
                            self.main_key,
                            progress_callback=update_progress
                        )
                        success = isinstance(result, str) and "successfully decrypted" in result.lower()
                        return success, result
                    except Exception as e:
                        return False, f"Decryption failed: {str(e)}"
                
                self._run_with_progress(
                    "Decrypting File...",
                    decrypt_operation,
                    self.on_decrypt_complete
                )
        
        except IndexError:
            show_neoui_error(
                self, 
                "Error",
                "You haven't selected a file. Please select one before continuing."
            )
        except Exception as e:
            show_neoui_error(
                self, 
                "Error", 
                f"Failed to decrypt file: {str(e)}"
            )
        finally:
            self.decrypting = False

    def show_about(self):
        # Custom themed About dialog with right-aligned "Visit" buttons for socials
        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

        win = tk.Toplevel(self)
        win.title("About Friend File Encryptor")
        win.configure(bg=theme["secondary_bg"])
        win.resizable(False, False)
        win.transient(self)

        main = tk.Frame(win, bg=theme["secondary_bg"], padx=20, pady=20)
        main.pack(expand=True, fill="both")

        # Title
        tk.Label(
            main,
            text="About Friend File Encryptor",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 24, "bold"),
            justify="left",
        ).pack(anchor="w")

        tk.Label(
            main,
            text='Version 3.0.0 "Lyrah" Developer Beta 5',
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 17),
            justify="left",
        ).pack(anchor="w")

        # Version info
        info_frame = tk.Frame(main, bg=theme["secondary_bg"])
        info_frame.pack(fill="x", pady=(10, 8))
        for line in [
            "Friend File Encryptor (FFE)",
            "Build: ffe_120325_300_db5",
            "Support Schedule: N/A", #L25-30A for official release
            "Python 3.14.0",
            "Windows Edition", # linucc when??
        ]:
            tk.Label(
                info_frame,
                text=line,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11),
                justify="left",
            ).pack(anchor="w")

        # Divider
        tk.Frame(main, height=2, bg=theme["accent"]).pack(fill="x", pady=(10, 10))

        # Social links with right-aligned Visit buttons
        tk.Label(
            main,
            text="Connect with Us:",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 12, "bold"),
            justify="left",
        ).pack(anchor="w", pady=(0, 6))

        socials = [
            ("GitHub: github.com/AVXAdvanced/FFE", "https://github.com/AVXAdvanced/FFE"),
            ("X/Twitter: x.com/ffe_world", "https://x.com/ffe_world"),
            ("ProductHunt: producthunt.com/products/ffe", "https://www.producthunt.com/products/ffe"),
        ]

        for label_text, url in socials:
            row = tk.Frame(main, bg=theme["secondary_bg"]) ; row.pack(fill="x", pady=4)
            lbl = tk.Label(row, text=label_text, bg=theme["secondary_bg"], fg=theme["text"], font=(DEFAULT_FONT, 11))
            lbl.pack(side="left", anchor="w")
            # spacer expands to push the button to the right
            spacer = tk.Frame(row, bg=theme["secondary_bg"]) ; spacer.pack(side="left", expand=True, fill="x")
            btn = NeoUIHoverButton(
                row,
                text="      Visit      ",
                command=lambda u=url: webbrowser.open_new(u),
                bg=theme["accent"],
                fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                font=(DEFAULT_FONT, 11),
                relief="flat",
            )
            btn.pack(side="right")

        # Footer
        tk.Label(
            main,
            text="(c)2025 AVX_Advanced. All Rights Reserved.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10, "italic"),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))

        imports_btn = NeoUIHoverButton(
            main,
            text="View Dependencies",
            command=lambda: self.show_imports(win),
            bg=NeoUIThemes.get_dialog_colors("info", self.current_theme),
            fg=NeoUIThemes.get_button_text_color(self.current_theme, "info"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
        )
        imports_btn.pack(fill="x", pady=(12, 5))

        tk.Frame(main, height=2, bg=theme["accent"]).pack(fill="x", pady=(10, 10))

        btns = tk.Frame(main, bg=theme["secondary_bg"]) ; btns.pack(fill="x", pady=(0, 0))
        close_btn = NeoUIHoverButton(
            btns,
            text="                                                    ✓                                                    ",
            command=win.destroy,
            bg=NeoUIThemes.get_dialog_colors("info", self.current_theme),
            fg=NeoUIThemes.get_button_text_color(self.current_theme, "info"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
        )
        close_btn.pack(fill="x", pady=(0, 0))

        # Center and modal-like behavior
        win.update_idletasks()
        w, h = win.winfo_width(), win.winfo_height()
        x = (win.winfo_screenwidth() // 2) - (w // 2)
        y = (win.winfo_screenheight() // 2) - (h // 2)
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.grab_set()
        win.focus_set()

    # DO NOT MAKE THE BELOW WINDOW RESIZABLE

    def show_imports(self, parent_window):
        """Display a window showing all imports used in FFE with neoui styling."""
        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        
        win = tk.Toplevel(parent_window)
        win.title("Dependencies")
        win.configure(bg=theme["secondary_bg"])
        

        win.minsize(400, 800)
        win.resizable(True, True) #DO NOT MAKE RESIZABLE I BEG YOU
        
        # Set initial size (will be constrained by screen size)
        screen_width = win.winfo_screenwidth()
        screen_height = win.winfo_screenheight()
        width = min(700, screen_width - 100)
        height = min(800, screen_height - 100)
        
        # Center the window.. maybe
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        win.geometry(f"{width}x{height}+{x}+{y}")
        
        main_frame = tk.Frame(win, bg=theme["secondary_bg"], padx=30, pady=25)
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)

        title_label = tk.Label(
            main_frame,
            text="Dependencies",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 24, "bold"),
            justify="left"
        )
        title_label.pack(anchor="w", pady=(0, 5))

        separator = tk.Frame(main_frame, height=2, bg=theme["accent"])
        separator.pack(fill="x", pady=(0, 15))
        
        content_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        content_frame.pack(fill="both", expand=True)

        def add_section(title, parent):
            section_frame = tk.Frame(parent, bg=theme["secondary_bg"])
            section_frame.pack(fill="x", pady=(0, 15))
            
            tk.Label(
                section_frame,
                text=title,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 14, "bold"),
                justify="left"
            ).pack(anchor="w", pady=(0, 5))
            
            # Section content frame
            content = tk.Frame(section_frame, bg=theme["secondary_bg"])
            content.pack(fill="both", expand=True, padx=10)
            
            return content

        std_lib_frame = add_section("Python Version", content_frame) # Python Ver
        std_lib_text = tk.Text(
            std_lib_frame,
            wrap=tk.WORD,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 12),
            padx=0,
            pady=0,
            relief="flat",
            height=1,
            bd=0,
            highlightthickness=0
        )
        std_lib_text.pack(fill="x")

        std_lib_info = tk.Text(
            std_lib_frame,
            wrap=tk.WORD,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11),
            padx=0,
            pady=0,
            relief="flat",
            height=3,
            bd=0,
            highlightthickness=0,
            width=0
        )
        std_lib_info.pack(fill="x", pady=(0, 15))
        std_lib_info.insert(tk.END, "Python Version 3.14.0\nPEP745\nWindows Version")
        std_lib_info.config(state="disabled")

        std_lib_frame = add_section("Python Standard Library", content_frame) # Standard Lib
        std_lib_text = tk.Text(
            std_lib_frame,
            wrap=tk.WORD,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 12),
            padx=0,
            pady=0,
            relief="flat",
            height=1,
            bd=0,
            highlightthickness=0
        )
        std_lib_text.pack(fill="x")
        
        std_lib_info = tk.Text(
            std_lib_frame,
            wrap=tk.WORD,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 12),
            padx=0,
            pady=0,
            relief="flat",
            height=8,
            bd=0,
            highlightthickness=0,
            width=0
        )
        std_lib_info.pack(fill="x", pady=(0, 15))
        std_lib_info.insert(tk.END, "os\nsys\ntkinter\ntextwrap\njson\nre\nwebbrowser\nthreading\nsecrets")
        std_lib_info.config(state="disabled")

        third_party_frame = add_section("Third-party Packages", content_frame) # Third Party
        third_party_text = tk.Text(
            third_party_frame,
            wrap=tk.WORD,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11),
            padx=0,
            pady=0,
            relief="flat",
            height=1,
            bd=0,
            highlightthickness=0
        )
        third_party_text.pack(fill="x")
        
        # Add text area for Third-party Packages
        third_party_info = tk.Text(
            third_party_frame,
            wrap=tk.WORD,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11),
            padx=0,
            pady=0,
            relief="flat",
            height=4,
            bd=0,
            highlightthickness=0,
            width=0
        )
        third_party_info.pack(fill="x", pady=(0, 15))
        third_party_info.insert(tk.END, "requests\ncryptography - fernet, hazmat, cipher\npackaging")
        third_party_info.config(state="disabled")

        separator = tk.Frame(main_frame, height=2, bg=theme["accent"])
        separator.pack(fill="x", pady=(0, 15))

        btn_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        btn_frame.pack(fill="x", pady=(15, 0))

        win.update_idletasks()
        width = 600
        height = 700
        x = (win.winfo_screenwidth() // 2) - (width // 2)
        y = (win.winfo_screenheight() // 2) - (height // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")
        
        # Make the window modal
        win.grab_set()
        win.focus_force()
        
        # Bind Escape key to close the window
        win.bind("<Escape>", lambda e: win.destroy())
        
        # Close button with neoui styling at the bottom
        btn_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        btn_frame.pack(fill="x", pady=(15, 0))
        
        close_btn = NeoUIHoverButton(
            btn_frame,
            text="                                                    ✓                                                    ",
            command=win.destroy,
            bg=NeoUIThemes.get_dialog_colors("info", self.current_theme),
            fg=NeoUIThemes.get_button_text_color(self.current_theme, "info"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
            width=3
        )
        close_btn.pack(side="right", padx=5)
        
        # Set window size and position
        win.update_idletasks()
        width = min(600, win.winfo_screenwidth() - 100)
        height = min(700, win.winfo_screenheight() - 100)
        x = (win.winfo_screenwidth() // 2) - (width // 2)
        y = (win.winfo_screenheight() // 2) - (height // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")
        
        # Make the window modal
        win.grab_set()
        win.focus_force()
        
        # Bind Escape key to close the window
        win.bind("<Escape>", lambda e: win.destroy())

    # DO NOT MAKE THE ABOVE WINDOW RESIZABLE

    def show_help(self):
        response = show_neoui_question(self, "Need Help?", """    Need Help using FFE?

     Head to the FFE GitHub:
     github.com/AVXAdvanced/FFE

     Then head to one of these tabs for help:

      - Discussions (Ask Questions)
      - Wiki (Read Documentations)
      - Issues (Report an Issue with FFE)

     We recommend you head to the Wiki first.
     If you can't find anything there, head to
     discussions. If that doesn't yield results head
     to the Issues tab.

     Someone from the FFE community will surely be able to 
     help!

     Would you like to head to the FFE GitHub now?
     """)

        if response:
            webbrowser.open_new("https://github.com/AVXAdvanced/FFE")

    def del_f(self):
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_neoui_error(self, "Nope", "Cannot delete a directory. Please select a file.")
                return
                
            if not os.path.exists(full_path):
                show_neoui_error(self, "Error",
                               "We couldn't find that file. You might not have sufficient permissions to modify it.")
                return
                
            # Use the context menu's delete dialog for consistency
            if not hasattr(self, 'context_menu'):
                # If for some reason context menu isn't initialized, create a temporary one
                self.context_menu = FileContextMenu(self, 
                    NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"]))
            
            self.context_menu.show_delete_dialog(full_path)
            
        except IndexError:
            show_neoui_error(self, "No File Selected",
                           "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_neoui_error(self, "Error", f"Something went wrong while trying to delete {str(e)}")

    def _download_with_progress(self, url, path, progress_callback=None):
        """Download a file with progress tracking"""
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 8192  # 8 KB blocks
        downloaded = 0
        
        with open(path, 'wb') as f:
            for data in response.iter_content(block_size):
                f.write(data)
                downloaded += len(data)
                if progress_callback and total_size > 0:
                    progress = int(50 * downloaded / total_size)
                    progress_callback(progress, f"Downloading... {downloaded/1024/1024:.1f}MB / {total_size/1024/1024:.1f}MB")
        
        return True

    def _verify_update(self, filepath, expected_size=None, expected_hash=None):
        """Verify the integrity of the downloaded update"""
        try:
            # Check file size if provided
            if expected_size:
                actual_size = os.path.getsize(filepath)
                if actual_size != expected_size:
                    return False, f"File size mismatch: expected {expected_size} bytes, got {actual_size} bytes"
            
            # TODO: Implement hash verification if you want to add checksums to your releases
            # if expected_hash:
            #     actual_hash = self._calculate_file_hash(filepath)
            #     if actual_hash.lower() != expected_hash.lower():
            #         return False, "File hash verification failed"
            
            return True, "Verification successful"
        except Exception as e:
            return False, f"Verification failed: {str(e)}"

    def update_ffe(self):
        """Check for and apply FFE updates"""
        try:
            current_version = "1.0.0"  # Hardcoded version for update check
            
            # Create a progress dialog
            progress_dialog = ProgressDialog(self, "Checking for Updates...")
            progress_dialog.update_progress(10, "Checking for updates...")
            
            # Get latest release info
            url = "https://api.github.com/repos/AVXAdvanced/FFE/releases/latest"
            response = requests.get(url)
            response.raise_for_status()
            latest_release = response.json()
            
            # Extract version from release name
            release_name = latest_release["name"]
            match = re.search(r"Version (\d+\.\d+\.\d+)", release_name)
            if not match:
                progress_dialog.destroy()
                show_neoui_error(self, "Error", "Could not determine version from release. Please check manually at github.com/AVXAdvanced/FFE/releases")
                return
                
            latest_version = match.group(1)
            progress_dialog.update_progress(30, f"Latest version: {latest_version}")
            
            # Check if update is needed
            if version.parse(latest_version) <= version.parse(current_version):
                progress_dialog.destroy()
                show_neoui_info(self, "No Updates Available", "You're already on the newest version. No updates currently available.")
                return
                
            # Ask user if they want to update
            progress_dialog.destroy()
            confirm = show_neoui_question(self, 
                "Update Available", 
                f"""Version {latest_version} is available (Current: {current_version}).

New versions include important improvements, bug fixes, and security updates.

Would you like to download and install this update now?""")
                
            if not confirm:
                return
                
            # Prepare for download
            if not latest_release.get("assets"):
                show_neoui_error(self, "Update Error", "No downloadable assets found in the latest release.")
                return
                
            asset = latest_release["assets"][0]
            download_url = asset["browser_download_url"]
            filename = asset["name"]
            file_size = asset.get("size")
            
            # Set up download path in user's Downloads folder
            download_dir = os.path.join(os.path.expanduser("~"), "Downloads", "FFE_Updates")
            os.makedirs(download_dir, exist_ok=True)
            download_path = os.path.join(download_dir, filename)
            
            # Create a new progress dialog for download
            download_dialog = ProgressDialog(self, "Downloading Update...")
            
            def update_progress(progress, status):
                download_dialog.update_progress(progress, status)
                download_dialog.update_idletasks()

            # whatcha doing reading the code huh?

            # Start download in a separate thread
            def download_thread():
                try:
                    # Download the update
                    self._download_with_progress(
                        download_url, 
                        download_path,
                        progress_callback=update_progress
                    )
                    
                    # Verify the download
                    download_dialog.update_progress(80, "Verifying update...")
                    is_valid, message = self._verify_update(download_path, expected_size=file_size)
                    
                    if not is_valid:
                        download_dialog.destroy()
                        show_neoui_error(self, "Update Error", f"Update verification failed: {message}")
                        return
                    
                    download_dialog.update_progress(100, "Download complete!")
                    download_dialog.destroy()
                    
                    # Ask user to install the update
                    install = show_neoui_question(self, 
                        "Download Complete", 
                        f"Update downloaded successfully to:\n{download_path}\n\n"
                        "Would you like to open the download location now?")
                    
                    if install:
                        # Open the download location
                        if os.name == 'nt':  # Windows
                            os.startfile(download_dir)
                        else:  # macOS and Linux
                            import subprocess
                            subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', download_dir])
                    
                    # Show instructions for manual installation
                    show_neoui_info(self, "Installation Instructions",
                        "To complete the update:\n\n"
                        "1. Close FFE completely\n"
                        f"2. Run the downloaded installer: {filename}\n"
                        "3. Follow the on-screen instructions\n\n"
                        "FFE will automatically restart after installation.")
                    
                except requests.exceptions.RequestException as e:
                    download_dialog.destroy()
                    show_neoui_error(self, "Download Failed", 
                        f"Failed to download update. Please check your internet connection and try again.\n\nError: {str(e)}")
                except Exception as e:
                    download_dialog.destroy()
                    show_neoui_error(self, "Update Error", 
                        f"An unexpected error occurred during update.\n\nError: {str(e)}")
            
            # Start the download in a separate thread
            import threading
            threading.Thread(target=download_thread, daemon=True).start()
            
        except requests.exceptions.RequestException as e:
            show_neoui_error(self, "Connection Error",
                f"Could not check for updates. Please check your internet connection.\n\nError: {str(e)}")
        except Exception as e:
            show_neoui_error(self, "Update Error",
                f"An unexpected error occurred while checking for updates.\n\nError: {str(e)}")
        finally:
            # Ensure progress dialog is closed if it's still open
            if 'progress_dialog' in locals() and progress_dialog.winfo_exists():
                progress_dialog.destroy()

print("FFEApp MainLoop Occurs here.")
print("Bottom of code reached.")

if __name__ == "__main__":
    app = FFEApp()
    app.mainloop()
