print("Friend File Encryptor - FFE")
print("Version 3.0 Developer Beta 3")
print("Build: ffe_102225_300_03_lyra")
print("")
print("Terminal Output Established")
print("")
print("Imports will be loaded now.")
print("")
print("""
List of Imports to be loaded:

os
requests
tkinter as tk
from tkinter import messagebox, ttk, simpledialog, Entry, Frame, Label, StringVar, X, Y, BOTH, NONE
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
import requests
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, Entry, Frame, Label, StringVar, X, Y, BOTH, NONE
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

# CAUTION! DO NOT DETACH UI LAYER FROM LYRA LOGIC! PASSWORD FUNCT IS TIED TO TKINTER LAYER!

# TODO: Add file path bar or action to send to path


SETTINGS_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'ffe_settings.json')
LEGACY_SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'ffedata.json')

print("def_fesys_gen_key")
print("")
def fesys_gen_key():
    print("def fesys_gen_key")
    print("")
    return Fernet.generate_key()

print("def derive_key")
print("")
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=125000,
    )
    return kdf.derive(password.encode())

print("def generate_salt")
print("")
def generate_salt() -> bytes:
    """Generate a random salt."""
    print("def generate_salt")
    print("")
    return secrets.token_bytes(16)

def encrypt_with_password(file_path: str, password: str, progress_callback=None) -> str:
    print("def encrypt_with_password")
    print("")
    """Encrypt a file using a password with AES-GCM."""
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
        # Derive key from password
        key = derive_key(password, salt)
        
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

def decrypt_with_password(file_path: str, password: str, progress_callback=None) -> str:
    """Decrypt a file using a password with AES-GCM."""
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
        return f"Error during password decryption: {str(e)}"

# Settings file handling

def load_app_settings():
    print("def load_app_settings")
    print("")
    """Load app settings from JSON file or create default if not exists."""
    defaults = {
        "theme": "Midnight Purple",
        "encryption": {
            "default_method": "key_file"  # 'key_file' or 'password'
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
    
    try:
        # Prefer new file
        path = SETTINGS_FILE if os.path.exists(SETTINGS_FILE) else None
        # Migrate legacy file if needed
        if path is None and os.path.exists(LEGACY_SETTINGS_FILE):
            path = LEGACY_SETTINGS_FILE
        if path:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # Ensure defaults
                    for k, v in defaults.items():
                        if isinstance(v, dict):
                            data.setdefault(k, {})
                            # deep defaults for stats
                            for sk, sv in v.items():
                                data[k].setdefault(sk, sv)
                        else:
                            data.setdefault(k, v)
                    # If coming from legacy, save to new path
                    if path == LEGACY_SETTINGS_FILE:
                        try:
                            with open(SETTINGS_FILE, 'w', encoding='utf-8') as wf:
                                json.dump(data, wf, indent=2)
                        except Exception:
                            pass
                    return data
    except Exception:
        pass
    return defaults.copy()


def save_app_settings(settings: dict):
    print("def save_app_settings")
    print("")
    """Persist app settings to SETTINGS_FILE safely."""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)
    except Exception:
        # Non-fatal if we cannot save
        pass


def fesys_save_key(key, filename):
    print("def fesys_save_key")
    print("")
    with open(filename, "wb") as key_file:
        key_file.write(key)


def fesys_encrypt_file(file_path, main_key, use_password=False, password=None, progress_callback=None):
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
        return encrypt_with_password(file_path, password, progress_callback=progress_callback)
    
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
                return decrypt_with_password(file_path, password, progress_callback=progress_callback)
        
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
        return f"File '{os.path.basename(decrypted_file_path)}' successfully decrypted!"
    except Exception as e:
        return f"Error during decryption: {str(e)}"


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
        self["background"] = self.bright_bg

    def on_leave(self, e):
        print("class HoverButton.on_leave")
        print("")
        self["background"] = self.default_bg

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



class FFEThemeColors:
    THEMES = {
        "Midnight Purple": {
            "bg": "#160c29",
            "secondary_bg": "#25153d",
            "accent": "#5f3a99",
            "success": "#40C28B",
            "error": "#E05268",
            "warning": "#E0903A",
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
        "Forest Green": {
            "bg": "#0a1f0a",
            "secondary_bg": "#122712",
            "accent": "#2d5a2d",
            "success": "#3d7a5f",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Ocean Deep": {
            "bg": "#0c1920",
            "secondary_bg": "#132b35",
            "accent": "#2d6477",
            "success": "#2d8879",
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
        theme = FFEThemeColors.THEMES.get(theme_name, FFEThemeColors.THEMES["Midnight Purple"])
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
        print("class FFEThemeColors.get_button_text_color")
        print("")
        return "white"


DEFAULT_FONT = "Segoe UI"


class FFEHoverButton(tk.Button):
    def __init__(self, master, **kwargs):
        print("class FFEHoverButton.__init__")
        print("")
        kwargs['height'] = 1
        kwargs['pady'] = 4
        if 'padx' not in kwargs:
            kwargs['padx'] = 10
        if 'font' not in kwargs:
            kwargs['font'] = (DEFAULT_FONT, 11)

        tk.Button.__init__(self, master, **kwargs)
        self.default_bg = self["background"]
        self.bright_bg = self._brighten_color(self.default_bg, 20)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, e):
        print("class FFEHoverButton._on_enter")
        print("")
        self["background"] = self.bright_bg

    def _on_leave(self, e):
        print("class FFEHoverButton._on_leave")
        print("")
        self["background"] = self.default_bg

    def _brighten_color(self, color, brightness_factor):
        print("class FFEHoverButton._brighten_color")
        print("")
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


class ProgressDialog(tk.Toplevel):
    def __init__(self, parent, title="Processing..."):
        print("class ProgressDialog.__init__")
        print("")
        super().__init__(parent)
        self.title(title)
        
        # Get theme
        theme_name = getattr(parent, 'current_theme', 'Midnight Purple')
        theme = FFEThemeColors.THEMES.get(theme_name, FFEThemeColors.THEMES["Midnight Purple"])
        
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
        status_label = tk.Label(
            main_frame,
            textvariable=self.status_var,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10),
            justify="left"
        )
        status_label.pack(anchor="w")
        
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


class ModernDialog(tk.Toplevel):
    TITLE_FONT_SIZE = 29
    VERSION_FONT_SIZE = 16
    CONTENT_FONT_SIZE = 11

    def __init__(self, parent, title, message, dialog_type="info", title_font_size=None):
        print("class ModernDialog.__init__")
        print("")
        super().__init__(parent)
        self.result = None

        # Theme
        theme_name = getattr(parent, 'current_theme', 'Midnight Purple')
        theme = FFEThemeColors.THEMES.get(theme_name, FFEThemeColors.THEMES["Midnight Purple"])
        accent_color = FFEThemeColors.get_dialog_colors(dialog_type, theme_name)

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

            yes_btn = FFEHoverButton(btn_frame, text="✓", command=self._yes, bg=accent_color,
                                        fg=FFEThemeColors.get_button_text_color(theme_name, "success"),
                                        font=(DEFAULT_FONT, 11), relief="flat")
            yes_btn.grid(row=0, column=0, sticky="ew", padx=2, pady=5)

            no_btn = FFEHoverButton(btn_frame, text="❌", command=self._no, bg=theme["accent"],
                                       fg=FFEThemeColors.get_button_text_color(theme_name, "accent"),
                                       font=(DEFAULT_FONT, 11), relief="flat")
            no_btn.grid(row=0, column=1, sticky="ew", padx=2, pady=5)
        else:
            ok_btn = FFEHoverButton(btn_frame, text="✓", command=self._ok, bg=accent_color,
                                       fg=FFEThemeColors.get_button_text_color(theme_name, dialog_type),
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
        print("class ModernDialog._ok")
        print("")
        self.result = True
        self.destroy()

    def _yes(self):
        print("class ModernDialog._yes")
        print("")
        self.result = True
        self.destroy()

    def _no(self):
        print("class ModernDialog._no")
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
        theme_name = getattr(parent, 'current_theme', 'Midnight Purple')
        theme = FFEThemeColors.THEMES.get(theme_name, FFEThemeColors.THEMES["Midnight Purple"])
        
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
        cancel_btn = FFEHoverButton(
            btn_frame,
            text="✕",
            command=self._cancel,
            bg=theme["error"],
            fg=FFEThemeColors.get_button_text_color(theme_name, "error"),
            font=(DEFAULT_FONT, 11),
            relief="flat"
        )
        cancel_btn.pack(side="right", padx=5)
        
        # OK button
        ok_btn = FFEHoverButton(
            btn_frame,
            text="✓",
            command=self._ok,
            bg=FFEThemeColors.get_dialog_colors("info", theme_name),
            fg=FFEThemeColors.get_button_text_color(theme_name, "info"),
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
            show_modern_error(self, "Error", "Passwords do not match!")
            return
        if not self.password.get():
            show_modern_error(self, "Error", "Password cannot be empty!")
            return
        self.result = self.password.get()
        self.destroy()
    
    def _cancel(self):
        print("class PasswordDialog._cancel")
        print("")
        self.result = None
        self.destroy()


def show_modern_info(parent, title, message):
    print("def show_modern_info")
    print("")
    d = ModernDialog(parent, title, message, "info")
    d.wait_window()
    return d.result


def show_modern_warning(parent, title, message):
    print("def show_modern_warning")
    print("")
    d = ModernDialog(parent, title, message, "warning")
    d.wait_window()
    return d.result


def show_modern_error(parent, title, message):
    print("def show_modern_error")
    print("")
    d = ModernDialog(parent, title, message, "error")
    d.wait_window()
    return d.result


def show_modern_question(parent, title, message):
    print("def show_modern_question")
    print("")
    d = ModernDialog(parent, title, message, "question")
    d.wait_window()
    return d.result

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Settings")
        theme = FFEThemeColors.THEMES.get(parent.current_theme, FFEThemeColors.THEMES["Midnight Purple"])
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

        # Buttons at bottom
        buttons = tk.Frame(main_frame, bg=theme["secondary_bg"]) 
        buttons.pack(fill="x", pady=(10, 0))

        close_btn = FFEHoverButton(
            buttons,
            text="✓",
            command=self.destroy,
            bg=FFEThemeColors.get_dialog_colors("info", self.parent.current_theme),
            fg=FFEThemeColors.get_button_text_color(self.parent.current_theme, "info"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
        )
        close_btn.pack(side="right", padx=5, pady=5)

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
            
    def _populate_na_tab(self, frame, theme):
        if frame == self.encryption_frame:
            self._populate_encryption_tab(frame, theme)
            return
            
        inner = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=20)
        inner.pack(expand=True, fill="both")
        
        if frame == self.general_frame:
            open_ffedata_btn = FFEHoverButton(
                inner,
                text="Open Configuration File",
                command=lambda: self.open_file_in_default_editor("ffedata.json"),
                bg=theme["accent"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 11, "bold"),
                relief="flat",
                padx=15,
                pady=8
            )
            open_ffedata_btn.pack(pady=(0, 10), fill="x")

            clear_key_btn = FFEHoverButton(
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

            clear_data_btn = FFEHoverButton(
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

            close_gen_btn = FFEHoverButton(
                inner,
                text="Force Quit",
                command=exit,
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
        
    def _update_encryption_default(self):
        """Update the default encryption method in settings."""
        method = self.default_enc_method.get().lower().replace(" ", "_")
        if "encryption" not in self.parent.settings:
            self.parent.settings["encryption"] = {}
        self.parent.settings["encryption"]["default_method"] = method
        save_app_settings(self.parent.settings)
        
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
        default_method = self.parent.settings.get("encryption", {}).get("default_method", "key_file")
        self.default_enc_method = tk.StringVar(value="Key File" if default_method == "key_file" else "Password")
        
        # Method selection
        method_frame = tk.Frame(default_frame, bg=theme["secondary_bg"])
        method_frame.pack(fill="x", pady=5)
        
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
            command=self._update_encryption_default
        )
        key_file_rb.pack(side="left", padx=(0, 20))
        
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
            command=self._update_encryption_default
        )
        password_rb.pack(side="left")
        
        # Info text
        tk.Label(
            container,
            text="This sets the default method used when clicking the 'Encrypt' button.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
        ).pack(anchor="w", pady=(0, 15))
        
        # Encryption Algorithm Section
        algo_frame = tk.Frame(container, bg=theme["secondary_bg"])
        algo_frame.pack(fill="x")
        
        tk.Label(
            algo_frame,
            text="Encryption Algorithm:",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11, "bold"),
        ).pack(anchor="w", pady=(10, 5))
        
        self.algo_var = tk.StringVar(value="AES-256")  # Default selection
        
        # Algorithm Options
        algorithms = ["AES-256", "ChaCha20", "Fernet"]
        for algo in algorithms:
            is_disabled = algo != "AES-256"  # Only enable AES-256, disable others
            row = tk.Frame(algo_frame, bg=theme["secondary_bg"])
            row.pack(fill="x", pady=2)
            
            rb = tk.Radiobutton(
                row,
                text=algo,
                variable=self.algo_var,
                value=algo,
                bg=theme["secondary_bg"],
                fg=theme["text"] if not is_disabled else "#666666",
                selectcolor=theme["accent"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"] if not is_disabled else "#666666",
                font=(DEFAULT_FONT, 11, "italic" if is_disabled else "normal"),
                state="disabled" if is_disabled else "normal"
            )
            rb.pack(side="left", anchor="w")
            
            if is_disabled:
                tk.Label(
                    row,
                    text="(coming soon)",
                    bg=theme["secondary_bg"],
                    fg="#666666",
                    font=(DEFAULT_FONT, 8, "italic"),
                ).pack(side="left", padx=(5, 0))
        
        # Info text
        tk.Label(
            container,
            text="Changing these settings may affect file compatibility.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
        ).pack(anchor="w", pady=(15, 0))

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
        # DO NOT DISABLE DEFAULT THEME (i.e. Midnight Purple)
        self.disabled_themes = [""]
        
        # Get all available themes
        themes = list(FFEThemeColors.THEMES.keys())
        
        # Ensure current theme is not disabled
        if self.parent.current_theme in self.disabled_themes:
            self.theme_var.set("Midnight Purple")
            self.parent.current_theme = "Midnight Purple"

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
            self.theme_var.set(self.parent.current_theme)  # Reset to current theme
            return
            
        # Update theme
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
        
        # Get the new theme
        theme = FFEThemeColors.THEMES.get(chosen, FFEThemeColors.THEMES["Midnight Purple"])
        
        # Update main window
        if hasattr(self.parent, 'apply_theme'):
            self.parent.apply_theme()
        
        # Update settings window
        self._update_settings_window_theme(theme)
    
    def _update_settings_window_theme(self, theme):
        """Update visual elements of the settings window to match the new theme."""
        # Update window background
        self.configure(bg=theme["secondary_bg"])
        
        # Update notebook style
        self._apply_notebook_style(self.parent.current_theme)
        
        # Update all widgets in the main frame
        for widget in self.winfo_children():
            if isinstance(widget, tk.Frame):
                widget.configure(bg=theme["secondary_bg"])
                for child in widget.winfo_children():
                    self._update_widget_theme(child, theme)
        
        # Update selector bar
        self._style_selector(theme)
    
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

Current Version: 3.0 Developer Beta 3
Current Build: ffe_102225_300_lyra

Caution! This is a developer beta build that cannot update.
Utilize the GitHub to manually download the next beta or stable.
            
            """,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10),
        )
        desc.pack(anchor="w", pady=(0, 10))

        check_btn = FFEHoverButton(
            container,
            text="                                              Check For Updates                                              ",
            command=self.parent.update_ffe,
            bg=theme["accent"],
            fg=FFEThemeColors.get_button_text_color(self.parent.current_theme, "accent"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
        )
        check_btn.pack(anchor="w")

    def _update_selector_active(self):
        if not hasattr(self, 'tab_buttons') or not self.tab_buttons:
            return

        theme = FFEThemeColors.THEMES.get(self.parent.current_theme, FFEThemeColors.THEMES["Midnight Purple"])
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
            
            btn = FFEHoverButton(
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

    def _style_selector(self, theme):
        if hasattr(self, 'selector_bar') and self.selector_bar:
            self.selector_bar.configure(bg=theme["secondary_bg"])
        if hasattr(self, 'tab_buttons'):
            for name, obj in self.tab_buttons.items():
                btn = obj["button"]
                ind = obj["indicator"]
                btn.configure(bg=theme["secondary_bg"], fg=theme["text"]) 
                
    def _reset_settings(self):
        if show_modern_question(
            self,
            "Confirm Reset", 
            "Are you sure you want to reset all settings to default?\n\nThis will reset all your preferences and statistics."
        ):
            try:
                # Reset settings to default
                default_settings = {
                    "theme": "Midnight Purple",
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
                self.parent.current_theme = "Midnight Purple"
                self.parent.settings = default_settings
                
                # Update theme immediately
                self._update_settings_window_theme(FFEThemeColors.THEMES["Midnight Purple"])
                
                show_modern_info(self, "Success", "All settings have been reset to default.")
            except Exception as e:
                show_modern_error(self, "Error", f"Failed to reset settings: {str(e)}")

    def _clear_key(self):
        """Delete and generate a new encryption key"""
        if show_modern_question(
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
                show_modern_info(
                    self, 
                    "Success", 
                    "A new encryption key has been generated.\n\n"
                    "Please make sure to back up the new key file (main_key.key)."
                )
            except Exception as e:
                show_modern_error(self, "Error", f"Failed to regenerate encryption key: {str(e)}")
                
    def _clear_data(self):
        """Clear all application data and settings"""
        if show_modern_question(
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
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffedata.json"),
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffe_settings.json")
                ]
                
                # Remove data files
                for file_path in data_files:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                
                # Reset in-memory settings
                if hasattr(self.parent, 'settings'):
                    self.parent.settings = self.parent.load_settings()
                
                show_modern_info(
                    self,
                    "Data Cleared",
                    "All application data and settings have been cleared.\n\n"
                    "The application will now restart to apply changes."
                )
                
                # Restart the application
                self.parent.restart_application()
                
            except Exception as e:
                show_modern_error(
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

        theme = FFEThemeColors.THEMES.get(theme_name, FFEThemeColors.THEMES["Midnight Purple"])
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
            command=self.encrypt_with_password,
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
            foreground=FFEThemeColors.get_dialog_colors("info", getattr(parent, 'current_theme', 'Midnight Purple'))
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
            
    def encrypt_with_password(self):
        file_path = self.get_selected_file()
        if file_path and os.path.isfile(file_path):
            self.parent.encrypt_with_password()
    
    def decrypt_file(self):
        file_path = self.get_selected_file()
        if file_path and os.path.isfile(file_path):
            self.parent.decrypt_file()
    
    def rename_file(self):
        file_path = self.get_selected_file()
        if file_path:
            old_name = os.path.basename(file_path)
            # Use modern dialog for renaming
            dialog = ModernDialog(
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
                    show_modern_error(self.parent, "Error", f"Failed to rename: {str(e)}")
    
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
        """Show file information in a modern dialog."""
        file_path = self.get_selected_file()
        if not file_path:
            return
            
        info = self.get_file_info(file_path)
        if not info:
            show_modern_error(self.parent, "Error", "Could not retrieve file information.")
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
        
        # Show the information in a modern dialog
        dialog = ModernDialog(
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
        theme = FFEThemeColors.THEMES.get(getattr(self.parent, 'current_theme', 'Midnight Purple'), 
                                           FFEThemeColors.THEMES["Midnight Purple"])
        accent_color = FFEThemeColors.get_dialog_colors("info", self.parent.current_theme)
        
        # Configure dialog
        dialog.configure(bg=theme["secondary_bg"])
        
        # Create main frame
        main_frame = tk.Frame(dialog, bg=theme["secondary_bg"], padx=25, pady=20)
        main_frame.pack(expand=True, fill="both")
        
        # Title
        title_label = tk.Label(
            main_frame, 
            text=f"Delete '{filename}'",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=("Segoe UI", 14, "bold"),
            justify="left"
        )
        title_label.pack(anchor="w", pady=(0, 15))
        
        # Message
        msg_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        msg_frame.pack(fill="x", pady=(0, 25))
        
        msg = tk.Label(
            msg_frame,
            text="How would you like to delete this file?",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=("Segoe UI", 11),
            justify="left"
        )
        msg.pack(anchor="w")
        
        # Delete buttons frame (for side-by-side buttons)
        delete_btn_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        delete_btn_frame.pack(fill="x", pady=(0, 12))
        
        # Secure Delete button (left) - Success style
        secure_btn = FFEHoverButton(
            delete_btn_frame,
            text="Secure Delete",
            command=lambda: self._perform_delete(file_path, secure=True, dialog=dialog),
            bg=FFEThemeColors.get_dialog_colors("success", self.parent.current_theme),
            fg=FFEThemeColors.get_button_text_color(self.parent.current_theme, "success"),
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            height=1,
            pady=6
        )
        secure_btn.pack(side="left", expand=True, fill="x", padx=(0, 10))
        
        # Normal Delete button (right) - Error style (like the delete button)
        normal_btn = FFEHoverButton(
            delete_btn_frame,
            text="Normal Delete",
            command=lambda: self._perform_delete(file_path, secure=False, dialog=dialog),
            bg=theme["error"],
            fg=FFEThemeColors.get_button_text_color(self.parent.current_theme, "error"),
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            height=1,
            pady=6
        )
        normal_btn.pack(side="left", expand=True, fill="x")
        
        # Cancel button (full width, below) - Accent style
        cancel_btn = FFEHoverButton(
            main_frame,
            text="Cancel",
            command=dialog.destroy,
            bg=theme["accent"],
            fg=FFEThemeColors.get_button_text_color(self.parent.current_theme, "accent"),
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            height=1,
            pady=6
        )
        cancel_btn.pack(fill="x", pady=(0, 5))
        
        # Center the dialog
        dialog.update_idletasks()
        w = 380  # Slightly wider to accommodate side-by-side buttons
        h = 240  # Taller to fit the new layout
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
                show_modern_error(self.parent, "Error", "File not found or already deleted.")
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
                    show_modern_error(self.parent, "Error", f"Secure delete failed: {str(e)}\nFalling back to normal delete.")
            
            # Delete the file
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
                
            # Update UI
            self.parent.refresh_view()
            self.parent.status_label.config(text=f"File {'securely ' if secure else ''}deleted: {os.path.basename(file_path)}")
            
            # Close the dialog if it's open
            if dialog:
                dialog.destroy()
                
        except Exception as e:
            show_modern_error(self.parent, "Error", f"Failed to delete file: {str(e)}")
            if dialog:
                dialog.destroy()
    
    def delete_file(self):
        file_path = self.get_selected_file()
        if file_path:
            self.show_delete_dialog(file_path)


class FFEApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Friend File Encryptor")
        self.geometry("1070x800")
        self.configure(bg="#0a1124")
        self.minsize(1070, 800)

        # Load saved settings (theme persistence)
        self.settings = load_app_settings()
        self.current_theme = self.settings.get("theme", "Midnight Purple")
        self.main_key = self.load_main_key()

        self.current_path = "C:/"
        self.history = [self.current_path]
        self.history_index = 0
        self.file_listbox = tk.Listbox(self, bg="#0f1936", fg="white", selectmode=tk.SINGLE, font=("Segoe UI", 12),
                                     selectbackground="#2a4180", selectforeground="white")
        self.file_listbox.bind("<Double-1>", self.file_dc_act)
        self.context_menu = None  # Will be initialized after theme is set
        self.create_widgets()
        # Apply initial theme to the whole app (main window only; dialogs already themed)
        self.apply_theme()
        self.acc_files()
        self.decrypting = False
        self.hovered_index = None
        self.brighten_factor = 20

        self.ffe_websrv_chk("https://www.github.com/AVXAdvanced/FFE", self.no_ffe_web)

    def no_ffe_web(self):
        show_modern_warning(self, "Online Features Unavailable", """FFE's Online Features aren't available.

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

    def ffe_websrv_chk(self, url, on_failure):
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
            # You could do something here based on the selected file if you want
            self.status_label.config(text=f"Selected: {os.path.basename(file_path)}")
            pass

        except IndexError:
            pass

    def fesys_load_key(self, filename):
        with open(filename, "rb") as key_file:
            return key_file.read()

    def create_widgets(self):  # toolbar_ui_crt_def (act on stup)
        toolbar = tk.Frame(self, bg="#0a1124")
        # Align toolbar with file listbox
        toolbar.pack(fill=X, padx=10, pady=0)
        # Keep a reference for later theming
        self.toolbar = toolbar
        toolbar.columnconfigure(2, weight=1)

        self.back_button = HoverButton(toolbar, text=" Back ", command=self.go_back, state=tk.DISABLED,
                                       bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.back_button.pack(side=tk.LEFT, padx=5)

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

        # Keep original file listbox padding
        self.file_listbox.pack(pady=(0, 8), padx=15, expand=True, fill=tk.BOTH)
        self.file_listbox.bind("<Double-1>", self.file_dc_act)

        # Encrypt button with dropdown
        encrypt_frame = tk.Frame(toolbar, bg="#0a1124")
        encrypt_frame.pack(side=tk.LEFT, padx=5, pady=8)
        
        theme = FFEThemeColors.THEMES.get(self.current_theme, FFEThemeColors.THEMES["Midnight Purple"])
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

        # Create status/info bar using current theme colors
        _theme = FFEThemeColors.THEMES.get(self.current_theme, FFEThemeColors.THEMES["Midnight Purple"])
        self.status_label = tk.Label(self, text="Select a file to encrypt. Double click folders to navigate.",
                                     bg=_theme["bg"], fg=_theme["text"], font=("Segoe UI", 11))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

    def acc_hdd(self):
        drives = [chr(drive) + ":\\" for drive in range(65, 91) if os.path.exists(chr(drive) + ":\\")]
        return drives

    def acc_files(self):
        try:
            self.file_listbox.delete(0, tk.END)
            file_paths = []
            display_names = []

            for entry in os.listdir(self.current_path):
                full_path = os.path.join(self.current_path, entry)

                if entry.startswith('.') or (os.name == 'nt' and os.stat(full_path).st_file_attributes & 2):
                    continue

                if os.path.isdir(full_path):
                    display_name = f"📁 {entry}/"
                elif entry.endswith(".enc"):
                    display_name = f"🔒 {entry}"
                else:
                    display_name = f"📄 {entry}"

                display_names.append(display_name)
                file_paths.append(full_path)

            for name in display_names:
                self.file_listbox.insert(tk.END, name)

            self.file_paths = file_paths
            self.status_label.config(text=f"Showing files in {self.current_path}")
            self.back_button.config(state=tk.NORMAL if self.history_index > 0 else tk.DISABLED)
            self.forward_button.config(state=tk.NORMAL if self.history_index < len(self.history) - 1 else tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load files: {str(e)}")

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
            self.acc_files()
            self.inc_stat("forward_count", 1)

    def open_settings(self):
        SettingsDialog(self)

    def apply_theme(self):
        """Apply current_theme colors to the main window widgets."""
        theme = FFEThemeColors.THEMES.get(self.current_theme, FFEThemeColors.THEMES["Midnight Purple"])
        
        # Update root window
        self.configure(bg=theme["bg"])
        
        # Update toolbar and its children
        if hasattr(self, 'toolbar') and self.toolbar:
            self.toolbar.configure(bg=theme["bg"])
            self.style_toolbar_children(theme)
        
        # Update file listbox
        self.update_file_listbox_theme(theme)
        
        # Update status label
        self.update_status_label_theme(theme)
        
        # Update encrypt/dropdown buttons if they exist
        self.update_encrypt_buttons_theme(theme)
        
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
    
    def update_status_label_theme(self, theme):
        """Update theme for the status label."""
        try:
            self.status_label.configure(bg=theme["bg"], fg=theme["text"])
            self.status_label.update_idletasks()
        except Exception:
            pass

    def inc_stat(self, key: str, amount: int = 1):
        """Increment a usage statistic and persist to ffedata.json."""
        try:
            if not hasattr(self, 'settings') or not isinstance(self.settings, dict):
                self.settings = load_app_settings()
            stats = self.settings.setdefault("stats", {})
            stats[key] = stats.get(key, 0) + amount
            save_app_settings(self.settings)
        except Exception:
            # Non-fatal; ignore stats errors
            pass

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
        if not os.path.exists("main_key.key"):
            key = Fernet.generate_key()
            with open("main_key.key", "wb") as key_file:
                key_file.write(key)
            show_modern_warning(self, "Key File Missing", """FFE has created a new Key File.

FFE couldn't find your Key File, so a new one was created.
If you think this is a mistake, please
check the following:

- Is your Key File in the same directory as "FFE.exe"?
- Is your Key File named "main_key.key"?
- Is your Key File corrupted?

If you've just opened FFE, this is normal 
and you can simply ignore this warning.
            """)
        key = self.fesys_load_key("main_key.key")
        return key

    def show_encrypt_dropdown(self):
        """Show the encryption options dropdown menu."""
        if self.encrypt_dropdown is not None:
            self.encrypt_dropdown.destroy()
            self.encrypt_dropdown = None
            return
            
        theme = FFEThemeColors.THEMES.get(self.current_theme, FFEThemeColors.THEMES["Midnight Purple"])
        
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
            self.encrypt_with_password()
        else:
            self.encrypt_with_key_file()
    
    def encrypt_with_key_file(self):
        """Encrypt the selected file using the key file."""
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_modern_error(self, "Nope", "Can't encrypt a directory. Select a file.")
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
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Welp, we couldn't encrypt that one: {str(e)}")
    
    def encrypt_with_password(self):
        """Encrypt the selected file using a password."""
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_modern_error(self, "Nope", "Can't encrypt a directory. Select a file.")
                return
                
            # Show password dialog
            dialog = PasswordDialog(
                self, 
                "Encrypt with Password",
                "Enter a password to encrypt the file:",
                confirm=True
            )
            self.wait_window(dialog)
            
            if not dialog.result:
                return  # User cancelled
                
            password = dialog.result
            
            def encrypt_operation(update_progress):
                result = encrypt_with_password(
                    full_path, 
                    password,
                    progress_callback=update_progress
                )
                success = isinstance(result, str) and "successfully encrypted" in result.lower()
                return success, result
                
            def on_encrypt_complete(result):
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
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Welp, we couldn't encrypt that one: {str(e)}")
    
    def encrypt_file(self):
        """Encrypt the selected file using the default method."""
        # Get default encryption method from settings
        default_method = self.settings.get("encryption", {}).get("default_method", "key_file")
        
        if default_method == "password":
            self.encrypt_with_password()
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
        
        def run_operation():
            try:
                # Run the operation with progress updates
                success, result = operation_callback(
                    lambda v, s=None: self._update_progress(progress_dialog, v, s)
                )
                
                # Schedule UI updates on the main thread
                self.after(0, lambda: on_operation_complete(success, result))
            except Exception as e:
                self.after(0, lambda: on_operation_complete(False, str(e)))
            finally:
                # Ensure dialog is closed
                self.after(0, lambda: progress_dialog.destroy() if progress_dialog.winfo_exists() else None)
        
        def on_operation_complete(success, result):
            if success:
                if success_callback:
                    success_callback(result)
            else:
                show_modern_error(self, "Operation Failed", str(result))
        
        # Start the operation in a separate thread
        import threading
        thread = threading.Thread(target=run_operation, daemon=True)
        thread.start()
        
        # Show the progress dialog (modal)
        self.wait_window(progress_dialog)

    def decrypt_file(self):
        if self.decrypting:
            return
            
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_modern_error(self, "Nope", "Can't decrypt a directory. Please select a file.")
                return

            if not full_path.endswith(".enc"):
                show_modern_error(self, "Nope", "Only .enc files can be decrypted.")
                return

            is_password_protected = False
            try:
                with open(full_path, 'rb') as f:
                    header = f.read(3)
                    if header == b"PWD":
                        is_password_protected = True
            except:
                pass
            if is_password_protected:
                dialog = PasswordDialog(
                    self,
                    "Password Required",
                    "This file is password protected. Please enter the password:",
                    confirm=False
                )
                self.wait_window(dialog)
                
                if not dialog.result:
                    return  # User cancelled
                    
                password = dialog.result
                
                def decrypt_operation(update_progress):
                    result = decrypt_with_password(
                        full_path,
                        password,
                        progress_callback=update_progress
                    )
                    if "incorrect password" in result.lower():
                        return False, "Incorrect password"
                    success = isinstance(result, str) and "successfully decrypted" in result.lower()
                    return success, result
                    
                def on_decrypt_complete(result):
                    if result == "Incorrect password":
                        show_modern_error(
                            self,
                            "Incorrect Password",
                            "The password you entered is incorrect. Please try again.",
                        )
                        return
                        
                    self.status_label.config(text=result)
                    self.acc_files()
                    if isinstance(result, str) and "successfully decrypted" in result.lower():
                        self.inc_stat("files_decrypted", 1)
                
                self._run_with_progress(
                    "Decrypting with Password...",
                    decrypt_operation,
                    on_decrypt_complete
                )
                
            else:
                # Use key file decryption
                def decrypt_operation(update_progress):
                    result = fesys_decrypt_file(
                        full_path,
                        self.main_key,
                        progress_callback=update_progress
                    )
                    success = isinstance(result, str) and "successfully decrypted" in result.lower()
                    return success, result
                    
                def on_decrypt_complete(result):
                    self.status_label.config(text=result)
                    self.acc_files()
                    if isinstance(result, str) and "successfully decrypted" in result.lower():
                        self.inc_stat("files_decrypted", 1)
                
                self._run_with_progress(
                    "Decrypting File...",
                    decrypt_operation,
                    on_decrypt_complete
                )
                
        except IndexError:
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Failed to decrypt file: {str(e)}")
        finally:
            self.decrypting = False

    def show_about(self):
        # Custom themed About dialog with right-aligned "Visit" buttons for socials
        theme = FFEThemeColors.THEMES.get(self.current_theme, FFEThemeColors.THEMES["Midnight Purple"])

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
            text="Version 3.0 Developer Beta 3",
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
            "The Aurora Update - Part A",
            "Build: ffe_102225_300_lyra",
            "Support Schedule: LYRA-03-A",
            "Python 3.14.0",
            "Windows Edition",
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
            btn = FFEHoverButton(
                row,
                text="      Visit      ",
                command=lambda u=url: webbrowser.open_new(u),
                bg=theme["accent"],
                fg=FFEThemeColors.get_button_text_color(self.current_theme, "accent"),
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

        imports_btn = FFEHoverButton(
            main,
            text="View Dependencies",
            command=lambda: self.show_imports(win),
            bg=FFEThemeColors.get_dialog_colors("info", self.current_theme),
            fg=FFEThemeColors.get_button_text_color(self.current_theme, "info"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
        )
        imports_btn.pack(fill="x", pady=(12, 5))

        tk.Frame(main, height=2, bg=theme["accent"]).pack(fill="x", pady=(10, 10))

        btns = tk.Frame(main, bg=theme["secondary_bg"]) ; btns.pack(fill="x", pady=(0, 0))
        close_btn = FFEHoverButton(
            btns,
            text="                                                    ✓                                                    ",
            command=win.destroy,
            bg=FFEThemeColors.get_dialog_colors("info", self.current_theme),
            fg=FFEThemeColors.get_button_text_color(self.current_theme, "info"),
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

    def show_imports(self, parent_window):
        """Display a window showing all imports used in FFE."""
        theme = FFEThemeColors.THEMES.get(self.current_theme, FFEThemeColors.THEMES["Midnight Purple"])
        
        win = tk.Toplevel(parent_window)
        win.title("FFE Dependencies")
        win.configure(bg=theme["secondary_bg"])
        win.transient(parent_window)
        win.resizable(True, True)
        
        # Main container
        main_frame = tk.Frame(win, bg=theme["secondary_bg"], padx=20, pady=20)
        main_frame.pack(expand=True, fill="both")
        
        # Title
        tk.Label(
            main_frame,
            text="FFE Dependencies",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
            justify="left"
        ).pack(anchor="w", pady=(0, 15))
        
        # Text widget with scrollbar for imports
        text_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        text_frame.pack(expand=True, fill="both")
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        
        imports_text = tk.Text(
            text_frame,
            wrap=tk.WORD,
            yscrollcommand=scrollbar.set,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10),
            padx=10,
            pady=10,
            relief="flat"
        )
        imports_text.pack(expand=True, fill="both")
        scrollbar.config(command=imports_text.yview)
        
        # Get all imports from the current namespace
        import pkgutil
        import importlib
        
        # List of standard library modules to exclude
        stdlib = {pkg.name for pkg in pkgutil.iter_modules() if pkg.ispkg}
        
        # Get all imported modules
        imported_modules = set()
        for name, module in list(globals().items()):
            if hasattr(module, '__package__') and module.__package__:
                imported_modules.add(module.__name__.split('.')[0])
        
        # Sort the modules
        sorted_modules = sorted(imported_modules)
        
        # Add modules to the text widget
        imports_text.insert(tk.END, "Python Standard Library:\n")
        imports_text.insert(tk.END, "=" * 30 + "\n\n")
        
        for module in sorted_modules:
            if module in stdlib:
                imports_text.insert(tk.END, f"• {module}\n")
        
        imports_text.insert(tk.END, "\n\nThird-party Packages:\n")
        imports_text.insert(tk.END, "=" * 30 + "\n\n")
        
        for module in sorted_modules:
            if module not in stdlib and not module.startswith('_'):
                try:
                    pkg = importlib.import_module(module)
                    version = getattr(pkg, '__version__', 'version not found')
                    imports_text.insert(tk.END, f"• {module} (v{version})\n")
                except ImportError:
                    imports_text.insert(tk.END, f"• {module} (version unknown)\n")
        
        # Make text read-only
        imports_text.config(state="disabled")
        
        # Close button
        btn_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
        btn_frame.pack(fill="x", pady=(15, 0))
        
        close_btn = FFEHoverButton(
            btn_frame,
            text="Close",
            command=win.destroy,
            bg=FFEThemeColors.get_dialog_colors("info", self.current_theme),
            fg=FFEThemeColors.get_button_text_color(self.current_theme, "info"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
        )
        close_btn.pack(side="right")
        
        # Set window size and position
        win.update_idletasks()
        width = min(600, win.winfo_screenwidth() - 100)
        height = min(600, win.winfo_screenheight() - 100)
        x = (win.winfo_screenwidth() // 2) - (width // 2)
        y = (win.winfo_screenheight() // 2) - (height // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")
        
        # Make the window modal
        win.grab_set()
        win.focus_set()

    def show_help(self):
        response = show_modern_question(self, "Need Help?", """    Need Help using FFE?

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
                show_modern_error(self, "Nope", "Cannot delete a directory. Please select a file.")
                return
                
            if not os.path.exists(full_path):
                show_modern_error(self, "Error",
                               "We couldn't find that file. You might not have sufficient permissions to modify it.")
                return
                
            # Use the context menu's delete dialog for consistency
            if not hasattr(self, 'context_menu'):
                # If for some reason context menu isn't initialized, create a temporary one
                self.context_menu = FileContextMenu(self, 
                    FFEThemeColors.THEMES.get(self.current_theme, FFEThemeColors.THEMES["Midnight Purple"]))
            
            self.context_menu.show_delete_dialog(full_path)
            
        except IndexError:
            show_modern_error(self, "No File Selected",
                           "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Error", f"Something went wrong while trying to delete {str(e)}")

    def update_ffe(self):

        try:
            current_version = "3.0.0" #UPDATE VERSION, CURR-V

            url = f"https://api.github.com/repos/AVXAdvanced/FFE/releases/latest"
            response = requests.get(url)
            response.raise_for_status()

            latest_release = response.json()
            release_name = latest_release["name"]
            match = re.search(r"Version (\d+\.\d+\.\d+)", release_name)

            if match:
                latest_version = match.group(1)
            else:
                show_modern_error(self, "Error",
                                     "An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually.")
                return

            if version.parse(latest_version) > version.parse(current_version):
                confirm = show_modern_question(self, "Update Available", f"""Version {latest_version} is available. 

New versions of FFE include important improvements.
You should always update FFE when possible.

Would you like to download the Update now?
""")
                if confirm:
                    asset_url = latest_release["assets"][0]["browser_download_url"]
                    filename = latest_release["assets"][0]["name"]
                    download_path = os.path.join(os.path.expanduser("~"), "Downloads", filename)
                else:
                    print("")
            else:
                show_modern_info(self, "No Updates Available", "You're already on the newest version. No updates currently available.")

        except requests.exceptions.RequestException as e:
            show_modern_error(self, "Update Error",
                                 f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"Error checking updates: {e}")
        except KeyError as e:
            show_modern_error(self, "Update Error",
                                 f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"Error parsing GitHub API: {e}")
        except Exception as e:
            show_modern_error(self, "Update Error",
                                 f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    app = FFEApp()
    app.mainloop()
