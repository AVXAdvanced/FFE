import os
import sys
import ctypes
import ctypes.wintypes
import requests
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox, ttk, simpledialog, filedialog, Entry, Frame, Label, StringVar, X, Scrollbar
import textwrap
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import webbrowser
import secrets
import struct
import base64
import threading
import zipfile
import time
import hashlib
import hmac
import uuid

# Optional drag & drop support (requires `tkinterdnd2`)
try:
    # noinspection PyPackageRequirements
    from tkinterdnd2 import DND_FILES, TkinterDnD

    DND2_AVAILABLE = True
except Exception:
    DND2_AVAILABLE = False
    DND_FILES = None
    TkinterDnD = None

FFEBaseTk = TkinterDnD.Tk if DND2_AVAILABLE and TkinterDnD is not None else tk.Tk

# Threading lock for shared state access
app_lock = threading.Lock()

_FFE_UI_SCALE = 1.0


def _ffe_enable_windows_dpi_awareness():
    if os.name != 'nt':
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def _ffe_configure_tk_scaling(root_window):
    global _FFE_UI_SCALE
    try:
        dpi = float(root_window.winfo_fpixels('1i'))
        if dpi <= 0:
            dpi = 96.0
    except Exception:
        dpi = 96.0

    ui_scale = max(1.0, min(4.0, dpi / 96.0))
    tk_scaling = max(1.0, min(4.0, dpi / 72.0))

    try:
        root_window.tk.call('tk', 'scaling', tk_scaling)
    except Exception:
        pass

    try:
        default_font = tkfont.nametofont('TkDefaultFont')
        text_font = tkfont.nametofont('TkTextFont')
        fixed_font = tkfont.nametofont('TkFixedFont')
        menu_font = tkfont.nametofont('TkMenuFont')
        heading_font = tkfont.nametofont('TkHeadingFont')

        base_size = int(round(10 * ui_scale))
        for f in (default_font, text_font, fixed_font, menu_font):
            try:
                f.configure(size=base_size)
            except Exception:
                pass
        try:
            heading_font.configure(size=int(round(11 * ui_scale)), weight='bold')
        except Exception:
            pass
    except Exception:
        pass

    _FFE_UI_SCALE = ui_scale


def _ffe_px(value):
    try:
        return int(round(float(value) * float(_FFE_UI_SCALE)))
    except Exception:
        return int(value)


def set_dark_title_bar(window):
    """
    Apply dark mode to the title bar of a Tkinter window on Windows 10/11.

    Args:
        window: The Tkinter window or Toplevel widget
    """
    if os.name != 'nt':
        return

    if not hasattr(window, 'winfo_id'):
        print("[DEBUG] set_dark_title_bar: Not a valid Tkinter window")
        return

    try:
        if hasattr(window, 'winfo_exists') and not window.winfo_exists():
            return
    except Exception:
        return

    try:
        hwnd = window.winfo_id()
        if not hwnd:
            return

        try:
            user32 = ctypes.WinDLL('user32', use_last_error=True)
            GA_ROOT = 2
            root_hwnd = user32.GetAncestor(hwnd, GA_ROOT)
            if root_hwnd:
                hwnd = root_hwnd
        except Exception:
            pass

        try:
            dwmapi = ctypes.windll.dwmapi
        except Exception:
            return

        if not hasattr(dwmapi, 'DwmSetWindowAttribute'):
            return

        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19

        value = ctypes.c_int(1)
        for attr in (DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1):
            try:
                result = dwmapi.DwmSetWindowAttribute(
                    ctypes.wintypes.HWND(hwnd),
                    ctypes.wintypes.DWORD(attr),
                    ctypes.byref(value),
                    ctypes.sizeof(value)
                )
                if result == 0:
                    return
            except Exception as e:
                print(f"[DEBUG] Error setting dark mode (attr={attr}): {e}")

    except Exception as e:
        print(f"[DEBUG] Error in set_dark_title_bar: {e}")


_DARK_TITLEBAR_HOOK_INSTALLED = False
_ORIG_TK_TOPLEVEL_INIT = None


def _schedule_dark_title_bar(window, attempts=12, delay_ms=60):
    if os.name != 'nt':
        return
    try:
        if hasattr(window, 'winfo_exists') and not window.winfo_exists():
            return
    except Exception:
        return

    def _attempt(remaining):
        try:
            if hasattr(window, 'winfo_exists') and not window.winfo_exists():
                return
            if hasattr(window, 'update_idletasks'):
                window.update_idletasks()
            set_dark_title_bar(window)
        except Exception:
            pass

        if remaining > 0:
            try:
                window.after(delay_ms, lambda: _attempt(remaining - 1))
            except Exception:
                pass

    _attempt(attempts)


def enable_dark_title_bar_for_all_windows(root_window):
    global _DARK_TITLEBAR_HOOK_INSTALLED, _ORIG_TK_TOPLEVEL_INIT
    if os.name != 'nt':
        return
    if _DARK_TITLEBAR_HOOK_INSTALLED:
        try:
            _schedule_dark_title_bar(root_window)
        except Exception:
            pass
        return

    _DARK_TITLEBAR_HOOK_INSTALLED = True

    try:
        _ORIG_TK_TOPLEVEL_INIT = tk.Toplevel.__init__
    except Exception:
        _ORIG_TK_TOPLEVEL_INIT = None
        return

    def _patched_toplevel_init(self, *args, **kwargs):
        _ORIG_TK_TOPLEVEL_INIT(self, *args, **kwargs)
        try:
            self.bind("<Map>", lambda _e: _schedule_dark_title_bar(self), add="+")
        except Exception:
            pass
        _schedule_dark_title_bar(self)

    tk.Toplevel.__init__ = _patched_toplevel_init

    try:
        _schedule_dark_title_bar(root_window)
    except Exception:
        pass


_FADE_HOOK_INSTALLED = False
_ORIG_TK_TOPLEVEL_INIT_FADE = None
_ORIG_TK_TOPLEVEL_DESTROY_FADE = None
_ORIG_TK_TK_DESTROY_FADE = None


def _ffe_window_supports_alpha(window):
    try:
        window.attributes("-alpha")
        return True
    except Exception:
        return False


def _ffe_should_animate_window(window):
    try:
        if getattr(window, "_ffe_disable_fade", False):
            return False
        if hasattr(window, "winfo_exists") and not window.winfo_exists():
            return False
        if hasattr(window, "wm_overrideredirect") and window.wm_overrideredirect():
            return False
        return _ffe_window_supports_alpha(window)
    except Exception:
        return False


def _ffe_fade_in(window, alpha=0.0, step=0.08, interval_ms=10):
    try:
        if hasattr(window, "winfo_exists") and not window.winfo_exists():
            return
        if not _ffe_should_animate_window(window):
            try:
                window.attributes("-alpha", 1.0)
            except Exception:
                pass
            return

        if getattr(window, "_ffe_fading_out", False):
            return

        alpha = float(alpha) + float(step)
        if alpha < 1.0:
            try:
                window.attributes("-alpha", alpha)
            except Exception:
                return
            window.after(interval_ms, lambda: _ffe_fade_in(window, alpha, step=step, interval_ms=interval_ms))
        else:
            try:
                window.attributes("-alpha", 1.0)
            except Exception:
                pass
    except Exception:
        return


def _ffe_fade_out(window, done_var, alpha=None, step=0.08, interval_ms=10):
    try:
        if hasattr(window, "winfo_exists") and not window.winfo_exists():
            try:
                done_var.set(True)
            except Exception:
                pass
            return

        if not _ffe_should_animate_window(window):
            try:
                done_var.set(True)
            except Exception:
                pass
            return

        if alpha is None:
            try:
                alpha = float(window.attributes("-alpha"))
            except Exception:
                alpha = 1.0

        try:
            if hasattr(window, "grab_current") and window.grab_current() is not None:
                window.grab_release()
        except Exception:
            pass

        alpha = float(alpha) - float(step)
        if alpha > 0.0:
            try:
                window.attributes("-alpha", alpha)
            except Exception:
                try:
                    done_var.set(True)
                except Exception:
                    pass
                return
            window.after(interval_ms,
                         lambda: _ffe_fade_out(window, done_var, alpha, step=step, interval_ms=interval_ms))
        else:
            try:
                window.attributes("-alpha", 0.0)
            except Exception:
                pass
            try:
                done_var.set(True)
            except Exception:
                pass
    except Exception:
        try:
            done_var.set(True)
        except Exception:
            pass


def _ffe_apply_fade_behavior_to_window(window):
    try:
        if getattr(window, "_ffe_fade_behavior_applied", False):
            return
        window._ffe_fade_behavior_applied = True

        if not getattr(window, "_ffe_fade_in_bind_installed", False):
            window._ffe_fade_in_bind_installed = True

            def _on_map(_e=None):
                try:
                    if getattr(window, "_ffe_fade_in_done", False):
                        return
                    window._ffe_fade_in_done = True

                    def _start_fade_in():
                        try:
                            if not _ffe_should_animate_window(window):
                                try:
                                    window.attributes("-alpha", 1.0)
                                except Exception:
                                    pass
                                return

                            try:
                                window.attributes("-alpha", 0.0)
                            except Exception:
                                return

                            window.after(10, lambda: _ffe_fade_in(window))
                        except Exception:
                            return

                    window.after(10, _start_fade_in)
                except Exception:
                    return

            try:
                window.bind("<Map>", _on_map, add="+")
            except Exception:
                pass

        try:
            if getattr(window, "_ffe_fade_in_done", False):
                return
            if hasattr(window, "winfo_viewable") and window.winfo_viewable():
                window.after(0, lambda: window.event_generate("<Map>"))
        except Exception:
            pass
    except Exception:
        return


def enable_fade_animations_for_all_windows(root_window):
    global _FADE_HOOK_INSTALLED, _ORIG_TK_TOPLEVEL_INIT_FADE, _ORIG_TK_TOPLEVEL_DESTROY_FADE, _ORIG_TK_TK_DESTROY_FADE
    if _FADE_HOOK_INSTALLED:
        try:
            _ffe_apply_fade_behavior_to_window(root_window)
        except Exception:
            pass
        return

    _FADE_HOOK_INSTALLED = True

    try:
        _ORIG_TK_TOPLEVEL_INIT_FADE = tk.Toplevel.__init__
    except Exception:
        _ORIG_TK_TOPLEVEL_INIT_FADE = None

    try:
        _ORIG_TK_TOPLEVEL_DESTROY_FADE = tk.Toplevel.destroy
    except Exception:
        _ORIG_TK_TOPLEVEL_DESTROY_FADE = None

    try:
        _ORIG_TK_TK_DESTROY_FADE = tk.Tk.destroy
    except Exception:
        _ORIG_TK_TK_DESTROY_FADE = None

    if _ORIG_TK_TOPLEVEL_INIT_FADE is not None:
        def _patched_toplevel_init_fade(self, *args, **kwargs):
            _ORIG_TK_TOPLEVEL_INIT_FADE(self, *args, **kwargs)
            _ffe_apply_fade_behavior_to_window(self)

        tk.Toplevel.__init__ = _patched_toplevel_init_fade

    if _ORIG_TK_TOPLEVEL_DESTROY_FADE is not None:
        def _patched_toplevel_destroy_fade(self):
            try:
                if getattr(self, "_ffe_destroy_in_progress", False):
                    return _ORIG_TK_TOPLEVEL_DESTROY_FADE(self)
                if getattr(self, "_ffe_fading_out", False):
                    return _ORIG_TK_TOPLEVEL_DESTROY_FADE(self)
                if not _ffe_should_animate_window(self):
                    return _ORIG_TK_TOPLEVEL_DESTROY_FADE(self)

                self._ffe_fading_out = True
                done = tk.BooleanVar(master=self, value=False)
                self.after(0, lambda: _ffe_fade_out(self, done))

                try:
                    self.wait_variable(done)
                except Exception:
                    pass

                self._ffe_destroy_in_progress = True
                return _ORIG_TK_TOPLEVEL_DESTROY_FADE(self)
            except Exception:
                return _ORIG_TK_TOPLEVEL_DESTROY_FADE(self)

        tk.Toplevel.destroy = _patched_toplevel_destroy_fade

    if _ORIG_TK_TK_DESTROY_FADE is not None:
        def _patched_tk_destroy_fade(self):
            try:
                if getattr(self, "_ffe_destroy_in_progress", False):
                    return _ORIG_TK_TK_DESTROY_FADE(self)
                if getattr(self, "_ffe_fading_out", False):
                    return _ORIG_TK_TK_DESTROY_FADE(self)
                if not _ffe_should_animate_window(self):
                    return _ORIG_TK_TK_DESTROY_FADE(self)

                self._ffe_fading_out = True
                done = tk.BooleanVar(master=self, value=False)
                self.after(0, lambda: _ffe_fade_out(self, done))

                try:
                    self.wait_variable(done)
                except Exception:
                    pass

                self._ffe_destroy_in_progress = True
                return _ORIG_TK_TK_DESTROY_FADE(self)
            except Exception:
                return _ORIG_TK_TK_DESTROY_FADE(self)

        tk.Tk.destroy = _patched_tk_destroy_fade

    try:
        _ffe_apply_fade_behavior_to_window(root_window)
    except Exception:
        pass


# /n for line break
# /n/n works for double line break (space between line break)

# Please don't remove any wierd looking text formatting, it's usually correct for a decent ui.. tkinter is wierd

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
        "fast": 200000,  # Less secure, but faster
        "balanced": 600000,  # Good balance (default)
        "secure": 1000000  # More secure, but slower
    }.get(security_level.lower(), 600000)  # Default to balanced if invalid

    print(f"Using {security_level} security level with {iterations:,} iterations")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())


def generate_salt() -> bytes:
    print("def generate_salt")
    print("")
    return secrets.token_bytes(16)


def _secure_clear_memory(*args):
    for data in args:
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0


def _validate_file_path(file_path: str) -> bool:
    if not file_path or not isinstance(file_path, str):
        return False

    # Normalize the path
    normalized_path = os.path.normpath(file_path)

    # Check for directory traversal attempts
    # (Use path segments rather than substring checks to avoid false positives.)
    try:
        parts = [p for p in normalized_path.replace("/", "\\").split("\\") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            return False
    except Exception:
        return False

    # Check for special characters that are invalid in Windows file paths.
    # Note: ':' is required for drive letters on Windows (e.g. C:\\...), so allow it only in that position.
    invalid_chars = ['<', '>', '"', '|', '?', '*']
    if any(char in file_path for char in invalid_chars):
        return False

    if os.name == 'nt':
        # Allow UNC paths (\\server\\share\\...) and drive-letter paths (C:\\...)
        # Reject ':' anywhere except as the drive separator.
        colon_positions = [i for i, ch in enumerate(file_path) if ch == ':']
        if colon_positions:
            if not (len(colon_positions) == 1 and colon_positions[0] == 1 and file_path[0].isalpha()):
                return False
    else:
        # On non-Windows, ':' is valid, but NUL is not.
        pass

    # Reject null bytes explicitly
    if '\x00' in file_path:
        return False

    return True


def _validate_password(password: str) -> bool:
    """Validate password format for security critical checks only."""
    if not password or not isinstance(password, str):
        return False

    # Check for null bytes (security critical)
    if '\x00' in password:
        return False

    return True


def encrypt_with_password(file_path: str, password: str, progress_callback=None, security_level=None) -> str:
    def update_progress(value, status=None):
        if progress_callback: progress_callback(value, status)

    if not _validate_file_path(file_path):
        return "Invalid file path. Path contains unsafe characters or attempts directory traversal."
    if not _validate_password(password):
        return "Invalid password format. Password cannot contain null bytes."

    password_bytes = bytearray(password.encode('utf-8'))
    try:
        update_progress(5, "Initializing encryption...")
        salt = generate_salt()
        update_progress(10, "Deriving key...")

        # Derive key & put it in a safe mutable buffer
        key = bytearray(derive_key(password, salt, security_level))
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(bytes(key)), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        file_size = os.path.getsize(file_path)
        chunk_size = 64 * 1024
        bytes_processed = 0

        encrypted_file_path = file_path + ".enc"

        update_progress(30, "Encrypting data...")
        with open(encrypted_file_path, "wb") as out_f:
            # Write dummy header space (3 PWD + 16 salt + 12 nonce + 16 placeholder tag)
            out_f.write(b"PWD" + salt + nonce + (b'\x00' * 16))

            with open(file_path, "rb") as in_f:
                while True:
                    chunk = in_f.read(chunk_size)
                    if not chunk:
                        break
                    out_f.write(encryptor.update(chunk))
                    bytes_processed += len(chunk)
                    progress = 30 + int((bytes_processed / max(1, file_size)) * 60)
                    update_progress(progress, f"Encrypting... {bytes_processed:,} / {file_size:,} bytes")

            # Finalize and retrieve auth tag
            out_f.write(encryptor.finalize())
            tag = encryptor.tag

            # Seek back and overwrite placeholder tag
            out_f.seek(3 + 16 + 12)
            out_f.write(tag)

        update_progress(100, "Encryption complete!")
        return f"File '{os.path.basename(file_path)}' successfully encrypted with password!"
    except Exception as e:
        return f"Error during password encryption: {str(e)}"
    finally:
        _secure_clear_memory(password_bytes, key if 'key' in locals() else None)


def decrypt_with_password(file_path: str, password: str, progress_callback=None) -> str:
    def update_progress(value, status=None):
        if progress_callback: progress_callback(value, status)

    password_bytes = bytearray(password.encode('utf-8')) if password else bytearray()
    output_path = file_path[:-4] if file_path.lower().endswith(".enc") else file_path + ".decrypted"

    try:
        update_progress(5, "Reading encrypted file...")
        with open(file_path, "rb") as f:
            header = f.read(3)
            if header != b"PWD":
                return "Not a password-encrypted file or file is corrupted."

            salt = f.read(16)
            nonce = f.read(12)
            tag = f.read(16)

            update_progress(20, "Deriving decryption key...")
            key = bytearray(derive_key(password, salt))

            update_progress(30, "Initializing decryption...")
            cipher = Cipher(algorithms.AES(bytes(key)), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            file_size = os.path.getsize(file_path)
            bytes_processed = 0

            update_progress(40, "Decrypting data...")
            with open(output_path, 'wb') as out_f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    out_f.write(decryptor.update(chunk))
                    bytes_processed += len(chunk)
                    progress = 40 + int((bytes_processed / max(1, file_size)) * 50)
                    update_progress(progress, "Decrypting...")

                # Will raise exception if wrong password/corrupted file
                out_f.write(decryptor.finalize())

        update_progress(100, "Decryption complete!")
        return f"File '{os.path.basename(file_path)}' successfully decrypted!"
    except Exception as e:
        # Delete malformed half-decrypted file on error
        if os.path.exists(output_path):
            os.remove(output_path)
        if "decryption failed" in str(e).lower() or "tag" in str(e).lower():
            return "Incorrect password. Decryption failed."
        return f"Error during password decryption: {str(e)}"
    finally:
        _secure_clear_memory(password_bytes, key if 'key' in locals() else None)


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
        "view_mode": "file_explorer",  # Options: file_explorer, mostly_file_explorer, mostly_drag_drop, drag_drop_only
        "ui": {
            "show_hidden_files": False,
            "remember_last_folder": True,
            "last_folder": None
        },
        "delete": {
            "show_options_dialog": True,
            "confirm_when_skipping_dialog": True,
            "default_method": "normal"  # normal | secure
        },
        "encryption": {
            "default_method": "password",
            # Security level for password-based encryption: fast, balanced, secure
            "security_level": "balanced",
            # Legacy toggle (kept for backwards compatibility)
            "faster_mode": False
            # password is default. using key_file as the generation default is NOT recommended.
        },
        "key_mgmt": {
            "installation_id": None,
            "installation_secret": None,
            "registered_keys": {},
            "active_key_id": None
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
    with app_lock:  # Use threading lock to prevent race conditions
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


def encrypt_with_keyfile(file_path: str, main_key: bytes, use_password: bool = False, password: str = None,
                         progress_callback=None):
    def update_progress(value, status=None):
        if progress_callback: progress_callback(value, status)

    if use_password:
        if not password: return "Password is required for password-based encryption."
        return encrypt_with_password(file_path, password, progress_callback=progress_callback)

    try:
        update_progress(5, "Initializing encryption...")
        cipher_main = Fernet(main_key)

        # We wrap a raw AES key via Fernet instead of using Fernet for the whole file payload
        file_key = bytearray(secrets.token_bytes(32))
        nonce = secrets.token_bytes(12)
        encrypted_key = cipher_main.encrypt(bytes(file_key))

        cipher = Cipher(algorithms.AES(bytes(file_key)), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        file_size = os.path.getsize(file_path)
        chunk_size = 64 * 1024
        bytes_processed = 0

        encrypted_file_path = file_path + ".enc"

        update_progress(20, "Encrypting data...")
        with open(encrypted_file_path, "wb") as out_f:
            # Write stream header: KFE2 + key length + encrypted key + nonce + placeholder tag
            key_len_bytes = struct.pack(">I", len(encrypted_key))
            header_start = b"KFE2" + key_len_bytes + encrypted_key + nonce
            out_f.write(header_start + (b'\x00' * 16))

            with open(file_path, "rb") as in_f:
                while True:
                    chunk = in_f.read(chunk_size)
                    if not chunk:
                        break
                    out_f.write(encryptor.update(chunk))
                    bytes_processed += len(chunk)
                    progress = 20 + int((bytes_processed / max(1, file_size)) * 70)
                    update_progress(progress, f"Encrypting... {bytes_processed:,} / {file_size:,} bytes")

            out_f.write(encryptor.finalize())
            tag = encryptor.tag

            out_f.seek(len(header_start))
            out_f.write(tag)

        update_progress(100, "Encryption complete!")
        return f"File '{os.path.basename(file_path)}' successfully encrypted with key file!"
    except Exception as e:
        return f"Error during encryption: {str(e)}"
    finally:
        if 'file_key' in locals(): _secure_clear_memory(file_key)


def decrypt_with_keyfile(file_path, main_key, progress_callback=None):
    def update_progress(value, status=None):
        if progress_callback: progress_callback(value, status)

    if not _validate_file_path(file_path):
        return "Invalid file path. Path contains unsafe characters or attempts directory traversal."

    try:
        update_progress(5, "Starting decryption...")
        if not os.path.isfile(file_path): return "Error: File does not exist or is not a file."
        if not os.access(file_path, os.R_OK): return "Error: File is not readable."
        if not file_path.endswith(".enc"): return "Only .enc files can be decrypted."

        # Pass it down if it's password encrypted
        try:
            with open(file_path, "rb") as f:
                header = f.read(3)
                if header == b"PWD":
                    parent = progress_callback.__self__ if progress_callback and hasattr(progress_callback,
                                                                                         '__self__') else tk._default_root
                    d = PasswordDialog(parent, "Password Required", "Enter password for decryption:", confirm=False)
                    d.wait_window()
                    password = d.result
                    if not password: return "Decryption cancelled by user."

                    temp_password = password
                    password = None
                    try:
                        result = decrypt_with_password(file_path, temp_password, progress_callback=progress_callback)
                    finally:
                        _secure_clear_memory(bytearray(temp_password.encode('utf-8')) if temp_password else bytearray())

                    if result and ("Incorrect password" in result or "decryption failed" in result.lower()):
                        if parent: show_neoui_error(parent, "Decryption Failed",
                                                    "Incorrect password. Please try again.")
                    return result
        except Exception as e:
            pass

        update_progress(10, "Loading encryption keys...")
        if not main_key or not isinstance(main_key, bytes): return "Error: Invalid encryption key."

        try:
            cipher_main = Fernet(main_key)
        except Exception as e:
            return f"Error: Invalid encryption key format: {str(e)}"

        output_path = file_path[:-4] if file_path.lower().endswith(".enc") else file_path + ".decrypted"

        with open(file_path, "rb") as f:
            header = f.read(4)
            if header == b"KFE2":
                # KFE2: AES-GCM streaming format
                key_len = struct.unpack(">I", f.read(4))[0]
                encrypted_key = f.read(key_len)
                nonce = f.read(12)
                tag = f.read(16)

                try:
                    file_key = bytearray(cipher_main.decrypt(encrypted_key))
                except Exception:
                    return "Incorrect Key File\n\nThe key file you selected does not match."

                update_progress(30, "Decrypting file content...")
                cipher = Cipher(algorithms.AES(bytes(file_key)), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()

                file_size = os.path.getsize(file_path)
                bytes_processed = 0

                try:
                    with open(output_path, "wb") as out_f:
                        while True:
                            chunk = f.read(64 * 1024)
                            if not chunk: break
                            out_f.write(decryptor.update(chunk))
                            bytes_processed += len(chunk)
                            progress = 30 + int((bytes_processed / max(1, file_size)) * 60)
                            update_progress(progress, "Decrypting...")
                        out_f.write(decryptor.finalize())
                except Exception as e:
                    if os.path.exists(output_path): os.remove(output_path)
                    raise e
                finally:
                    _secure_clear_memory(file_key)

            elif header == b"KFE1":
                # KFE1: Legacy completely-in-memory Fernet format
                update_progress(20, "Processing legacy file...")
                f.seek(0)
                full_encrypted_data = f.read()

                key_len = struct.unpack(">I", full_encrypted_data[4:8])[0]
                key_start = 8
                key_end = key_start + key_len
                encrypted_key = full_encrypted_data[key_start:key_end]
                encrypted_data = full_encrypted_data[key_end:]

                try:
                    decrypted_key = cipher_main.decrypt(encrypted_key)
                    cipher_file = Fernet(decrypted_key)
                    decrypted_data = cipher_file.decrypt(encrypted_data)
                except Exception:
                    return "Incorrect Key File\n\nThe key file you selected does not match."

                update_progress(80, "Saving legacy decrypted file...")
                with open(output_path, "wb") as out_f:
                    out_f.write(decrypted_data)
            else:
                # Ancient un-headered fallback
                try:
                    f.seek(0)
                    full_encrypted_data = f.read()
                    encrypted_data, encrypted_key = full_encrypted_data.rsplit(b"|||", 1)
                    decrypted_key = cipher_main.decrypt(encrypted_key)
                    cipher_file = Fernet(decrypted_key)
                    decrypted_data = cipher_file.decrypt(encrypted_data)
                    with open(output_path, "wb") as out_f:
                        out_f.write(decrypted_data)
                except Exception:
                    return "Error: Encrypted file is corrupted or not in the correct format."

        update_progress(100, "Decryption complete!")
        return None
    except Exception as e:
        error_msg = str(e).lower()
        if "invalid signature" in error_msg or "invalid token" in error_msg or "invalid key" in error_msg or "tag" in error_msg:
            return "Incorrect Key File\n\nThe key file you selected does not match the one used to encrypt this file."
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
        "Arctic Stars": {
            "bg": "#0f1419",
            "secondary_bg": "#1a2027",
            "accent": "#3d4a59",
            "success": "#3d7a5f",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
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
                r, g, b = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
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
                r, g, b = tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))
                r = max(0, r - darkness_factor)
                g = max(0, g - darkness_factor)
                b = max(0, b - darkness_factor)
                return f"#{r:02x}{g:02x}{b:02x}"
            except ValueError:
                return color
        return color


class NeoUIScrollbar(ttk.Scrollbar):
    """A themed scrollbar that adapts to the NeoUI colors."""

    def __init__(self, master, parent_theme_name="Ocean Deep", **kwargs):
        # Get theme colors
        theme = NeoUIThemes.THEMES.get(parent_theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        # Create a unique style name to prevent conflicts
        style_name = f"NeoUI.Vertical.TScrollbar"

        style = ttk.Style()
        # Ensure we are using a theme that supports recoloring (clam is best for this)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        # Configure the colors
        style.configure(
            style_name,
            background=theme["accent"],  # The thumb color
            troughcolor=theme["bg"],  # The track color
            bordercolor=theme["secondary_bg"],
            arrowcolor=theme["text"],
            relief="flat",
            borderwidth=0
        )

        # Map active states (hovering over the scrollbar)
        style.map(
            style_name,
            background=[('active', theme["text"]), ('pressed', theme["text"])],
            arrowcolor=[('active', theme["accent"])]
        )

        kwargs["style"] = style_name
        super().__init__(master, **kwargs)


class ProgressDialog(tk.Toplevel):
    def __init__(self, parent, title="Processing..."):
        super().__init__(parent)
        self.withdraw()  # Hide initially
        self.attributes('-alpha', 0.0)  # Make transparent
        self.title(title)

        # Get theme
        theme_name = getattr(parent, 'current_theme', 'Ocean Deep')
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        # Configure window
        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)

        self.after(40, lambda: set_dark_title_bar(self))

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
            length=_ffe_px(400),
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

        # Center on screen (use requested size; avoid tiny 1x1 geometry)
        self.update_idletasks()
        req_w = self.winfo_reqwidth()
        req_h = self.winfo_reqheight()

        min_w = _ffe_px(520)
        min_h = _ffe_px(210)
        final_w = max(min_w, req_w)
        final_h = max(min_h, req_h)

        x = (self.winfo_screenwidth() // 2) - (final_w // 2)
        y = (self.winfo_screenheight() // 2) - (final_h // 2)
        self.geometry(f"{final_w}x{final_h}+{x}+{y}")
        self.minsize(final_w, final_h)

        if _FADE_HOOK_INSTALLED:
            _ffe_apply_fade_behavior_to_window(self)

        # Make it modal
        self.deiconify()
        self.grab_set()
        self.focus_set()

    def update_progress(self, value, status=None):
        """Update progress bar value (0-100) and status text."""
        self.progress_var.set(min(100, max(0, value)))
        if status is not None:
            self.status_var.set(status)
        self.update_idletasks()


def _neoui_theme_source(widget):
    cur = widget
    seen = set()
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if hasattr(cur, 'current_theme'):
            return cur
        if hasattr(cur, 'parent'):
            cur = getattr(cur, 'parent', None)
            continue
        if hasattr(cur, 'master'):
            cur = getattr(cur, 'master', None)
            continue
        break
    return widget


class neouiDialog(tk.Toplevel):
    TITLE_FONT_SIZE = 29
    VERSION_FONT_SIZE = 16
    CONTENT_FONT_SIZE = 11

    def __init__(self, parent, title, message, dialog_type="info", title_font_size=None):
        super().__init__(parent)
        self.withdraw()  # Hide initially
        self.attributes('-alpha', 0.0)  # Make transparent

        self.after(40, lambda: set_dark_title_bar(self))

        self.result = None

        # Theme
        theme_parent = _neoui_theme_source(parent)
        theme_name = getattr(theme_parent, 'current_theme', 'Ocean Deep')
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

        # Message - Reduced padding here to tighten the UI
        clean_message = textwrap.dedent(message).lstrip("\n")
        msg = tk.Label(main, text=clean_message, bg=theme["secondary_bg"], fg=theme["text"],
                       font=(DEFAULT_FONT, self.CONTENT_FONT_SIZE), justify="left", wraplength=_ffe_px(680))
        msg.pack(pady=(10, 10), anchor="w")

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

        # --- GEOMETRY CALCULATION ---
        self.update_idletasks()

        req_w = self.winfo_reqwidth()
        req_h = self.winfo_reqheight()

        # Reduced minimum height significantly to fix "too much space" issue
        min_w = _ffe_px(480)
        min_h = _ffe_px(150)  # Was 240

        final_w = max(min_w, req_w)
        final_h = max(min_h, req_h)

        # Center on screen
        x = (self.winfo_screenwidth() // 2) - (final_w // 2)
        y = (self.winfo_screenheight() // 2) - (final_h // 2)

        # Apply geometry BEFORE deiconifying to prevent flashing 200x200
        self.geometry(f"{final_w}x{final_h}+{x}+{y}")
        self.minsize(final_w, final_h)

        self.grab_set()

        # Trigger the fade-in animation manually if needed, or just show
        if _FADE_HOOK_INSTALLED:
            _ffe_apply_fade_behavior_to_window(self)

        self.deiconify()

        if hasattr(self, '_no'):
            self.protocol("WM_DELETE_WINDOW", self._no)
        else:
            self.protocol("WM_DELETE_WINDOW", self._ok)
        self.focus_set()

    def _ok(self):
        self.result = True
        self.destroy()

    def _yes(self):
        self.result = True
        self.destroy()

    def _no(self):
        self.result = False
        self.destroy()


class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt, confirm=False):
        super().__init__(parent)
        self.withdraw()  # Hide initially
        self.attributes('-alpha', 0.0)  # Make transparent

        self.after(40, lambda: set_dark_title_bar(self))
        self.title(title)
        self.result = None
        self.confirm = confirm
        self.password = StringVar()
        self.confirm_password = StringVar() if confirm else None

        # Get theme
        theme_parent = _neoui_theme_source(parent)
        theme_name = getattr(theme_parent, 'current_theme', 'Ocean Deep')
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        # Configure window
        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)

        # Main frame
        main_frame = Frame(self, bg=theme["secondary_bg"], padx=22, pady=22)
        main_frame.pack(expand=True, fill="both")

        # Title
        title_label = Label(
            main_frame,
            text=title,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
            justify="left"
        )
        title_label.pack(anchor="w")

        tk.Frame(main_frame, height=2, bg=theme["accent"]).pack(fill="x", pady=(10, 14))

        # Prompt with wrapping
        prompt_label = Label(
            main_frame,
            text=prompt,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11),
            justify="left",
            wraplength=_ffe_px(600)
        )
        prompt_label.pack(anchor="w", pady=(0, 16), fill="x")

        # Password entry
        entry_frame = Frame(main_frame, bg=theme["secondary_bg"])
        entry_frame.pack(fill="x", pady=(0, 14))

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
        self.entry.pack(fill="x", ipady=_ffe_px(7))

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
            self.confirm_entry.pack(fill="x", ipady=_ffe_px(7))

        # Buttons
        btn_frame = Frame(main_frame, bg=theme["secondary_bg"])
        btn_frame.pack(fill="x", pady=(6, 0))
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)

        cancel_btn = NeoUIHoverButton(
            btn_frame,
            text="Cancel",
            command=self._cancel,
            bg=theme["error"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "error"),
            font=(DEFAULT_FONT, 11, "bold"),
            relief="flat"
        )
        cancel_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        ok_btn = NeoUIHoverButton(
            btn_frame,
            text="OK",
            command=self._ok,
            bg=NeoUIThemes.get_dialog_colors("info", theme_name),
            fg=NeoUIThemes.get_button_text_color(theme_name, "info"),
            font=(DEFAULT_FONT, 11, "bold"),
            relief="flat"
        )
        ok_btn.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        # Bind Enter key to OK
        self.entry.bind('<Return>', lambda e: self._ok())
        if confirm:
            self.confirm_entry.bind('<Return>', lambda e: self._ok())

        self.update_idletasks()
        req_w = self.winfo_reqwidth()
        req_h = self.winfo_reqheight()

        min_width = _ffe_px(620)
        min_height = _ffe_px(320) if confirm else _ffe_px(260)

        final_w = max(min_width, req_w)
        final_h = max(min_height, req_h)

        x = (self.winfo_screenwidth() // 2) - (final_w // 2)
        y = (self.winfo_screenheight() // 2) - (final_h // 2)

        self.minsize(final_w, final_h)
        self.geometry(f"{final_w}x{final_h}+{x}+{y}")

        self.deiconify()  # Show window with fade effect
        self.entry.focus_set()
        self.grab_set()

    def _ok(self):
        password_input = self.password.get()
        confirm_input = self.confirm_password.get() if self.confirm else None

        # Clear StringVar immediately to minimize password exposure
        self.password.set("")
        if self.confirm_password:
            self.confirm_password.set("")

        if self.confirm and password_input != confirm_input:
            show_neoui_error(self, "Error",
                             "Passwords do not match!\n\nPlease ensure both password fields contain exactly the same characters. Passwords are case-sensitive.")
            return
        if not password_input:
            show_neoui_error(self, "Error", "Password cannot be empty!\n\nPlease enter a password.")
            return

        # Enforce minimum 4-character password length
        if len(password_input) < 4:
            show_neoui_error(self, "Error",
                             "Password must be at least 4 characters long!\n\nPlease enter a stronger password for better security.")
            return

        # Store password temporarily
        self.result = password_input
        password_input = None
        confirm_input = None
        self.destroy()

    def _cancel(self):
        try:
            self.result = None
            self.destroy()
        except tk.TclError:
            pass


class TextInputDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt, initialvalue=""):
        super().__init__(parent)
        self.withdraw()
        self.attributes('-alpha', 0.0)

        self.after(40, lambda: set_dark_title_bar(self))
        self.title(title)
        self.result = None

        self.value_var = StringVar(value=initialvalue if initialvalue is not None else "")

        theme_parent = _neoui_theme_source(parent)
        theme_name = getattr(theme_parent, 'current_theme', 'Ocean Deep')
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)

        main_frame = Frame(self, bg=theme["secondary_bg"], padx=22, pady=22)
        main_frame.pack(expand=True, fill="both")

        title_label = Label(
            main_frame,
            text=title,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
            justify="left"
        )
        title_label.pack(anchor="w")

        tk.Frame(main_frame, height=2, bg=theme["accent"]).pack(fill="x", pady=(10, 14))

        prompt_label = Label(
            main_frame,
            text=prompt,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11),
            justify="left",
            wraplength=_ffe_px(600)
        )
        prompt_label.pack(anchor="w", pady=(0, 16), fill="x")

        entry_frame = Frame(main_frame, bg=theme["secondary_bg"])
        entry_frame.pack(fill="x", pady=(0, 14))

        self.entry = Entry(
            entry_frame,
            textvariable=self.value_var,
            font=(DEFAULT_FONT, 11),
            bg=theme["bg"],
            fg=theme["text"],
            insertbackground=theme["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=theme["accent"],
            highlightcolor=theme["accent"],
        )
        self.entry.pack(fill="x", ipady=_ffe_px(7))

        btn_frame = Frame(main_frame, bg=theme["secondary_bg"])
        btn_frame.pack(fill="x", pady=(6, 0))
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)

        cancel_btn = NeoUIHoverButton(
            btn_frame,
            text="Cancel",
            command=self._cancel,
            bg=theme["error"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "error"),
            font=(DEFAULT_FONT, 11, "bold"),
            relief="flat"
        )
        cancel_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        ok_btn = NeoUIHoverButton(
            btn_frame,
            text="OK",
            command=self._ok,
            bg=NeoUIThemes.get_dialog_colors("info", theme_name),
            fg=NeoUIThemes.get_button_text_color(theme_name, "info"),
            font=(DEFAULT_FONT, 11, "bold"),
            relief="flat"
        )
        ok_btn.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.entry.bind('<Return>', lambda e: self._ok())
        self.entry.bind('<Escape>', lambda e: self._cancel())

        self.update_idletasks()
        req_w = self.winfo_reqwidth()
        req_h = self.winfo_reqheight()

        min_width = _ffe_px(620)
        min_height = _ffe_px(260)

        final_w = max(min_width, req_w)
        final_h = max(min_height, req_h)

        x = (self.winfo_screenwidth() // 2) - (final_w // 2)
        y = (self.winfo_screenheight() // 2) - (final_h // 2)

        self.minsize(final_w, final_h)
        self.geometry(f"{final_w}x{final_h}+{x}+{y}")

        self.deiconify()
        try:
            self.entry.selection_range(0, tk.END)
        except tk.TclError:
            pass
        self.entry.focus_set()
        self.grab_set()

        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _ok(self):
        v = self.value_var.get()
        self.value_var.set("")

        if v is None:
            self.result = None
            self.destroy()
            return

        v = v.strip()
        if not v:
            show_neoui_error(self, "Error", "Name cannot be empty!\n\nPlease enter a name.")
            return

        self.result = v
        self.destroy()

    def _cancel(self):
        try:
            self.result = None
            self.value_var.set("")
            self.destroy()
        except tk.TclError:
            pass


def show_neoui_info(parent, title, message):
    d = neouiDialog(parent, title, message, "info")
    d.wait_window()
    return d.result


def show_neoui_warning(parent, title, message):
    d = neouiDialog(parent, title, message, "warning")
    d.wait_window()
    return d.result


def show_neoui_error(parent, title, message):
    d = neouiDialog(parent, title, message, "error")
    d.wait_window()
    return d.result


def show_neoui_question(parent, title, message):
    d = neouiDialog(parent, title, message, "question")
    d.wait_window()
    return d.result


class KeyManagerDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.withdraw()
        self.attributes('-alpha', 0.0)

        self.parent = parent

        theme_name = getattr(parent, 'current_theme', 'Ocean Deep')
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        self.title("Key Manager")
        self.configure(bg=theme["secondary_bg"])
        self.resizable(False, False)
        self.transient(parent)

        self.after(40, lambda: set_dark_title_bar(self))

        main = tk.Frame(self, bg=theme["secondary_bg"], padx=20, pady=20)
        main.pack(expand=True, fill="both")

        tk.Label(
            main,
            text="Key Manager",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 24, "bold"),
            justify="left",
        ).pack(anchor="w")

        tk.Frame(main, height=2, bg=theme["accent"]).pack(fill="x", pady=(10, 15))

        tk.Label(
            main,
            text=(
                "Manage encryption keys for this FFE install.\n"
                "Each key can have a custom name. Names travel with the key through .ekp export/import."
            ),
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11),
            justify="left",
            wraplength=_ffe_px(560),
        ).pack(anchor="w", pady=(0, 12))

        list_frame = tk.Frame(main, bg=theme["secondary_bg"])
        list_frame.pack(fill="both", expand=True)

        self.listbox = tk.Listbox(
            list_frame,
            bg=theme["bg"],
            fg=theme["text"],
            selectbackground=theme["accent"],
            selectforeground=theme["text"],
            font=(DEFAULT_FONT, 10),
            bd=0,
            highlightthickness=1,
            highlightbackground=theme["accent"],
            activestyle='none',
            height=10,
        )
        self.listbox.pack(side="left", fill="both", expand=True)

        sb = Scrollbar(list_frame, orient="vertical", command=self.listbox.yview)
        sb.pack(side="right", fill="y")
        self.listbox.configure(yscrollcommand=sb.set)

        btns = tk.Frame(main, bg=theme["secondary_bg"])
        btns.pack(fill="x", pady=(12, 0))

        self.activate_btn = NeoUIHoverButton(
            btns,
            text="Set Active",
            command=self._set_active,
            bg=theme["success"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "success"),
            font=(DEFAULT_FONT, 11, "bold"),
        )
        self.activate_btn.pack(fill="x", pady=(0, 6))

        self.generate_btn = NeoUIHoverButton(
            btns,
            text="Generate",
            command=self._generate_new,
            bg=theme["success"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "accent"),
            font=(DEFAULT_FONT, 11, "bold"),
        )
        self.generate_btn.pack(fill="x", pady=(0, 6))

        self.import_btn = NeoUIHoverButton(
            btns,
            text="Import .ekp",
            command=self._import_ekp,
            bg=theme["warning"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "warning"),
            font=(DEFAULT_FONT, 11, "bold"),
        )
        self.import_btn.pack(fill="x", pady=(0, 6))

        self.export_btn = NeoUIHoverButton(
            btns,
            text="Export .ekp",
            command=self._export_ekp,
            bg=theme["warning"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "warning"),
            font=(DEFAULT_FONT, 11, "bold"),
        )
        self.export_btn.pack(fill="x", pady=(0, 6))

        self.rename_btn = NeoUIHoverButton(
            btns,
            text="Rename",
            command=self._rename_selected,
            bg=theme["warning"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "accent"),
            font=(DEFAULT_FONT, 11, "bold"),
        )
        self.rename_btn.pack(fill="x", pady=(0, 6))

        self.delete_btn = NeoUIHoverButton(
            btns,
            text="Delete",
            command=self._delete_selected,
            bg=theme["error"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "error"),
            font=(DEFAULT_FONT, 11, "bold"),
        )
        self.delete_btn.pack(fill="x", pady=(0, 10))

        tk.Frame(btns, height=14, bg=theme["secondary_bg"]).pack(fill="x")

        NeoUIHoverButton(
            btns,
            text="✓",
            command=self.destroy,
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(theme_name, "accent"),
            font=(DEFAULT_FONT, 11, "bold"),
        ).pack(fill="x")

        self._items = []
        self.refresh()

        self.update_idletasks()
        req_w = self.winfo_reqwidth()
        req_h = self.winfo_reqheight()
        min_w = _ffe_px(560)
        min_h = _ffe_px(560)
        final_w = max(min_w, req_w)
        final_h = max(min_h, req_h)
        x = (self.winfo_screenwidth() // 2) - (final_w // 2)
        y = (self.winfo_screenheight() // 2) - (final_h // 2)
        self.geometry(f"{final_w}x{final_h}+{x}+{y}")

        self.deiconify()
        self.grab_set()
        self.focus_set()

    def refresh(self):
        theme_name = getattr(self.parent, 'current_theme', 'Ocean Deep')
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        self.listbox.delete(0, tk.END)
        self._items = []

        items = self.parent._km_list_key_inventory()
        active_key_id = self.parent._km_get_active_key_id()

        for idx, it in enumerate(items):
            tag = it.get('tag') or it.get('filename', '')
            is_active = (it.get('key_id') and it.get('key_id') == active_key_id
                         and it.get('registered') and it.get('valid'))
            prefix = "[ACTIVE]  " if is_active else ""
            label = f"{prefix}{tag}"
            self.listbox.insert(tk.END, label)

            if it.get('registered') and it.get('valid'):
                self.listbox.itemconfig(idx, fg=theme["success"])
            else:
                self.listbox.itemconfig(idx, fg=theme["error"])

            self._items.append(it)

    def _selected_item(self):
        try:
            i = self.listbox.curselection()[0]
        except Exception:
            return None
        if i < 0 or i >= len(self._items):
            return None
        return self._items[i]

    def _require_selection(self, registered_and_valid=False):
        """Return selected item or show an error. Optionally require it to be registered+valid."""
        it = self._selected_item()
        if not it:
            show_neoui_error(self, "No Key Selected",
                             "Please click a key in the list to select it first.")
            return None
        if registered_and_valid and (not it.get('registered') or not it.get('valid')):
            show_neoui_error(self, "Invalid Key",
                             "The selected key is not valid for this operation.\n\nOnly valid, registered keys can be used here.")
            return None
        return it

    def _generate_new(self):
        try:
            self.parent._km_setup_new_key()
            self.refresh()
        except Exception as e:
            show_neoui_error(self, "Key Error",
                             f"Failed to create new encryption key: {str(e)}\n\nPlease check file permissions and disk space, then try again.")

    def _import_ekp(self):
        try:
            self.parent._km_import_ekp_via_ui()
            self.refresh()
        except Exception as e:
            show_neoui_error(self, "Import Failed",
                             f"Failed to import key package: {str(e)}\n\nPlease ensure the file is a valid .ekp and the password is correct.")

    def _export_ekp(self):
        it = self._require_selection(registered_and_valid=True)
        if not it:
            return
        try:
            self.parent._km_export_ekp_via_ui(it)
        except Exception as e:
            show_neoui_error(self, "Export Failed",
                             f"Failed to export key package: {str(e)}\n\nPlease check write permissions and try again.")

    def _set_active(self):
        it = self._require_selection(registered_and_valid=True)
        if not it:
            return
        try:
            self.parent._km_set_active_key(it)
            self.refresh()
        except Exception as e:
            show_neoui_error(self, "Error",
                             f"Failed to set active key: {str(e)}\n\nPlease ensure the key is valid and try again.")

    def _rename_selected(self):
        it = self._require_selection()
        if not it:
            return
        key_id = it.get('key_id')
        current_tag = it.get('tag') or it.get('filename', '')
        dlg = TextInputDialog(
            self,
            "Rename Key",
            f"Enter a new name for this key:\n(current: {current_tag})",
            initialvalue=current_tag,
        )
        dlg.wait_window()
        new_tag = dlg.result
        if not new_tag or new_tag.strip() == current_tag.strip():
            return
        new_tag = new_tag.strip()
        try:
            self.parent._km_rename_key(key_id, new_tag)
            self.refresh()
        except Exception as e:
            show_neoui_error(self, "Rename Failed",
                             f"Failed to rename key: {str(e)}")

    def _delete_selected(self):
        it = self._require_selection()
        if not it:
            return
        tag = it.get('tag') or it.get('filename', '')
        try:
            ok = show_neoui_question(
                self,
                "Delete Key",
                f"Delete \"{tag}\"?\n\nThis removes the key from this install and may delete the .key file from disk.",
            )
            if not ok:
                return
            self.parent._km_delete_key(it)
            self.refresh()
        except Exception as e:
            show_neoui_error(self, "Delete Failed",
                             f"Failed to delete key: {str(e)}\n\nPlease check file permissions and ensure the key is not in use.")

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        # Check if parent has current_theme, if not set a default
        if not hasattr(parent, 'current_theme'):
            # Try to set current_theme from settings if available
            if hasattr(parent, 'settings') and isinstance(parent.settings, dict):
                parent.current_theme = parent.settings.get("theme", "Ocean Deep")
            else:
                parent.current_theme = "Ocean Deep"

        super().__init__(parent)
        self.parent = parent
        self.title("Settings")

        # Hide window initially to prevent flash
        self.withdraw()
        self.attributes('-alpha', 0.0)  # Make transparent

        # Initialize theme variable with error handling
        try:
            self.theme_var = tk.StringVar(value=parent.current_theme)
            self.original_theme = parent.current_theme
            self.current_theme = parent.current_theme  # Track current theme for this window
        except Exception as e:
            print(f"Error initializing theme variables: {e}")
            # Fallback to default theme
            self.theme_var = tk.StringVar(value="Ocean Deep")
            self.original_theme = "Ocean Deep"
            self.current_theme = "Ocean Deep"
            parent.current_theme = "Ocean Deep"

        try:
            theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        except Exception as e:
            print(f"Error getting theme: {e}")
            theme = NeoUIThemes.THEMES["Ocean Deep"]

        # Configure window with error handling
        try:
            self.configure(bg=theme["secondary_bg"])
            self.resizable(False, False)
            self.transient(parent)
        except Exception as e:
            print(f"Error configuring settings window: {e}")
            # Continue with basic configuration
            try:
                self.configure(bg="#132b35")  # Fallback to Ocean Deep secondary_bg
                self.resizable(False, False)
            except Exception:
                pass

        # Cleanup handler
        try:
            self.protocol("WM_DELETE_WINDOW", self._on_close)
        except Exception as e:
            print(f"Error setting up window protocol: {e}")

        # Apply dark mode after window is fully initialized
        def init_dark_mode():
            self.update_idletasks()
            self.update()
            set_dark_title_bar(self)
            # Force refresh after a short delay
            self.after(200, lambda: set_dark_title_bar(self))

        self.after(100, init_dark_mode)

        try:
            main_frame = tk.Frame(self, bg=theme["secondary_bg"], padx=20, pady=20)
            main_frame.pack(expand=True, fill="both")
        except Exception as e:
            print(f"Error creating main frame: {e}")
            # Fallback frame creation
            try:
                main_frame = tk.Frame(self, bg="#132b35", padx=20, pady=20)
                main_frame.pack(expand=True, fill="both")
            except Exception:
                print("Critical error: Could not create main frame")
                raise

        try:
            title_label = tk.Label(
                main_frame,
                text="Settings",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 24, "bold"),
                justify="left",
            )
            title_label.pack(anchor="w")
        except Exception as e:
            print(f"Error creating title label: {e}")
            # Fallback title label
            try:
                title_label = tk.Label(
                    main_frame,
                    text="Settings",
                    bg="#132b35",
                    fg="white",
                    font=("Arial", 24, "bold"),
                    justify="left",
                )
                title_label.pack(anchor="w")
            except Exception:
                pass

        try:
            tk.Frame(main_frame, height=3, bg=theme["accent"]).pack(fill="x", pady=(10, 15))
        except Exception as e:
            print(f"Error creating separator: {e}")
            # Fallback separator
            try:
                tk.Frame(main_frame, height=3, bg="#2d6477").pack(fill="x", pady=(10, 15))
            except Exception:
                pass

        # Create notebook containers with error handling
        try:
            notebook_container = tk.Frame(main_frame, bg=theme["secondary_bg"])
            notebook_container.pack(fill="both", expand=True)

            notebook_frame = tk.Frame(notebook_container, bg=theme["secondary_bg"])
            notebook_frame.pack(fill="both", expand=True)
        except Exception as e:
            print(f"Error creating notebook containers: {e}")
            # Fallback containers
            try:
                notebook_container = tk.Frame(main_frame, bg="#132b35")
                notebook_container.pack(fill="both", expand=True)

                notebook_frame = tk.Frame(notebook_container, bg="#132b35")
                notebook_frame.pack(fill="both", expand=True)
            except Exception:
                print("Critical error: Could not create notebook containers")
                raise

        # Notebook with tabs (we will hide native tabs and use our custom selector)
        try:
            notebook = ttk.Notebook(notebook_frame)
            notebook.pack(expand=True, fill="both")
        except Exception as e:
            print(f"Error creating notebook: {e}")
            # Create a simple frame as fallback
            notebook = tk.Frame(notebook_frame, bg="#132b35")
            notebook.pack(expand=True, fill="both")

        # Apply base notebook style with error handling
        try:
            self._apply_notebook_style(self.parent.current_theme)
        except Exception as e:
            print(f"Error applying notebook style: {e}")
            # Continue without style
            pass

        self.notebook = notebook

        # Create frames per tab with error handling
        try:
            self.general_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
            self.themes_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
            self.view_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
            self.encryption_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
            self.stats_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
            self.update_frame = tk.Frame(notebook, bg=theme["secondary_bg"])
        except Exception as e:
            print(f"Error creating tab frames: {e}")
            # Fallback frame creation with default colors
            try:
                fallback_bg = "#132b35"
                self.general_frame = tk.Frame(notebook, bg=fallback_bg)
                self.themes_frame = tk.Frame(notebook, bg=fallback_bg)
                self.view_frame = tk.Frame(notebook, bg=fallback_bg)
                self.encryption_frame = tk.Frame(notebook, bg=fallback_bg)
                self.stats_frame = tk.Frame(notebook, bg=fallback_bg)
                self.update_frame = tk.Frame(notebook, bg=fallback_bg)
            except Exception:
                print("Critical error: Could not create tab frames")
                raise

        # Add tabs with error handling
        try:
            if hasattr(notebook, 'add'):
                notebook.add(self.general_frame, text='General')
                notebook.add(self.themes_frame, text='Themes')
                notebook.add(self.view_frame, text='View')
                notebook.add(self.encryption_frame, text='Encryption')
                notebook.add(self.stats_frame, text='Stats')
                notebook.add(self.update_frame, text='Update')
        except Exception as e:
            print(f"Error adding tabs to notebook: {e}")
            # Continue without tabs if notebook is a simple frame

        # Build custom selector bar with error handling
        try:
            self._build_selector_bar(notebook_container, theme)
        except Exception as e:
            print(f"Error building selector bar: {e}")
            # Continue without selector bar

        # Create separator with error handling
        try:
            separator = tk.Frame(notebook_container, height=1, bg=theme["accent"])
            separator.pack(fill="x", pady=(0, 10))
        except Exception as e:
            print(f"Error creating separator: {e}")
            # Fallback separator
            try:
                separator = tk.Frame(notebook_container, height=1, bg="#2d6477")
                separator.pack(fill="x", pady=(0, 10))
            except Exception:
                pass

        # Hide native tabs with error handling
        try:
            if hasattr(notebook, 'hide'):
                for tab_id in list(notebook.tabs()):
                    notebook.hide(tab_id)
        except Exception as e:
            print(f"Error hiding native tabs: {e}")
            # Continue if tabs can't be hidden

        # Populate all tabs with error handling
        try:
            self._populate_na_tab(self.general_frame, theme)
        except Exception as e:
            print(f"Error populating general tab: {e}")

        try:
            self._populate_themes_tab(self.themes_frame, theme)
        except Exception as e:
            print(f"Error populating themes tab: {e}")

        try:
            self._populate_view_tab(self.view_frame, theme)
        except Exception as e:
            print(f"Error populating view tab: {e}")

        try:
            self._populate_encryption_tab(self.encryption_frame, theme)
        except Exception as e:
            print(f"Error populating encryption tab: {e}")

        try:
            self._populate_stats_tab(self.stats_frame, theme)
        except Exception as e:
            print(f"Error populating stats tab: {e}")

        try:
            self._populate_update_tab(self.update_frame, theme)
        except Exception as e:
            print(f"Error populating update tab: {e}")

        # Show the General tab by default with error handling
        try:
            if hasattr(self.notebook, 'select'):
                self.notebook.select(self.general_frame)
        except Exception as e:
            print(f"Error selecting general tab: {e}")

        # Buttons container with error handling
        try:
            btn_frame = tk.Frame(main_frame, bg=theme["secondary_bg"])
            btn_frame.pack(fill="x", pady=(15, 5))
        except Exception as e:
            print(f"Error creating button frame: {e}")
            # Fallback button frame
            try:
                btn_frame = tk.Frame(main_frame, bg="#132b35")
                btn_frame.pack(fill="x", pady=(15, 5))
            except Exception:
                btn_frame = main_frame  # Use main_frame as fallback

        # Store original theme when dialog opens with error handling
        try:
            self.original_theme = self.parent.current_theme
        except Exception as e:
            print(f"Error storing original theme: {e}")
            self.original_theme = "Ocean Deep"

        # Full width checkmark button with error handling
        try:
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
        except Exception as e:
            print(f"Error creating apply button: {e}")
            # Fallback button
            try:
                apply_btn = tk.Button(
                    btn_frame,
                    text="✓ Close",
                    command=self.destroy,
                    bg="#2d6477",
                    fg="white",
                    font=("Arial", 11, "bold"),
                    relief="flat"
                )
                apply_btn.pack(fill="x", pady=5, expand=True)
            except Exception:
                pass

        # --- GEOMETRY FIX START ---
        try:
            self.update_idletasks()

            # Use requested width/height
            req_w = self.winfo_reqwidth()
            req_h = self.winfo_reqheight()

            # Themes tab is large, set reasonable minimums
            min_width = _ffe_px(750)
            min_height = _ffe_px(600)  # Reduced from 1030 to prevent off-screen clipping

            # Final calculation
            final_w = max(req_w, min_width)
            final_h = max(req_h, min_height)

            # Ensure it fits on screen
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()

            # Cap height to screen height - padding
            if final_h > screen_h - 100:
                final_h = screen_h - 100

            x = (screen_w // 2) - (final_w // 2)
            y = (screen_h // 2) - (final_h // 2)

            self.geometry(f"{final_w}x{final_h}+{x}+{y}")
            self.minsize(min_width, min_height)

            self.deiconify()
            self.grab_set()
            self.focus_set()
        except Exception as e:
            print(f"Error centering and showing window: {e}")
            # Fallback
            try:
                self.geometry("650x600")
                self.minsize(650, 600)
                self.deiconify()
            except Exception:
                pass
        # --- GEOMETRY FIX END ---

    def open_file_in_default_editor(self, filename):
        try:
            file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
            if os.path.exists(file_path):
                os.startfile(file_path)
            else:
                show_neoui_error(self, "Error", f"File not found:\n\n{file_path}")
        except Exception as e:
            show_neoui_error(self, "Error", f"Failed to open file:\n\n{str(e)}")

    def _populate_na_tab(self, frame, theme):
        if frame == self.encryption_frame:
            self._populate_encryption_tab(frame, theme)
            return

        inner = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=20)
        inner.pack(expand=True, fill="both")

        if frame == self.general_frame:
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

            prefs_title = tk.Label(
                inner,
                text="Preferences",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 12, "bold"),
                justify="left"
            )
            prefs_title.pack(anchor="w", pady=(10, 6))

            ui_settings = (getattr(self.parent, 'settings', {}) or {}).get("ui", {})
            del_settings = (getattr(self.parent, 'settings', {}) or {}).get("delete", {})

            self.show_hidden_var = tk.BooleanVar(value=bool(ui_settings.get("show_hidden_files", False)))
            self.remember_last_folder_var = tk.BooleanVar(value=bool(ui_settings.get("remember_last_folder", True)))
            self.delete_show_dialog_var = tk.BooleanVar(value=bool(del_settings.get("show_options_dialog", True)))
            self.delete_confirm_skip_var = tk.BooleanVar(
                value=bool(del_settings.get("confirm_when_skipping_dialog", True)))
            self.delete_default_method_var = tk.StringVar(value=str(del_settings.get("default_method", "normal")))

            def persist_general_settings(*_args):
                if not hasattr(self, 'parent') or not hasattr(self.parent, 'settings'):
                    return
                self.parent.settings.setdefault("ui", {})
                self.parent.settings.setdefault("delete", {})

                self.parent.settings["ui"]["show_hidden_files"] = bool(self.show_hidden_var.get())
                self.parent.settings["ui"]["remember_last_folder"] = bool(self.remember_last_folder_var.get())
                self.parent.settings["delete"]["show_options_dialog"] = bool(self.delete_show_dialog_var.get())
                self.parent.settings["delete"]["confirm_when_skipping_dialog"] = bool(
                    self.delete_confirm_skip_var.get())

                dm = (self.delete_default_method_var.get() or "normal").strip().lower()
                if dm not in ("normal", "secure"):
                    dm = "normal"
                self.parent.settings["delete"]["default_method"] = dm

                save_app_settings(self.parent.settings)

                try:
                    if hasattr(self.parent, 'refresh_view'):
                        self.parent.refresh_view()
                except Exception:
                    pass

            show_hidden_cb = tk.Checkbutton(
                inner,
                text="Show hidden files",
                variable=self.show_hidden_var,
                command=persist_general_settings,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["bg"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"],
                font=(DEFAULT_FONT, 10),
                anchor="w",
                justify="left"
            )
            show_hidden_cb.pack(fill="x", pady=(0, 4))

            remember_folder_cb = tk.Checkbutton(
                inner,
                text="Remember last folder on startup",
                variable=self.remember_last_folder_var,
                command=persist_general_settings,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["bg"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"],
                font=(DEFAULT_FONT, 10),
                anchor="w",
                justify="left"
            )
            remember_folder_cb.pack(fill="x", pady=(0, 10))

            delete_title = tk.Label(
                inner,
                text="Delete Behavior",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 12, "bold"),
                justify="left"
            )
            delete_title.pack(anchor="w", pady=(0, 6))

            delete_dialog_cb = tk.Checkbutton(
                inner,
                text="Show delete options dialog (Secure / Delete)",
                variable=self.delete_show_dialog_var,
                command=persist_general_settings,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["bg"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"],
                font=(DEFAULT_FONT, 10),
                anchor="w",
                justify="left"
            )
            delete_dialog_cb.pack(fill="x", pady=(0, 4))

            delete_confirm_cb = tk.Checkbutton(
                inner,
                text="Confirm before delete when skipping dialog",
                variable=self.delete_confirm_skip_var,
                command=persist_general_settings,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["bg"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"],
                font=(DEFAULT_FONT, 10),
                anchor="w",
                justify="left"
            )
            delete_confirm_cb.pack(fill="x", pady=(0, 6))

            delete_method_row = tk.Frame(inner, bg=theme["secondary_bg"])
            delete_method_row.pack(fill="x", pady=(0, 10))

            tk.Label(
                delete_method_row,
                text="Default method when skipping dialog:",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 10, "bold"),
                justify="left"
            ).pack(side="left")

            rb_normal = tk.Radiobutton(
                delete_method_row,
                text="Delete",
                variable=self.delete_default_method_var,
                value="normal",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["accent"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"],
                font=(DEFAULT_FONT, 10),
                command=persist_general_settings
            )
            rb_normal.pack(side="left", padx=(10, 10))

            rb_secure = tk.Radiobutton(
                delete_method_row,
                text="Secure",
                variable=self.delete_default_method_var,
                value="secure",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["accent"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"],
                font=(DEFAULT_FONT, 10),
                command=persist_general_settings
            )
            rb_secure.pack(side="left")

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
                text="\nOpen Configuration File: Opens the configuration file in the default text editor\nClear Data: Resets all settings to default\nForce Quit: Forcefully quits the application",
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

    def _populate_view_tab(self, frame, theme):
        """Populate the View tab with view mode options."""
        container = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=10)
        container.pack(expand=True, fill="both")

        tk.Label(
            container,
            text="View Mode",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
        ).pack(anchor="w", pady=(0, 15))

        tk.Label(
            container,
            text="Choose how you want to interact with files:",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 11),
        ).pack(anchor="w", pady=(0, 15))

        # Get current view mode from settings
        current_mode = self.parent.settings.get("view_mode", "file_explorer")
        self.view_mode_var = tk.StringVar(value=current_mode)

        # View mode options
        view_modes = [
            ("file_explorer", "File Explorer Only", "Classic file browser view with toolbar"),
            ("mostly_file_explorer", "Mostly File Explorer", "File browser with drag & drop zone available"),
            ("mostly_drag_drop", "Mostly Drag and Drop", "Drag & drop zone with file browser as option"),
            ("drag_drop_only", "Drag and Drop Only", "Simplified view with just drag & drop zone")
        ]

        for mode_value, mode_name, mode_desc in view_modes:
            mode_frame = tk.Frame(container, bg=theme["secondary_bg"])
            mode_frame.pack(fill="x", pady=5)

            # Radio button
            rb = tk.Radiobutton(
                mode_frame,
                text=mode_name,
                variable=self.view_mode_var,
                value=mode_value,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["accent"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"],
                font=(DEFAULT_FONT, 11, "bold" if mode_value == current_mode else "normal"),
                command=lambda m=mode_value: self._on_view_mode_change(m)
            )
            rb.pack(anchor="w")

            # Description
            desc_label = tk.Label(
                mode_frame,
                text=f"  • {mode_desc}",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 9),
                justify="left"
            )
            desc_label.pack(anchor="w", padx=20)

            # Add separator between options
            if mode_value != "drag_drop_only":
                separator = tk.Frame(container, height=1, bg=theme["bg"])
                separator.pack(fill="x", pady=8)

        # Info text
        tk.Label(
            container,
            text="Drag and drop files onto the zone to encrypt or decrypt them.\n.enc files will be automatically detected for decryption.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
            justify="left"
        ).pack(anchor="w", pady=(15, 5))

    def _on_view_mode_change(self, mode):
        """Handle view mode change."""
        # Update settings
        self.parent.settings["view_mode"] = mode
        save_app_settings(self.parent.settings)

        # Apply the view mode to the main window
        if hasattr(self.parent, 'apply_view_mode'):
            self.parent.apply_view_mode()

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
            ("fast", "Fast", "200,000 iterations", "Less secure, but faster"),
            ("balanced", "Balanced", "600,000 iterations", "Good balance (recommended)"),
            ("secure", "Secure", "1,000,000 iterations", "More secure, but slower")
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

            # Add a small preview of the theme colors
            theme_colors = NeoUIThemes.THEMES.get(name, {})
            preview_bar = tk.Frame(row, height=15, bg=theme_colors.get("accent", "#000000"), bd=1, relief="solid")
            preview_bar.pack(side="left", padx=(5, 0), fill="x", expand=True)

            # Store theme preview frames for later updates
            if not hasattr(self, 'theme_preview_frames'):
                self.theme_preview_frames = {}
            self.theme_preview_frames[name] = preview_bar

        hint = tk.Label(
            container,
            text="Select a theme to instantly preview it in this window.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
        )
        hint.pack(anchor="w", pady=(8, 10))

        # Preview frame with better styling (like in setup assistant)
        preview_frame = tk.Frame(
            container,
            bg=theme["bg"],
            bd=1,
            relief="solid",
            padx=15,
            pady=15
        )
        preview_frame.pack(fill="x", pady=(10, 0))

        self.preview_label = tk.Label(
            preview_frame,
            text="Theme Preview",
            bg=theme["bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 12, "bold"),
            anchor="w"
        )
        self.preview_label.pack(fill="x", pady=(0, 10))

        # Add sample UI elements for preview
        sample_frame = tk.Frame(preview_frame, bg=theme["bg"])
        sample_frame.pack(fill="x")

        # Sample button
        sample_btn = NeoUIHoverButton(
            sample_frame,
            text="Sample Button",
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
            font=(DEFAULT_FONT, 10)
        )
        sample_btn.pack(side="left", padx=5, pady=5)

        # Sample text
        sample_text = tk.Label(
            sample_frame,
            text="This is sample text in the selected theme.",
            bg=theme["bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10)
        )
        sample_text.pack(side="left", padx=10)

        # Store preview widgets for theme updates
        self.preview_widgets = {
            'frame': preview_frame,
            'sample_btn': sample_btn,
            'sample_text': sample_text
        }

    def _on_theme_change(self):
        chosen = self.theme_var.get()
        if chosen in self.disabled_themes:
            self.theme_var.set(self.original_theme)  # Reset to original theme
            return

        # Store the chosen theme for preview
        self.preview_theme = chosen

        # Get the new theme first
        new_theme = NeoUIThemes.THEMES.get(chosen, NeoUIThemes.THEMES["Ocean Deep"])

        # Update the preview widgets
        if hasattr(self, 'preview_widgets'):
            try:
                # Update the preview frame and widgets
                self.preview_widgets['frame'].config(bg=new_theme["bg"])
                self.preview_widgets['sample_btn'].config(
                    bg=new_theme["accent"],
                    fg=NeoUIThemes.get_button_text_color(chosen, "accent")
                )
                self.preview_widgets['sample_text'].config(
                    bg=new_theme["bg"],
                    fg=new_theme["text"]
                )
                self.preview_label.config(
                    bg=new_theme["bg"],
                    fg=new_theme["text"]
                )
            except (tk.TclError, AttributeError):
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

        # Instantly apply the theme to this settings window
        self._update_settings_window_theme(chosen)

        # Also update the main application window theme
        if hasattr(self.parent, 'current_theme'):
            self.parent.current_theme = chosen
            if hasattr(self.parent, 'settings'):
                self.parent.settings['theme'] = chosen
                save_app_settings(self.parent.settings)
            if hasattr(self.parent, 'apply_theme'):
                self.parent.apply_theme()

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

    def _on_close(self):
        """Handle window close event."""
        self.destroy()

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
        # Keep track of previous theme so we can map existing widget colors cleanly.
        old_theme_name = getattr(self, 'current_theme', getattr(self.parent, 'current_theme', 'Ocean Deep'))
        old_theme = NeoUIThemes.THEMES.get(old_theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        self.current_theme = theme_name
        theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        # Update window background
        self.configure(bg=theme["secondary_bg"])

        # Update notebook style
        self._apply_notebook_style(theme_name)

        # Update all widgets recursively
        self._update_all_widgets_theme(self, theme, old_theme)

        # Update selector bar
        self._style_selector(theme)

        # Ensure selected tab highlight/indicator updates immediately
        self._update_selector_active()

        # Force update the window
        self.update_idletasks()
        try:
            self.update()
        except Exception:
            pass

        # Explicitly update the tab buttons to ensure they use the new theme
        if hasattr(self, 'tab_buttons') and self.tab_buttons:
            for name, obj in self.tab_buttons.items():
                btn = obj["button"]
                if isinstance(btn, NeoUIHoverButton):
                    btn.update_theme(
                        bg=theme["secondary_bg"],
                        fg=theme["text"],
                        active_bg=theme["accent"],
                        active_fg=theme["text"]
                    )

    def _map_theme_color(self, value, old_theme, new_theme):
        """Map a color from old_theme -> new_theme when it matches a known theme token."""
        if not isinstance(value, str) or not old_theme or not new_theme:
            return value
        v = value.lower()
        for key in ["bg", "secondary_bg", "accent", "success", "error", "warning", "text", "button_text"]:
            if key in old_theme and isinstance(old_theme.get(key), str) and v == old_theme[key].lower():
                return new_theme.get(key, value)
        return value

    def _update_all_widgets_theme(self, widget, theme, old_theme=None):
        """Recursively update all widgets and their children with the new theme."""
        try:
            # Update this widget
            self._update_single_widget_theme(widget, theme, old_theme)

            # Update all children
            for child in widget.winfo_children():
                self._update_all_widgets_theme(child, theme, old_theme)
        except Exception:
            pass

    def _update_single_widget_theme(self, widget, theme, old_theme=None):
        """Update a single widget with the new theme colors."""
        try:
            widget_type = type(widget).__name__

            # Helper: map widget's existing colors (based on old theme) to the new theme.
            def mapc(val):
                return self._map_theme_color(val, old_theme, theme)

            # Handle NeoUIHoverButton - use update_theme method
            if isinstance(widget, NeoUIHoverButton):
                widget.update_theme(
                    bg=mapc(widget.cget('bg')),
                    fg=mapc(widget.cget('fg')),
                    active_bg=mapc(widget.cget('activebackground')),
                    active_fg=mapc(widget.cget('activeforeground')),
                )
                return

            # Handle regular tk.Button
            if isinstance(widget, tk.Button):
                widget.configure(
                    bg=mapc(widget.cget('bg')),
                    fg=mapc(widget.cget('fg')),
                    activebackground=mapc(widget.cget('activebackground')),
                    activeforeground=mapc(widget.cget('activeforeground'))
                )
                return

            # Handle tk.Label
            if isinstance(widget, tk.Label):
                widget.configure(
                    bg=mapc(widget.cget('bg')),
                    fg=mapc(widget.cget('fg'))
                )
                return

            # Handle tk.Frame / tk.LabelFrame
            if isinstance(widget, (tk.Frame, tk.LabelFrame)):
                if 'bg' in widget.keys():
                    widget.configure(bg=mapc(widget.cget('bg')))
                return

            # Handle tk.Radiobutton
            if isinstance(widget, tk.Radiobutton):
                widget.configure(
                    bg=mapc(widget.cget('bg')),
                    fg=mapc(widget.cget('fg')),
                    selectcolor=mapc(widget.cget('selectcolor')),
                    activebackground=mapc(widget.cget('activebackground')),
                    activeforeground=mapc(widget.cget('activeforeground'))
                )
                return

            # Handle tk.Checkbutton
            if isinstance(widget, tk.Checkbutton):
                widget.configure(
                    bg=mapc(widget.cget('bg')),
                    fg=mapc(widget.cget('fg')),
                    selectcolor=mapc(widget.cget('selectcolor')),
                    activebackground=mapc(widget.cget('activebackground')),
                    activeforeground=mapc(widget.cget('activeforeground'))
                )
                return

            # Handle tk.Entry
            if isinstance(widget, tk.Entry):
                widget.configure(
                    bg=mapc(widget.cget('bg')),
                    fg=mapc(widget.cget('fg')),
                    insertbackground=mapc(widget.cget('insertbackground')),
                    highlightbackground=mapc(widget.cget('highlightbackground')),
                    highlightcolor=mapc(widget.cget('highlightcolor'))
                )
                return

            # Handle ttk widgets
            if hasattr(widget, 'configure'):
                # Try common ttk style configurations
                try:
                    if 'TNotebook' in str(type(widget).__name__):
                        pass  # Already handled by _apply_notebook_style
                    elif 'TNotebook.Tab' in str(type(widget).__name__):
                        pass  # Already handled by _apply_notebook_style
                except Exception:
                    pass

        except Exception:
            pass

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
        nav = stats.get("navigate_count", 0)

        most_used_theme = "N/A"
        if isinstance(tusage, dict) and tusage:
            most_used_theme = max(tusage.items(), key=lambda kv: (kv[1], kv[0]))[0]

        # Calculate additional stats
        total_operations = fe + fd + fdel
        total_navigation = fwd + back + nav
        avg_refresh_per_session = ref / max(1, tch) if tch > 0 else 0

        # Create sections for better organization
        # File Operations Section
        tk.Label(
            container,
            text="File Operations",
            bg=theme["secondary_bg"],
            fg=theme["accent"],
            font=(DEFAULT_FONT, 14, "bold"),
        ).pack(anchor="w", pady=(15, 5))

        file_items = [
            ("Files Encrypted", fe),
            ("Files Decrypted", fd),
            ("Files Deleted", fdel),
            ("Total Operations", total_operations),
        ]

        for name, val in file_items:
            row = tk.Frame(container, bg=theme["secondary_bg"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{name}:", bg=theme["secondary_bg"], fg=theme["text"],
                     font=(DEFAULT_FONT, 11, "bold")).pack(side="left")
            tk.Label(row, text=str(val), bg=theme["secondary_bg"], fg=theme["text"], font=(DEFAULT_FONT, 11)).pack(
                side="left", padx=(6, 0))

        # Navigation Section
        tk.Label(
            container,
            text="Navigation",
            bg=theme["secondary_bg"],
            fg=theme["accent"],
            font=(DEFAULT_FONT, 14, "bold"),
        ).pack(anchor="w", pady=(15, 5))

        nav_items = [
            ("Times Went Forward", fwd),
            ("Times Went Back", back),
            ("Times Navigated", nav),
            ("Total Navigation", total_navigation),
        ]

        for name, val in nav_items:
            row = tk.Frame(container, bg=theme["secondary_bg"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{name}:", bg=theme["secondary_bg"], fg=theme["text"],
                     font=(DEFAULT_FONT, 11, "bold")).pack(side="left")
            tk.Label(row, text=str(val), bg=theme["secondary_bg"], fg=theme["text"], font=(DEFAULT_FONT, 11)).pack(
                side="left", padx=(6, 0))

        # Theme Section
        tk.Label(
            container,
            text="Theme Usage",
            bg=theme["secondary_bg"],
            fg=theme["accent"],
            font=(DEFAULT_FONT, 14, "bold"),
        ).pack(anchor="w", pady=(15, 5))

        theme_items = [
            ("Theme Changes", tch),
            ("Most Used Theme", most_used_theme),
            ("Times Refreshed", ref),
            ("Avg Refresh/Theme", f"{avg_refresh_per_session:.1f}"),
        ]

        for name, val in theme_items:
            row = tk.Frame(container, bg=theme["secondary_bg"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{name}:", bg=theme["secondary_bg"], fg=theme["text"],
                     font=(DEFAULT_FONT, 11, "bold")).pack(side="left")
            tk.Label(row, text=str(val), bg=theme["secondary_bg"], fg=theme["text"], font=(DEFAULT_FONT, 11)).pack(
                side="left", padx=(6, 0))

        # Theme Usage Breakdown
        if isinstance(tusage, dict) and tusage:
            tk.Label(
                container,
                text="Theme Breakdown:",
                bg=theme["secondary_bg"],
                fg=theme["text"],
                font=(DEFAULT_FONT, 12, "bold"),
            ).pack(anchor="w", pady=(10, 5))

            for theme_name, count in sorted(tusage.items(), key=lambda x: x[1], reverse=True):
                row = tk.Frame(container, bg=theme["secondary_bg"])
                row.pack(fill="x", pady=1, padx=(20, 0))
                tk.Label(row, text=f"• {theme_name}:", bg=theme["secondary_bg"], fg=theme["text"],
                         font=(DEFAULT_FONT, 10)).pack(side="left")
                tk.Label(row, text=f"{count} times", bg=theme["secondary_bg"], fg=theme["text"],
                         font=(DEFAULT_FONT, 10)).pack(
                    side="left", padx=(6, 0))

    def _populate_update_tab(self, frame, theme):
        container = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=10)
        container.pack(expand=True, fill="both")

        tk.Label(
            container,
            text="Updates",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 18, "bold"),
        ).pack(anchor="w", pady=(0, 6))

        tk.Label(
            container,
            text=(
                "Browse FFE releases on GitHub.\n"
                "\n"
                "Installed: Version 3.0.0 \"Amaryllis\"  |  Build: ffe_042926_300"
            ),
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10),
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        tk.Frame(container, height=2, bg=theme["accent"]).pack(fill="x", pady=(0, 10))

        # Initialize State Dictionary
        if not hasattr(self, "_update_tab_state"):
            self._update_tab_state = {}

        st = self._update_tab_state
        # Ensure filter is set immediately
        if "filter" not in st:
            st["filter"] = tk.StringVar(value="stable")

        st["releases_all"] = []
        st["releases_filtered"] = []
        st["selected_index"] = 0
        st["selected_release"] = None

        # Controls Row
        controls = tk.Frame(container, bg=theme["secondary_bg"])
        controls.pack(fill="x", pady=(0, 10))

        tk.Label(
            controls,
            text="Channel:",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10, "bold"),
        ).pack(side="left")

        st["stable_btn"] = NeoUIHoverButton(
            controls,
            text="Stable",
            command=lambda: self._update_tab_set_filter("stable"),
            bg=theme["bg"],  # Placeholder, set by _update_tab_set_filter below
            fg=theme["text"],
            font=(DEFAULT_FONT, 10, "bold"),
        )
        st["stable_btn"].pack(side="left", padx=(10, 6))

        st["beta_btn"] = NeoUIHoverButton(
            controls,
            text="Beta",
            command=lambda: self._update_tab_set_filter("beta"),
            bg=theme["bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10, "bold"),
        )
        st["beta_btn"].pack(side="left")

        st["refresh_btn"] = NeoUIHoverButton(
            controls,
            text="Refresh",
            command=self._update_tab_load_releases,
            bg=theme["bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10, "bold"),
        )
        st["refresh_btn"].pack(side="right")

        # Content Area
        content = tk.Frame(container, bg=theme["secondary_bg"])
        content.pack(fill="both", expand=True)

        # LEFT SIDE: List
        left = tk.Frame(content, bg=theme["secondary_bg"], width=220)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)

        # Nav Buttons
        nav = tk.Frame(left, bg=theme["secondary_bg"])
        nav.pack(fill="x", pady=(0, 6))

        st["prev_btn"] = NeoUIHoverButton(
            nav,
            text="◀",
            command=lambda: self._update_tab_cycle(-1),
            bg=theme["bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10, "bold"),
            padx=8,
        )
        st["prev_btn"].pack(side="left")

        st["next_btn"] = NeoUIHoverButton(
            nav,
            text="▶",
            command=lambda: self._update_tab_cycle(1),
            bg=theme["bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10, "bold"),
            padx=8,
        )
        st["next_btn"].pack(side="right")

        # Listbox with Themed Scrollbar
        list_frame = tk.Frame(left, bg=theme["secondary_bg"])
        list_frame.pack(fill="both", expand=True)

        st["versions_list"] = tk.Listbox(
            list_frame,
            bg=theme["bg"],
            fg=theme["text"],
            selectbackground=theme["accent"],
            selectforeground=theme["text"],
            font=(DEFAULT_FONT, 10),
            bd=0,
            highlightthickness=1,
            highlightbackground=theme["accent"],
            activestyle='none',
        )
        st["versions_list"].pack(side="left", fill="both", expand=True)
        st["versions_list"].bind("<<ListboxSelect>>", self._update_tab_on_listbox_select)

        # REPLACEMENT: NeoUIScrollbar
        st["versions_sb"] = NeoUIScrollbar(list_frame, parent_theme_name=self.current_theme, orient="vertical",
                                           command=st["versions_list"].yview)
        st["versions_sb"].pack(side="right", fill="y")
        st["versions_list"].configure(yscrollcommand=st["versions_sb"].set)

        # RIGHT SIDE: Details
        right = tk.Frame(content, bg=theme["secondary_bg"])
        right.pack(side="left", fill="both", expand=True)

        title_row = tk.Frame(right, bg=theme["secondary_bg"])
        title_row.pack(fill="x")

        st["version_label"] = tk.Label(
            title_row,
            text="Loading...",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 16, "bold"),
            justify="left",
        )
        st["version_label"].pack(side="left", anchor="w")

        st["badges_frame"] = tk.Frame(title_row, bg=theme["secondary_bg"])
        st["badges_frame"].pack(side="left", padx=(10, 0), anchor="w")

        notes_frame = tk.Frame(right, bg=theme["secondary_bg"])
        notes_frame.pack(fill="both", expand=True, pady=(10, 10))

        st["notes_text"] = tk.Text(
            notes_frame,
            wrap=tk.WORD,
            bg=theme["bg"],
            fg=theme["text"],
            insertbackground=theme["text"],
            font=(DEFAULT_FONT, 10),
            bd=0,
            highlightthickness=1,
            highlightbackground=theme["accent"],
        )
        st["notes_text"].pack(side="left", fill="both", expand=True)

        # REPLACEMENT: NeoUIScrollbar for Text widget
        st["notes_sb"] = NeoUIScrollbar(notes_frame, parent_theme_name=self.current_theme, orient="vertical",
                                        command=st["notes_text"].yview)
        st["notes_sb"].pack(side="right", fill="y")
        st["notes_text"].configure(yscrollcommand=st["notes_sb"].set)
        st["notes_text"].config(state="disabled")

        st["open_btn"] = NeoUIHoverButton(
            right,
            text="Download (Open on GitHub)",
            command=self._update_tab_open_selected_release,
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"),
            font=(DEFAULT_FONT, 11, "bold"),
        )
        st["open_btn"].pack(fill="x")

        # Initialize button colors immediately based on default filter ("stable")
        self._update_tab_set_filter("stable")

        # Load releases after delay
        self.after(200, self._update_tab_load_releases)

    def _update_tab_set_filter(self, mode: str):
        st = getattr(self, "_update_tab_state", None)
        if not st:
            return

        st["filter"].set(mode)
        theme = NeoUIThemes.THEMES.get(self.parent.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

        # Update button visual states
        is_stable = (mode == "stable")

        st["stable_btn"].update_theme(
            bg=theme["accent"] if is_stable else theme["bg"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent") if is_stable else theme["text"],
        )
        st["beta_btn"].update_theme(
            bg=theme["accent"] if not is_stable else theme["bg"],
            fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent") if not is_stable else theme[
                "text"],
        )

        # Apply logic
        self._update_tab_refresh_filtered()

    def _update_tab_release_is_beta(self, release: dict) -> bool:
        name = (release.get("name") or "")
        tag = (release.get("tag_name") or "")
        # Standardize check
        return "beta" in f"{name} {tag}".lower() or "alpha" in f"{name} {tag}".lower() or release.get("prerelease",
                                                                                                      False)

    def _update_tab_release_version_text(self, release: dict) -> str:
        name = (release.get("name") or "").strip()
        tag = (release.get("tag_name") or "").strip()
        if name:
            return name
        if tag:
            return tag
        return "(untitled release)"

    def _update_tab_load_releases(self):
        st = getattr(self, "_update_tab_state", None)
        if not st:
            return

        # Disable controls while loading
        for k in ["stable_btn", "beta_btn", "refresh_btn", "prev_btn", "next_btn", "open_btn"]:
            try:
                st[k].config(state="disabled")
            except:
                pass

        try:
            st["versions_list"].delete(0, tk.END)
            st["version_label"].config(text="Loading...")
            st["notes_text"].config(state="normal")
            st["notes_text"].delete("1.0", tk.END)
            st["notes_text"].insert("1.0", "Fetching releases from GitHub...")
            st["notes_text"].config(state="disabled")
        except:
            pass

        def fetch():
            try:
                url = "https://api.github.com/repos/AVXAdvanced/FFE/releases?per_page=100"
                resp = requests.get(
                    url,
                    timeout=12,
                    headers={"Accept": "application/vnd.github+json", "User-Agent": "FFE"}
                )
                resp.raise_for_status()
                releases = resp.json()
                if not isinstance(releases, list):
                    releases = []
                # Pass results back to main thread
                self.after(0, lambda: self._update_tab_apply_releases(releases))
            except Exception as e:
                print(f"Update Check Error: {e}")
                self.after(0, lambda: self._update_tab_apply_releases(None))

        threading.Thread(target=fetch, daemon=True).start()

    def _update_tab_apply_releases(self, releases):
        st = getattr(self, "_update_tab_state", None)
        if not st: return

        # Re-enable controls
        for k in ["stable_btn", "beta_btn", "refresh_btn", "prev_btn", "next_btn", "open_btn"]:
            try:
                st[k].config(state="normal")
            except:
                pass

        if releases is None:
            st["releases_all"] = []
            self._update_tab_refresh_filtered(error=True)
            return

        st["releases_all"] = releases
        # FORCE REFRESH: This fixes the empty list issue
        self._update_tab_refresh_filtered(error=False)

    def _update_tab_refresh_filtered(self, error: bool = False):
        st = getattr(self, "_update_tab_state", None)
        if not st: return

        # Check widget existence to prevent errors during close
        lb = st.get("versions_list")
        if not lb or not lb.winfo_exists():
            return

        if error:
            st["releases_filtered"] = []
            st["selected_release"] = None
            self._update_tab_render_empty("Could not load releases from GitHub.\nCheck your internet connection.")
            return

        releases = st.get("releases_all") or []
        mode = st["filter"].get()

        # Filtering Logic
        if mode == "beta":
            filtered = [r for r in releases if self._update_tab_release_is_beta(r)]
        else:
            filtered = [r for r in releases if not self._update_tab_release_is_beta(r)]

        st["releases_filtered"] = filtered
        st["selected_index"] = 0

        # Update Listbox
        lb.delete(0, tk.END)
        for r in filtered:
            lb.insert(tk.END, self._update_tab_release_version_text(r))

        # Handle Empty Result
        if not filtered:
            msg = "No releases found for this channel."
            if not releases:
                msg = "No releases found on GitHub."
            self._update_tab_render_empty(msg)
            return

        # Select first item automatically
        try:
            lb.selection_clear(0, tk.END)
            lb.selection_set(0)
            lb.activate(0)
            lb.see(0)
        except:
            pass

        st["selected_release"] = filtered[0]
        self._update_tab_render_selected()

    def _update_tab_render_empty(self, message: str):
        st = getattr(self, "_update_tab_state", None)
        if not st:
            return

        try:
            st["version_label"].config(text="Unavailable")
        except Exception:
            pass

        bf = st.get("badges_frame")
        if bf:
            for w in list(bf.winfo_children()):
                w.destroy()

        t = st.get("notes_text")
        if t:
            t.config(state="normal")
            t.delete("1.0", tk.END)
            t.insert(tk.END, message + "\n\nhttps://github.com/AVXAdvanced/FFE/releases")
            t.config(state="disabled")

    def _update_tab_set_badges(self, release: dict, is_latest: bool):
        st = getattr(self, "_update_tab_state", None)
        if not st:
            return

        theme = NeoUIThemes.THEMES.get(self.parent.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        bf = st.get("badges_frame")
        if not bf:
            return

        for w in list(bf.winfo_children()):
            w.destroy()

        def add_badge(text: str, bg: str, fg: str):
            tk.Label(
                bf,
                text=text,
                bg=bg,
                fg=fg,
                font=(DEFAULT_FONT, 9, "bold"),
                padx=8,
                pady=2,
            ).pack(side="left", padx=(0, 6))

        if is_latest:
            add_badge("Latest", theme["success"],
                      NeoUIThemes.get_button_text_color(self.parent.current_theme, "success"))
        else:
            add_badge("Out of date", theme["warning"],
                      NeoUIThemes.get_button_text_color(self.parent.current_theme, "warning"))

        if self._update_tab_release_is_beta(release):
            add_badge("Beta", theme["warning"], NeoUIThemes.get_button_text_color(self.parent.current_theme, "warning"))

    def _update_tab_render_selected(self):
        st = getattr(self, "_update_tab_state", None)
        if not st:
            return
        rels = st.get("releases_filtered") or []
        if not rels:
            self._update_tab_render_empty("No release selected.")
            return

        idx = max(0, min(int(st.get("selected_index", 0)), len(rels) - 1))
        st["selected_index"] = idx
        release = rels[idx]
        st["selected_release"] = release

        is_latest = (idx == 0)
        title = self._update_tab_release_version_text(release)
        try:
            st["version_label"].config(text=title)
        except Exception:
            pass

        self._update_tab_set_badges(release, is_latest=is_latest)

        body = release.get("body")
        if body is None or str(body).strip() == "":
            body = "(No description provided for this release.)"

        t = st.get("notes_text")
        if t:
            t.config(state="normal")
            t.delete("1.0", tk.END)
            t.insert(tk.END, str(body))
            t.config(state="disabled")

    def _update_tab_on_listbox_select(self, event=None):
        st = getattr(self, "_update_tab_state", None)
        if not st:
            return
        lb = st.get("versions_list")
        if not lb:
            return
        try:
            sel = lb.curselection()
            if not sel:
                return
            st["selected_index"] = int(sel[0])
        except Exception:
            return
        self._update_tab_render_selected()

    def _update_tab_cycle(self, delta: int):
        st = getattr(self, "_update_tab_state", None)
        if not st:
            return
        rels = st.get("releases_filtered") or []
        if not rels:
            return

        idx = int(st.get("selected_index", 0)) + int(delta)
        idx = max(0, min(idx, len(rels) - 1))
        st["selected_index"] = idx

        lb = st.get("versions_list")
        if lb:
            try:
                lb.selection_clear(0, tk.END)
                lb.selection_set(idx)
                lb.activate(idx)
                lb.see(idx)
            except Exception:
                pass
        self._update_tab_render_selected()

    def _update_tab_open_selected_release(self):
        st = getattr(self, "_update_tab_state", None)
        if not st:
            return
        release = st.get("selected_release")
        url = None
        if isinstance(release, dict):
            url = release.get("html_url")
        if not url:
            url = "https://github.com/AVXAdvanced/FFE/releases"
        try:
            webbrowser.open_new(url)
        except Exception:
            pass

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
            ind.pack_forget()  # Hide all indicators
            if isinstance(btn, NeoUIHoverButton):
                btn.update_theme(
                    bg=bg,
                    fg=norm_fg,
                    active_bg=theme["accent"],
                    active_fg=norm_fg
                )
            else:
                btn.configure(bg=bg, fg=norm_fg, font=(DEFAULT_FONT, 11))

        # Then show the selected tab's indicator and update its style
        if hasattr(self, 'selected_tab_name'):
            selected_obj = self.tab_buttons.get(self.selected_tab_name)
            if selected_obj:
                btn = selected_obj["button"]
                ind = selected_obj["indicator"]
                if isinstance(btn, NeoUIHoverButton):
                    btn.update_theme(
                        bg=bg,
                        fg=sel_fg,
                        active_bg=theme["accent"],
                        active_fg=sel_fg
                    )
                else:
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
            ("View", self.view_frame),
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
                if isinstance(btn, NeoUIHoverButton):
                    btn.update_theme(
                        bg=theme["secondary_bg"],
                        fg=theme["text"],
                        active_bg=theme["accent"],
                        active_fg=theme["text"]
                    )
                else:
                    btn.configure(bg=theme["secondary_bg"], fg=theme["text"])
                ind.configure(bg=theme["accent"])

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

                show_neoui_info(self, "Success",
                                "All settings have been reset to default values.\n\nThe application will now use the original theme and configuration settings.")
            except Exception as e:
                show_neoui_error(self, "Error",
                                 f"Failed to reset settings: {str(e)}\n\nPlease check file permissions and try restarting the application.")

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
                    "A new encryption key has been generated successfully!\n\n"
                    "IMPORTANT: Please make sure to back up the new key file (main_key.key)\n"
                    "to a safe location. Without this key, you won't be able to decrypt\n"
                    "files encrypted with this new key."
                )
            except Exception as e:
                show_neoui_error(self, "Error",
                                 f"Failed to regenerate encryption key: {str(e)}\n\nPlease check disk space and file permissions, then try again.")

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
                    "All application data and settings have been cleared successfully.\n\n"
                    "The application will now restart to apply the changes.\n"
                    "Your files will not be affected, only the application configuration."
                )

                # Restart the application
                self.parent.restart_application()

            except Exception as e:
                show_neoui_error(
                    self,
                    "Error",
                    f"Failed to clear application data: {str(e)}\n\nPlease check file permissions and ensure the application is not running in read-only mode."
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
                    show_neoui_error(self.parent, "Error",
                                     f"Failed to rename file: {str(e)}\n\nPlease check if the file is in use or if you have permission to rename it.")

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
            show_neoui_error(self.parent, "Error",
                             "Could not retrieve file information.\n\nThe file may be inaccessible or corrupted. Please check if the file exists and try again.")
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
        dialog.withdraw()
        try:
            dialog.attributes('-alpha', 0.0)
        except Exception:
            pass
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

        try:
            dialog.after(40, lambda: set_dark_title_bar(dialog))
        except Exception:
            pass

        # Create main frame with consistent padding
        main_frame = tk.Frame(dialog, bg=theme["secondary_bg"], padx=25, pady=18)
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
        buttons_frame.pack(fill="x", pady=(12, 4))

        # Button style configuration - matching the app's standard button style
        btn_font = ("Segoe UI", 11)  # Slightly larger font like other buttons
        btn_pady = 8  # More padding for taller buttons
        btn_height = 1  # Standard height

        # Button frame with consistent padding
        action_buttons_frame = tk.Frame(buttons_frame, bg=theme["secondary_bg"])
        action_buttons_frame.pack(fill="x", pady=(0, 6))

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
        cancel_btn.pack(fill="x", pady=(4, 0))

        # Center the dialog
        dialog.update_idletasks()
        req_w = dialog.winfo_reqwidth()
        req_h = dialog.winfo_reqheight()
        w = max(450, req_w)
        h = max(240, req_h)
        x = (dialog.winfo_screenwidth() // 2) - (w // 2)
        y = (dialog.winfo_screenheight() // 2) - (h // 2)
        dialog.geometry(f"{w}x{h}+{x}+{y}")

        if _FADE_HOOK_INSTALLED:
            _ffe_apply_fade_behavior_to_window(dialog)

        dialog.deiconify()

        # Set focus to dialog and bind Escape key to cancel
        dialog.focus_set()
        dialog.bind('<Escape>', lambda e: dialog.destroy())

    def _perform_delete(self, file_path, secure=False, dialog=None):
        """Perform the actual file deletion with optional secure delete."""
        try:
            if not os.path.exists(file_path):
                show_neoui_error(self.parent, "Error",
                                 "File not found or already deleted.\n\nThe file may have been moved, renamed, or deleted by another process.")
                if dialog:
                    dialog.destroy()
                return

            if secure:
                try:
                    self._secure_delete_file(file_path)
                    file_path = None
                except Exception as e:
                    show_neoui_error(self.parent, "Error",
                                     f"Secure delete failed: {str(e)}\nFalling back to normal delete.\n\nThis may be due to insufficient permissions or disk space.")

            # Delete the file
            if file_path:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    os.rmdir(file_path)

            try:
                if hasattr(self.parent, 'inc_stat'):
                    self.parent.inc_stat("files_deleted", 1)
            except Exception:
                pass

            # Update UI
            self.parent.refresh_view()

            # Close the dialog if it's open
            if dialog:
                dialog.destroy()

        except Exception as e:
            show_neoui_error(self.parent, "Error",
                             f"Failed to delete file: {str(e)}\n\nPlease check if the file is in use or if you have sufficient permissions to delete it.")
            if dialog:
                dialog.destroy()

    def _secure_delete_file(self, file_path: str):
        if not os.path.isfile(file_path):
            raise ValueError("Secure delete only supports files.")

        dir_name = os.path.dirname(file_path)
        base_name = os.path.basename(file_path)
        try:
            rand_name = secrets.token_hex(16)
        except Exception:
            rand_name = os.urandom(16).hex()

        renamed_path = os.path.join(dir_name, f".{rand_name}.{base_name}.del")
        try:
            os.replace(file_path, renamed_path)
        except Exception:
            renamed_path = file_path

        try:
            file_size = os.path.getsize(renamed_path)
        except Exception:
            file_size = 0

        chunk = 1024 * 1024
        with open(renamed_path, 'r+b', buffering=0) as f:
            remaining = file_size
            f.seek(0)
            while remaining > 0:
                n = chunk if remaining > chunk else remaining
                f.write(os.urandom(n))
                remaining -= n
            try:
                f.flush()
            except Exception:
                pass
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
            try:
                f.truncate(0)
            except Exception:
                pass
            try:
                f.flush()
            except Exception:
                pass
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

        os.remove(renamed_path)

    def delete_file(self):
        file_path = self.get_selected_file()
        if file_path:
            settings = getattr(self.parent, 'settings', {}) or {}
            delete_settings = settings.get("delete", {}) or {}
            show_dialog = bool(delete_settings.get("show_options_dialog", True))

            if show_dialog:
                self.show_delete_dialog(file_path)
                return

            confirm = bool(delete_settings.get("confirm_when_skipping_dialog", True))
            if confirm:
                ok = show_neoui_question(
                    self.parent,
                    "Confirm Delete",
                    f"Delete '{os.path.basename(file_path)}'?",
                )
                if not ok:
                    return

            method = str(delete_settings.get("default_method", "normal")).strip().lower()
            secure = (method == "secure")
            self._perform_delete(file_path, secure=secure, dialog=None)


class WelcomeWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.withdraw()
        self.attributes('-alpha', 0.0)
        self.after(40, lambda: set_dark_title_bar(self))
        self.title("FFE Setup Assistant")
        self.parent = parent
        self.current_page = 0

        theme_name = getattr(parent, 'current_theme', 'Ocean Deep')
        self.theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])

        self.configure(bg=self.theme["bg"])
        self.minsize(850, 700)
        self.maxsize(850, 700)
        self.resizable(False, False)
        self.transient(parent)

        # Main Split Container
        self.container = tk.Frame(self, bg=self.theme["bg"])
        self.container.pack(fill="both", expand=True)

        # Left Sidebar for Steps
        self.sidebar = tk.Frame(self.container, bg=self.theme["secondary_bg"], width=240)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Branding in Sidebar
        self.sidebar_title = tk.Label(self.sidebar, text="FFE", bg=self.theme["secondary_bg"],
                                      fg=self.theme["accent"], font=(DEFAULT_FONT, 28, "bold"))
        self.sidebar_title.pack(anchor="w", padx=30, pady=(40, 10))

        self.sidebar_subtitle = tk.Label(self.sidebar, text="Setup Assistant", bg=self.theme["secondary_bg"],
                                         fg=self.theme["text"], font=(DEFAULT_FONT, 12))
        self.sidebar_subtitle.pack(anchor="w", padx=30, pady=(0, 40))

        self.step_labels = []
        steps = [
            ("1", "Welcome"),
            ("2", "Interface Theme"),
            ("3", "Security Profile"),
            ("4", "Master Key"),
            ("5", "Finish")
        ]

        for num, title in steps:
            frame = tk.Frame(self.sidebar, bg=self.theme["secondary_bg"])
            frame.pack(fill="x", pady=8, padx=20)

            indicator = tk.Label(frame, text=num, bg=self.theme["bg"], fg=self.theme["text"],
                                 font=(DEFAULT_FONT, 10, "bold"), width=3, height=1)
            indicator.pack(side="left", padx=(10, 15))

            lbl = tk.Label(frame, text=title, bg=self.theme["secondary_bg"], fg=self.theme["text"],
                           font=(DEFAULT_FONT, 11))
            lbl.pack(side="left")
            self.step_labels.append((indicator, lbl))

        # Right Content Area
        self.content_area = tk.Frame(self.container, bg=self.theme["bg"])
        self.content_area.pack(side="right", fill="both", expand=True)

        # 🚨 FIX: Pack the nav_frame FIRST to the bottom. This prevents the pages
        # from expanding and squishing the buttons out of bounds.
        self.nav_frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        self.nav_frame.pack(fill="x", side="bottom", padx=40, pady=30)

        # Now pack the pages container so it safely fills the remaining space
        self.pages_container = tk.Frame(self.content_area, bg=self.theme["bg"])
        self.pages_container.pack(fill="both", expand=True, padx=40, pady=40)

        self.pages = []
        self._create_welcome_page()
        self._create_theme_page()
        self._create_encryption_page()
        self._create_key_file_page()
        self._create_finish_page()

        # Bottom Navigation Buttons
        self.prev_btn = NeoUIHoverButton(
            self.nav_frame, text="Exit Setup", command=self.parent.destroy,
            bg=self.theme["secondary_bg"], fg=self.theme["text"], font=(DEFAULT_FONT, 11),
            width=12, padx=10, pady=6
        )
        self.prev_btn.pack(side="left")

        self.next_btn = NeoUIHoverButton(
            self.nav_frame, text="Continue →", command=self.next_page,
            bg=self.theme["accent"], fg=NeoUIThemes.get_button_text_color(theme_name, "accent"),
            font=(DEFAULT_FONT, 11, "bold"), width=14, padx=10, pady=6
        )
        self.next_btn.pack(side="right")

        self.show_page(0)

        # Center on screen
        self.update_idletasks()
        w, h = 980, 600
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

        self.deiconify()
        self.grab_set()
        self.focus_set()
        self.protocol("WM_DELETE_WINDOW", lambda: None)

    def _create_welcome_page(self):
        page = tk.Frame(self.pages_container, bg=self.theme["bg"])
        tk.Label(page, text="Welcome to FFE", bg=self.theme["bg"], fg=self.theme["text"],
                 font=(DEFAULT_FONT, 28, "bold")).pack(anchor="w", pady=(20, 5))
        tk.Label(page, text="Version 3.0.0 'Amaryllis'", bg=self.theme["bg"],
                 fg=self.theme["accent"], font=(DEFAULT_FONT, 12, "bold")).pack(anchor="w", pady=(0, 30))

        msg = (
            "Let's get FFE configured to your preferences.\n\n"
            "What's new in this version:\n\n"
            "✨ Redesigned neoUI Interface\n"
            "🎨 New Beautiful Themes\n"
            "🔒 Improved Encryption\n"
            "🖱️ New Layout Options\n\n"
            "Setup takes less than a minute. You can change these settings later."
        )
        tk.Label(page, text=msg, bg=self.theme["bg"], fg=self.theme["text"], font=(DEFAULT_FONT, 11),
                 justify="left", wraplength=560).pack(anchor="w")
        self.pages.append(page)

    def _create_theme_page(self):
        page = tk.Frame(self.pages_container, bg=self.theme["bg"])
        tk.Label(page, text="Choose Your Theme", bg=self.theme["bg"], fg=self.theme["text"],
                 font=(DEFAULT_FONT, 24, "bold")).pack(anchor="w", pady=(10, 5))
        tk.Label(page, text="Select a visual style. You can change this later in settings.",
                 bg=self.theme["bg"], fg=self.theme["text"], font=(DEFAULT_FONT, 11)).pack(anchor="w", pady=(0, 25))

        self.theme_var = tk.StringVar(value=getattr(self.parent, 'current_theme', 'Ocean Deep'))
        theme_names = list(NeoUIThemes.THEMES.keys())

        grid = tk.Frame(page, bg=self.theme["bg"])
        grid.pack(fill="both", expand=True)

        self.theme_preview_frames = {}
        for i, theme_name in enumerate(theme_names):
            row, col = divmod(i, 2)
            card = tk.Frame(grid, bg=self.theme["secondary_bg"], padx=10, pady=10)
            card.grid(row=row, column=col, sticky="nsew", padx=10, pady=10)

            btn = tk.Radiobutton(card, text=theme_name, variable=self.theme_var, value=theme_name,
                                 bg=self.theme["secondary_bg"], fg=self.theme["text"], selectcolor=self.theme["accent"],
                                 activebackground=self.theme["secondary_bg"], activeforeground=self.theme["text"],
                                 font=(DEFAULT_FONT, 11, "bold"), indicatoron=1, highlightthickness=0, bd=0,
                                 command=lambda t=theme_name: self._preview_theme(t))
            btn.pack(anchor="w", fill="x")

            p_bar = tk.Frame(card, height=6, bg=NeoUIThemes.THEMES[theme_name]["accent"])
            p_bar.pack(fill="x", pady=(8, 0))
            self.theme_preview_frames[theme_name] = p_bar

        self.pages.append(page)

    def _create_encryption_page(self):
        page = tk.Frame(self.pages_container, bg=self.theme["bg"])
        tk.Label(page, text="Security Profile", bg=self.theme["bg"], fg=self.theme["text"],
                 font=(DEFAULT_FONT, 24, "bold")).pack(anchor="w", pady=(10, 5))
        tk.Label(page, text="Configure your default file encryption behavior.",
                 bg=self.theme["bg"], fg=self.theme["text"], font=(DEFAULT_FONT, 11)).pack(anchor="w", pady=(0, 25))

        settings = load_app_settings()
        encryption_settings = settings.get('encryption', {})

        # Default Method
        tk.Label(page, text="Primary Encryption Method", bg=self.theme["bg"], fg=self.theme["accent"],
                 font=(DEFAULT_FONT, 12, "bold")).pack(anchor="w", pady=(0, 10))
        self.encryption_var = tk.StringVar(value=encryption_settings.get('default_method', 'password'))

        frame1 = tk.Frame(page, bg=self.theme["secondary_bg"], padx=15, pady=15)
        frame1.pack(fill="x", pady=(0, 25))

        tk.Radiobutton(frame1, text="Password (Standard for daily use)", variable=self.encryption_var, value="password",
                       bg=self.theme["secondary_bg"], fg=self.theme["text"], selectcolor=self.theme["accent"],
                       activebackground=self.theme["secondary_bg"], activeforeground=self.theme["text"],
                       font=(DEFAULT_FONT, 11), highlightthickness=0, bd=0).pack(anchor="w", pady=(0, 10))
        tk.Radiobutton(frame1, text="Key File (Advanced digital identity)", variable=self.encryption_var,
                       value="key_file",
                       bg=self.theme["secondary_bg"], fg=self.theme["text"], selectcolor=self.theme["accent"],
                       activebackground=self.theme["secondary_bg"], activeforeground=self.theme["text"],
                       font=(DEFAULT_FONT, 11), highlightthickness=0, bd=0).pack(anchor="w")

        # Security Level
        tk.Label(page, text="Password Iteration Level", bg=self.theme["bg"], fg=self.theme["accent"],
                 font=(DEFAULT_FONT, 12, "bold")).pack(anchor="w", pady=(0, 10))
        self.security_level_var = tk.StringVar(value=encryption_settings.get('security_level', 'balanced'))

        frame2 = tk.Frame(page, bg=self.theme["secondary_bg"], padx=15, pady=15)
        frame2.pack(fill="x")

        levels = [("fast", "Fast (200k iterations)"), ("balanced", "Balanced (600k iterations)"),
                  ("secure", "Secure (1M iterations)")]
        for val, txt in levels:
            tk.Radiobutton(frame2, text=txt, variable=self.security_level_var, value=val,
                           bg=self.theme["secondary_bg"], fg=self.theme["text"], selectcolor=self.theme["accent"],
                           activebackground=self.theme["secondary_bg"], activeforeground=self.theme["text"],
                           font=(DEFAULT_FONT, 11), highlightthickness=0, bd=0).pack(anchor="w", pady=4)

        self.pages.append(page)

    def _create_key_file_page(self):
        page = tk.Frame(self.pages_container, bg=self.theme["bg"])
        tk.Label(page, text="Master Key Generation", bg=self.theme["bg"], fg=self.theme["text"],
                 font=(DEFAULT_FONT, 24, "bold")).pack(anchor="w", pady=(10, 5))
        tk.Label(page, text="A Master Key acts as a physical token for your digital vault.",
                 bg=self.theme["bg"], fg=self.theme["text"], font=(DEFAULT_FONT, 11)).pack(anchor="w", pady=(0, 25))

        self.create_key_var = tk.BooleanVar(value=True)

        card = tk.Frame(page, bg=self.theme["secondary_bg"], padx=25, pady=25)
        card.pack(fill="x")

        tk.Radiobutton(card, text="Generate a new Master Key File now (Recommended)", variable=self.create_key_var,
                       value=True, bg=self.theme["secondary_bg"], fg=self.theme["text"],
                       selectcolor=self.theme["accent"],
                       activebackground=self.theme["secondary_bg"], activeforeground=self.theme["text"],
                       font=(DEFAULT_FONT, 12, "bold"), highlightthickness=0, bd=0).pack(anchor="w", pady=(0, 15))
        tk.Label(card, text="Creates a secure, machine-bound key automatically.", bg=self.theme["secondary_bg"],
                 fg=self.theme["text"], font=(DEFAULT_FONT, 10)).pack(anchor="w", padx=30, pady=(0, 20))

        tk.Radiobutton(card, text="Skip this step", variable=self.create_key_var, value=False,
                       bg=self.theme["secondary_bg"], fg=self.theme["text"], selectcolor=self.theme["accent"],
                       activebackground=self.theme["secondary_bg"], activeforeground=self.theme["text"],
                       font=(DEFAULT_FONT, 11), highlightthickness=0, bd=0).pack(anchor="w")

        self.pages.append(page)

    def _recursively_theme_widget(self, widget, theme, old_theme):
        try:
            if isinstance(widget, tk.Frame) and widget not in self.theme_preview_frames.values():
                if str(widget.cget("bg")) == old_theme["secondary_bg"]:
                    widget.configure(bg=theme["secondary_bg"])
                else:
                    widget.configure(bg=theme["bg"])
            elif isinstance(widget, tk.Label):
                widget.configure(bg=widget.master.cget("bg"), fg=theme["text"])
            elif isinstance(widget, tk.Radiobutton):
                widget.configure(bg=widget.master.cget("bg"), fg=theme["text"], selectcolor=theme["accent"],
                                 activebackground=widget.master.cget("bg"), activeforeground=theme["text"],
                                 highlightthickness=0, bd=0)

            for child in widget.winfo_children():
                self._recursively_theme_widget(child, theme, old_theme)
        except Exception:
            pass

    def _create_finish_page(self):
        page = tk.Frame(self.pages_container, bg=self.theme["bg"])
        tk.Label(page, text="Setup Complete", bg=self.theme["bg"], fg=self.theme["text"],
                 font=(DEFAULT_FONT, 28, "bold")).pack(anchor="w", pady=(20, 15))

        msg = "You're all done! Thanks for choosing FFE!"
        tk.Label(page, text=msg, bg=self.theme["bg"], fg=self.theme["text"], font=(DEFAULT_FONT, 12)).pack(anchor="w",
                                                                                                           pady=(0, 30))

        card = tk.Frame(page, bg=self.theme["secondary_bg"], padx=30, pady=30)
        card.pack(fill="x")

        features = [
            ("🔒", "Military-grade AES-GCM encryption is active"),
            ("🎨", "Your personalized workspace is ready"),
            ("⚡", "Hardware-accelerated processing configured")
        ]

        for item in features:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                icon, text = item
            else:
                icon, text = "", str(item)
            f = tk.Frame(card, bg=self.theme["secondary_bg"])
            f.pack(fill="x", pady=8)
            tk.Label(f, text=icon, bg=self.theme["secondary_bg"], fg=self.theme["text"], font=(DEFAULT_FONT, 16)).pack(
                side="left", padx=(0, 15))
            tk.Label(f, text=text, bg=self.theme["secondary_bg"], fg=self.theme["text"], font=(DEFAULT_FONT, 11)).pack(
                side="left")

        self.pages.append(page)

    def show_page(self, page_num):
        for page in self.pages:
            page.pack_forget()

        self.pages[page_num].pack(fill="both", expand=True)
        self.current_page = page_num

        # Update Sidebar Progress & text colors
        for i, (ind, lbl) in enumerate(self.step_labels):
            if i == page_num:
                ind.config(bg=self.theme["accent"],
                           fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"))
                lbl.config(fg=self.theme["text"], font=(DEFAULT_FONT, 11, "bold"))
            elif i < page_num:
                ind.config(bg=self.theme["success"],
                           fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "success"))
                lbl.config(fg=self.theme["text"], font=(DEFAULT_FONT, 11))
            else:
                ind.config(bg=self.theme["bg"], fg=self.theme["text"])
                lbl.config(fg="#888888", font=(DEFAULT_FONT, 11))

        if page_num == 0:
            self.prev_btn.config(text="Exit Setup", command=self.parent.destroy)
        else:
            self.prev_btn.config(text="← Back", command=self.prev_page)

        if page_num == len(self.pages) - 1:
            self.next_btn.config(text="Launch FFE", command=self._finish_setup)
            self.next_btn.update_theme(bg=self.theme["success"],
                                       fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "success"))
        else:
            self.next_btn.config(text="Continue →", command=self.next_page)
            self.next_btn.update_theme(bg=self.theme["accent"],
                                       fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"))

    def next_page(self):
        if self.current_page < len(self.pages) - 1:
            self.show_page(self.current_page + 1)

    def prev_page(self):
        if self.current_page > 0:
            self.show_page(self.current_page - 1)

    def _preview_theme(self, theme_name):
        new_theme = NeoUIThemes.THEMES.get(theme_name, NeoUIThemes.THEMES["Ocean Deep"])
        self.parent.current_theme = theme_name
        self.parent.settings["theme"] = theme_name
        save_app_settings(self.parent.settings)

        old_theme = self.theme  # Track the old theme so recursion knows what to flip
        self.theme = new_theme

        try:
            self.parent.after_idle(self.parent.apply_theme)
        except Exception:
            pass

        self.apply_theme_to_window(new_theme, old_theme)

    def apply_theme_to_window(self, theme, old_theme):
        self.configure(bg=theme["bg"])
        self.container.configure(bg=theme["bg"])
        self.sidebar.configure(bg=theme["secondary_bg"])
        self.content_area.configure(bg=theme["bg"])
        self.pages_container.configure(bg=theme["bg"])
        self.nav_frame.configure(bg=theme["bg"])

        # Title/Subtitle update fix
        self.sidebar_title.configure(bg=theme["secondary_bg"], fg=theme["accent"])
        self.sidebar_subtitle.configure(bg=theme["secondary_bg"], fg=theme["text"])

        if hasattr(self, 'prev_btn'):
            self.prev_btn.update_theme(bg=theme["secondary_bg"], fg=theme["text"], active_bg=theme["accent"],
                                       active_fg=theme["text"])

        for i, (ind, lbl) in enumerate(self.step_labels):
            lbl.master.configure(bg=theme["secondary_bg"])
            lbl.configure(bg=theme["secondary_bg"])
            if i == self.current_page:
                ind.configure(bg=theme["accent"],
                              fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "accent"))
                lbl.configure(fg=theme["text"])
            elif i < self.current_page:
                ind.configure(bg=theme["success"],
                              fg=NeoUIThemes.get_button_text_color(self.parent.current_theme, "success"))
                lbl.configure(fg=theme["text"])
            else:
                ind.configure(bg=theme["bg"], fg=theme["text"])
                lbl.configure(fg="#888888")

        for page in self.pages:
            self._recursively_theme_widget(page, theme, old_theme)

        if hasattr(self, 'theme_preview_frames'):
            for t_name, p_frame in self.theme_preview_frames.items():
                p_frame.config(bg=NeoUIThemes.THEMES.get(t_name, {}).get('accent', '#000000'))

    def _recursively_theme_widget(self, widget, theme, old_theme):
        try:
            if isinstance(widget, tk.Frame) and widget not in self.theme_preview_frames.values():
                if str(widget.cget("bg")) == old_theme["secondary_bg"]:
                    widget.configure(bg=theme["secondary_bg"])
                else:
                    widget.configure(bg=theme["bg"])
            elif isinstance(widget, tk.Label):
                widget.configure(bg=widget.master.cget("bg"), fg=theme["text"])
            elif isinstance(widget, tk.Radiobutton):
                widget.configure(bg=widget.master.cget("bg"), fg=theme["text"], selectcolor=theme["accent"],
                                 activebackground=widget.master.cget("bg"), activeforeground=theme["text"],
                                 highlightthickness=0, bd=0)

            for child in widget.winfo_children():
                self._recursively_theme_widget(child, theme, old_theme)
        except Exception:
            pass

    def _finish_setup(self):
        settings = getattr(self.parent, 'settings', None)
        if not isinstance(settings, dict):
            settings = load_app_settings()
        theme_name = self.theme_var.get()
        settings["theme"] = theme_name

        if "encryption" not in settings:
            settings["encryption"] = {}
        if hasattr(self, 'encryption_var'):
            settings["encryption"]["default_method"] = self.encryption_var.get()
        if hasattr(self, 'security_level_var'):
            settings["encryption"]["security_level"] = self.security_level_var.get()

        if hasattr(self, 'create_key_var') and self.create_key_var.get():
            try:
                self.parent._km_setup_new_key()
                self.parent.after(500, lambda: show_neoui_info(
                    self.parent, "Master Key Created",
                    "Your new Master Key has been generated and set as active!\n\n"
                    "Manage or back up this key anytime from the 'Keys' menu."
                ))
            except Exception as e:
                self.parent.after(500, lambda: show_neoui_error(
                    self.parent, "Key Generation Failed",
                    f"Could not automatically create your key file:\n{str(e)}"
                ))

        save_app_settings(settings)
        self.parent.settings = settings

        if hasattr(self.parent, 'apply_theme'):
            self.parent.current_theme = theme_name
            self.parent.apply_theme()
            self.parent.update_idletasks()

        self.destroy()


class FFEApp(FFEBaseTk):
    def __init__(self):
        super().__init__()
        self.title("Friend File Encryptor")
        self.geometry("1070x800")

        _ffe_configure_tk_scaling(self)

        enable_dark_title_bar_for_all_windows(self)
        self._ffe_disable_fade = True  # Disables fade-in for the main window only
        enable_fade_animations_for_all_windows(self)
        self.after(40, lambda: set_dark_title_bar(self))

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
        try:
            ui = (self.settings.get("ui", {}) or {})
            if ui.get("remember_last_folder", True):
                last = ui.get("last_folder")
                if isinstance(last, str) and last and os.path.isdir(last):
                    self.current_path = os.path.abspath(last)
        except Exception:
            pass
        self.history = [self.current_path]
        self.history_index = 0
        # File listbox is created in create_widgets() (so it can be parented correctly for view modes)
        self.file_listbox = None
        self.context_menu = None  # Will be initialized after theme is set

        self._last_folder_saved = None

        # Sort settings
        self.sort_method = 'name'  # 'name', 'size', or 'date'
        self.sort_ascending = True  # True for ascending, False for descending

        self.create_widgets()
        # Apply layout based on configured view mode (File Explorer / Drag & Drop)
        self.apply_view_mode()
        # Apply initial theme to the whole app (main window only; dialogs already themed)
        self.apply_theme()
        self.acc_files()
        self.decrypting = False
        self.hovered_index = None
        self.brighten_factor = 20

        self.ffe_websrv_chk("https://www.github.com/AVXAdvanced/FFE", self.no_ffe_web)

    def no_ffe_web(self):
        show_neoui_warning(
            self,
            "Online Features Unavailable",
            """FFE can't reach online services right now.

Updates and other online features may not work.

Try:

- Checking your internet connection
- Disabling VPN/proxy
- Trying again later (GitHub may be down)

Error Code: FxNG82933217

You can keep using FFE offline.""",
        )

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

    def _km_get_app_dir(self):
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        return os.path.dirname(os.path.abspath(__file__))

    def _km_get_app_instance_id(self) -> str:
        try:
            app_dir = os.path.normcase(os.path.abspath(self._km_get_app_dir()))
        except Exception:
            app_dir = str(self._km_get_app_dir())
        return hashlib.sha256(app_dir.encode('utf-8', errors='ignore')).hexdigest()

    def _km_get_user_data_dir(self):
        try:
            if os.name == 'nt':
                base = os.environ.get('APPDATA') or os.environ.get('LOCALAPPDATA')
                if base:
                    d = os.path.join(base, 'Lyne')
                    os.makedirs(d, exist_ok=True)
                    return d
        except Exception:
            pass
        d = os.path.join(os.path.expanduser('~'), '.lyne')
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
        return d

    def _km_installation_secret_path(self):
        km = self._km_ensure_settings()
        iid = km.get('installation_id')
        d = os.path.join(self._km_get_user_data_dir(), 'installations', str(iid))
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
        return os.path.join(d, 'installation_secret.dpapi.b64')

    def _km_legacy_shared_secret_path(self):
        return os.path.join(self._km_get_user_data_dir(), 'installation_secret.b64')

    def _km_machine_secret_path(self):
        return os.path.join(self._km_get_user_data_dir(), 'machine_secret.dpapi.b64')

    def _km_dpapi_protect(self, data: bytes) -> bytes:
        if os.name != 'nt':
            return data

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        in_blob = DATA_BLOB()
        in_blob.cbData = len(data)
        in_blob.pbData = ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_byte))

        out_blob = DATA_BLOB()
        if ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(in_blob),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(out_blob),
        ) == 0:
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)

    def _km_dpapi_unprotect(self, blob: bytes) -> bytes:
        if os.name != 'nt':
            return blob

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        in_blob = DATA_BLOB()
        in_blob.cbData = len(blob)
        in_blob.pbData = ctypes.cast(ctypes.create_string_buffer(blob, len(blob)), ctypes.POINTER(ctypes.c_byte))

        out_blob = DATA_BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(in_blob),
                None,
                None,
                None,
                None,
                0,
                ctypes.byref(out_blob),
        ) == 0:
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)

    def _km_try_load_secret_dpapi_b64(self, path: str):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                b64 = (f.read() or '').strip()
            if not b64:
                return None
            blob = base64.b64decode(b64)
            secret = self._km_dpapi_unprotect(blob)
            if isinstance(secret, (bytes, bytearray)) and len(secret) >= 16:
                return bytes(secret)
        except Exception:
            pass
        return None

    def _km_try_save_secret_dpapi_b64(self, path: str, secret_bytes: bytes) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except Exception:
            pass
        try:
            blob = self._km_dpapi_protect(secret_bytes)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(base64.b64encode(blob).decode('ascii'))
            return True
        except Exception:
            return False

    def _km_try_load_installation_secret_from_file(self):
        p = self._km_installation_secret_path()
        return self._km_try_load_secret_dpapi_b64(p)

    def _km_try_save_installation_secret_to_file(self, secret_bytes: bytes) -> bool:
        p = self._km_installation_secret_path()
        return self._km_try_save_secret_dpapi_b64(p, secret_bytes)

    def _km_get_machine_secret(self) -> bytes:
        p = self._km_machine_secret_path()
        existing = self._km_try_load_secret_dpapi_b64(p)
        if isinstance(existing, (bytes, bytearray)) and len(existing) >= 16:
            return bytes(existing)
        new_secret = secrets.token_bytes(32)
        self._km_try_save_secret_dpapi_b64(p, new_secret)
        return new_secret

    def _km_get_legacy_shared_secret(self):
        km = self._km_ensure_settings()

        try:
            legacy_b64 = km.get('installation_secret') or ''
            legacy = base64.b64decode(legacy_b64) if legacy_b64 else b''
            if legacy and len(legacy) >= 16:
                return legacy
        except Exception:
            pass

        p = self._km_legacy_shared_secret_path()
        try:
            with open(p, 'r', encoding='utf-8') as f:
                b64 = (f.read() or '').strip()
            if b64:
                legacy = base64.b64decode(b64)
                if legacy and len(legacy) >= 16:
                    return legacy
        except Exception:
            pass
        return None

    def _km_ensure_settings(self):
        if not hasattr(self, 'settings') or not isinstance(self.settings, dict):
            self.settings = load_app_settings()
        km = self.settings.setdefault('key_mgmt', {})
        if not isinstance(km, dict):
            km = {}
            self.settings['key_mgmt'] = km

        if not km.get('installation_id'):
            km['installation_id'] = str(uuid.uuid4())
        if 'installation_secret' not in km:
            km['installation_secret'] = None
        if not isinstance(km.get('registered_keys'), dict):
            km['registered_keys'] = {}
        if 'active_key_id' not in km:
            km['active_key_id'] = None
        save_app_settings(self.settings)
        return km

    def _km_get_installation_secret(self) -> bytes:
        km = self._km_ensure_settings()
        secret = self._km_try_load_installation_secret_from_file()
        if isinstance(secret, (bytes, bytearray)) and len(secret) >= 16:
            return bytes(secret)

        new_secret = secrets.token_bytes(32)
        self._km_try_save_installation_secret_to_file(new_secret)
        if km.get('installation_secret') is not None:
            km['installation_secret'] = None
            save_app_settings(self.settings)
        return new_secret

    def _km_get_active_key_id(self):
        km = self._km_ensure_settings()
        return km.get('active_key_id')

    def _km_key_store_dir(self):
        d = os.path.join(self._km_get_app_dir(), 'keys')
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
        return d

    def _km_compute_hmac(self, payload_bytes: bytes, mode: str) -> bytes:
        if mode == 'machine':
            secret = self._km_get_machine_secret()
        elif mode == 'install':
            secret = self._km_get_installation_secret()
        elif mode == 'legacy':
            secret = self._km_get_legacy_shared_secret()
            if not secret:
                return b''
        else:
            return b''
        return hmac.new(secret, payload_bytes, hashlib.sha256).digest()

    def _km_pack_key_file(self, key_id: str, fernet_key_b64: str, bind_mode: str = 'install') -> bytes:
        """Pack a key into the signed .key file format (v2, compact JSON).
        bind_mode='install'  -> HMAC keyed with installation secret.
        bind_mode='machine'  -> HMAC keyed with machine secret.
        """
        bind_mode = (bind_mode or 'install').lower().strip()
        km = self._km_ensure_settings()

        # Build bind block – only include fields relevant to this mode (keeps payload small).
        bind: dict = {'mode': bind_mode}
        if bind_mode == 'install':
            bind['installation_id'] = km.get('installation_id')
            bind['app_instance'] = self._km_get_app_instance_id()

        payload = {'key_id': key_id, 'fernet_key': fernet_key_b64, 'bind': bind}
        payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
        sig = self._km_compute_hmac(payload_bytes, bind_mode)
        # Compact JSON (no indent) – ~30 % smaller on disk
        doc = {'v': 2, 'payload': base64.b64encode(payload_bytes).decode('ascii'),
               'hmac': base64.b64encode(sig).decode('ascii')}
        return json.dumps(doc, separators=(',', ':')).encode('utf-8')

    def _km_try_parse_key_file(self, path: str):
        try:
            with open(path, 'rb') as f:
                raw = f.read()
        except Exception:
            return {'path': path, 'valid': False, 'registered': False, 'key_id': None, 'fernet_key': None,
                    'kind': 'unreadable'}

        try:
            txt = raw.decode('utf-8')
            doc = json.loads(txt)
            if isinstance(doc, dict) and doc.get('v') in (1, 2) and 'payload' in doc and 'hmac' in doc:
                payload_bytes = base64.b64decode(doc.get('payload') or '')
                sig = base64.b64decode(doc.get('hmac') or '')
                payload = json.loads(payload_bytes.decode('utf-8'))
                bind = payload.get('bind') if isinstance(payload, dict) else None
                bind_mode = None
                bind_installation_id = None
                bind_app_instance = None
                if isinstance(bind, dict):
                    bind_mode = (bind.get('mode') or '').lower().strip()
                    bind_installation_id = bind.get('installation_id')
                    bind_app_instance = bind.get('app_instance')

                if doc.get('v') == 2:
                    if bind_mode not in ('install', 'machine'):
                        return {'path': path, 'valid': False, 'registered': False, 'key_id': None, 'fernet_key': None,
                                'kind': 'signed'}
                    expected = self._km_compute_hmac(payload_bytes, bind_mode)
                    if not expected or not hmac.compare_digest(sig, expected):
                        return {'path': path, 'valid': False, 'registered': False, 'key_id': None, 'fernet_key': None,
                                'kind': 'signed'}
                    if bind_mode == 'install':
                        km = self._km_ensure_settings()
                        if str(bind_installation_id) != str(km.get('installation_id')):
                            return {'path': path, 'valid': False, 'registered': False, 'key_id': None,
                                    'fernet_key': None, 'kind': 'signed'}
                        if str(bind_app_instance) != str(self._km_get_app_instance_id()):
                            return {'path': path, 'valid': False, 'registered': False, 'key_id': None,
                                    'fernet_key': None, 'kind': 'signed'}
                    key_id = payload.get('key_id')
                    fernet_key = payload.get('fernet_key')
                    return {'path': path, 'valid': True, 'registered': False, 'key_id': key_id,
                            'fernet_key': fernet_key, 'kind': 'signed', 'bind_mode': bind_mode}

                if doc.get('v') == 1:
                    expected = self._km_compute_hmac(payload_bytes, 'legacy')
                    if not expected or not hmac.compare_digest(sig, expected):
                        return {'path': path, 'valid': False, 'registered': False, 'key_id': None, 'fernet_key': None,
                                'kind': 'signed_legacy'}
                    key_id = payload.get('key_id')
                    fernet_key = payload.get('fernet_key')
                    return {'path': path, 'valid': True, 'registered': False, 'key_id': key_id,
                            'fernet_key': fernet_key, 'kind': 'signed_legacy', 'bind_mode': 'legacy'}
        except Exception:
            pass

        try:
            key_bytes = raw.strip()
            Fernet(key_bytes)
            # Raw Fernet keys are treated as invalid by default (drop-in keys should not work).
            # They may still be manually registered, which converts them into a signed key.
            return {'path': path, 'valid': False, 'registered': False, 'key_id': None,
                    'fernet_key': key_bytes.decode('ascii', errors='ignore'), 'kind': 'legacy_raw'}
        except Exception:
            return {'path': path, 'valid': False, 'registered': False, 'key_id': None, 'fernet_key': None,
                    'kind': 'unknown'}

    def _km_list_key_inventory(self):
        km = self._km_ensure_settings()
        reg = km.get('registered_keys') or {}

        app_dir = self._km_get_app_dir()
        key_dir = self._km_key_store_dir()

        paths = []
        try:
            for name in os.listdir(app_dir):
                if name.lower().endswith('.key'):
                    paths.append(os.path.join(app_dir, name))
        except Exception:
            pass
        try:
            for name in os.listdir(key_dir):
                if name.lower().endswith('.key'):
                    p = os.path.join(key_dir, name)
                    if p not in paths:
                        paths.append(p)
        except Exception:
            pass

        items = []
        for p in paths:
            parsed = self._km_try_parse_key_file(p)
            fname = os.path.basename(p)
            parsed['filename'] = fname

            key_id = parsed.get('key_id')
            reg_entry = reg.get(key_id) if key_id and isinstance(reg, dict) else None
            if reg_entry is not None:
                parsed['registered'] = True
                # Attach the user tag stored in settings (falls back to filename stem)
                stored_tag = reg_entry.get('tag') if isinstance(reg_entry, dict) else None
                parsed['tag'] = stored_tag or os.path.splitext(fname)[0]
            else:
                parsed['registered'] = False
                parsed['tag'] = os.path.splitext(fname)[0]
            items.append(parsed)

        items.sort(key=lambda x: (0 if (x.get('registered') and x.get('valid')) else 1, (x.get('tag') or '').lower()))
        return items

    def _km_register_selected(self, item: dict):
        km = self._km_ensure_settings()
        reg = km.setdefault('registered_keys', {})
        kind = item.get('kind')
        path = item.get('path')

        if kind in ('signed', 'signed_legacy') and item.get('valid') and item.get('key_id'):
            key_id = item['key_id']
            if kind == 'signed_legacy':
                parsed = self._km_try_parse_key_file(path)
                if not (parsed.get('valid') and parsed.get('fernet_key')):
                    raise ValueError("Selected key file is invalid.")
                out_name = f"key_{key_id}.key"
                out_path = os.path.join(self._km_key_store_dir(), out_name)
                with open(out_path, 'wb') as f:
                    f.write(self._km_pack_key_file(key_id, parsed.get('fernet_key'), bind_mode='install'))
                reg[key_id] = {'path': out_path, 'tag': f"Key {key_id[:8]}"}
                km['active_key_id'] = key_id
                save_app_settings(self.settings)
                self._km_refresh_active_key()
                return

            # Preserve existing tag if already set, else generate default
            existing = reg.get(key_id)
            existing_tag = existing.get('tag', '') if isinstance(existing, dict) else ''
            reg[key_id] = {'path': path, 'tag': existing_tag or f"Key {key_id[:8]}"}
            save_app_settings(self.settings)
            return

        if kind == 'legacy_raw' and item.get('fernet_key'):
            key_id = str(uuid.uuid4())
            fernet_key_b64 = item.get('fernet_key')
            # Validate the raw key material before converting
            try:
                Fernet(fernet_key_b64.encode('ascii'))
            except Exception:
                raise ValueError("Selected key file is not a valid Fernet key.")
            out_name = f"key_{key_id}.key"
            out_path = os.path.join(self._km_key_store_dir(), out_name)
            with open(out_path, 'wb') as f:
                f.write(self._km_pack_key_file(key_id, fernet_key_b64, bind_mode='install'))
            reg[key_id] = {'path': out_path, 'tag': f"Key {key_id[:8]}"}
            km['active_key_id'] = key_id
            save_app_settings(self.settings)
            self._km_refresh_active_key()
            return

        raise ValueError("Selected key file cannot be registered.")

    def _km_set_active_key(self, item: dict):
        if not item.get('key_id'):
            raise ValueError("Selected key does not have a key id.")
        km = self._km_ensure_settings()
        if not (item.get('registered') and item.get('valid')):
            raise ValueError("Key must be registered and valid to be active.")
        km['active_key_id'] = item.get('key_id')
        save_app_settings(self.settings)
        self._km_refresh_active_key()

    def _km_delete_key(self, item: dict):
        km = self._km_ensure_settings()
        reg = km.get('registered_keys') or {}

        key_id = item.get('key_id')
        path = item.get('path')

        # Unregister if registered
        if key_id and isinstance(reg, dict) and key_id in reg:
            try:
                del reg[key_id]
            except Exception:
                pass

        # If deleting the active key, clear it
        if key_id and km.get('active_key_id') == key_id:
            km['active_key_id'] = None
            self.main_key = None

        save_app_settings(self.settings)

        # Delete the file from disk only if it lives in FFE-controlled folders
        if path and os.path.exists(path):
            try:
                app_dir = os.path.normcase(os.path.abspath(self._km_get_app_dir()))
                key_dir = os.path.normcase(os.path.abspath(self._km_key_store_dir()))
                abs_path = os.path.normcase(os.path.abspath(path))
                allowed_roots = (app_dir, key_dir)
                if abs_path.startswith(allowed_roots):
                    os.remove(abs_path)
            except Exception:
                # If deletion fails (permissions/in use), we still keep it unregistered.
                pass

        # Ensure active key state is consistent
        self._km_refresh_active_key()

    def _km_refresh_active_key(self):
        km = self._km_ensure_settings()
        active = km.get('active_key_id')
        reg = km.get('registered_keys') or {}
        if not active or active not in reg:
            self.main_key = None
            return
        path = (reg.get(active) or {}).get('path')
        if not path or not os.path.exists(path):
            self.main_key = None
            return
        parsed = self._km_try_parse_key_file(path)
        if not (parsed.get('valid') and parsed.get('key_id') == active):
            self.main_key = None
            return
        fernet_key_b64 = parsed.get('fernet_key')
        if not fernet_key_b64:
            self.main_key = None
            return
        try:
            key_bytes = fernet_key_b64.encode('ascii') if isinstance(fernet_key_b64, str) else fernet_key_b64
            Fernet(key_bytes)
            self.main_key = key_bytes
        except Exception:
            self.main_key = None

    def _km_setup_new_key(self, tag: str = ''):
        km = self._km_ensure_settings()
        reg = km.setdefault('registered_keys', {})

        key_id = str(uuid.uuid4())
        fernet_key_bytes = Fernet.generate_key()
        out_name = f"key_{key_id}.key"
        out_path = os.path.join(self._km_key_store_dir(), out_name)

        with open(out_path, 'wb') as f:
            f.write(self._km_pack_key_file(key_id, fernet_key_bytes.decode('ascii'), bind_mode='install'))

        default_tag = tag.strip() if tag and tag.strip() else f"Key {key_id[:8]}"
        reg[key_id] = {'path': out_path, 'tag': default_tag}
        km['active_key_id'] = key_id
        save_app_settings(self.settings)
        self._km_refresh_active_key()

    def _km_rename_key(self, key_id: str, new_tag: str):
        """Update the user-visible tag for a registered key (persists in settings)."""
        if not key_id or not new_tag:
            raise ValueError("key_id and new_tag are required.")
        km = self._km_ensure_settings()
        reg = km.get('registered_keys') or {}
        if key_id not in reg:
            raise ValueError("Key is not registered.")
        entry = reg[key_id]
        if not isinstance(entry, dict):
            reg[key_id] = {'tag': new_tag}
        else:
            entry['tag'] = new_tag
        save_app_settings(self.settings)

    def _km_export_ekp_via_ui(self, item: dict):
        theme_name = getattr(self, 'current_theme', 'Ocean Deep')

        password = self._ask_password(
            "Export Key Package",
            "Enter a password to lock this .ekp file.\n\nShare this password securely with the recipient.",
            confirm=True,
        )
        if not password:
            return

        # Use password immediately and clear it as soon as possible
        temp_password = password
        password = None  # Clear the reference immediately

        try:
            save_path = filedialog.asksaveasfilename(
                title="Export Key Package",
                defaultextension=".ekp",
                filetypes=[("Encrypted Key Package", "*.ekp")],
            )
            if not save_path:
                return

            key_id = item.get('key_id')
            km = self._km_ensure_settings()
            reg = km.get('registered_keys') or {}
            path = (reg.get(key_id) or {}).get('path')
            if not path or not os.path.exists(path):
                raise ValueError("Key file not found.")
            parsed = self._km_try_parse_key_file(path)
            if not (parsed.get('valid') and parsed.get('key_id') == key_id):
                raise ValueError("Key file is invalid.")

            # Include the tag so the recipient gets the same display name
            tag = (reg.get(key_id) or {}).get('tag') if isinstance(reg.get(key_id), dict) else None
            payload = {
                'key_id': key_id,
                'fernet_key': parsed.get('fernet_key'),
                'tag': tag or '',
            }
            payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')

            salt = generate_salt()
            security_level = (self.settings.get('encryption', {}) or {}).get('security_level', 'balanced')
            wrap_key = derive_key(temp_password, salt, security_level)
            nonce = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(wrap_key), modes.GCM(nonce))
            enc = cipher.encryptor()
            ciphertext = enc.update(payload_bytes) + enc.finalize()
            tag = enc.tag

            with open(save_path, 'wb') as f:
                f.write(b"EKP1" + salt + nonce + tag + ciphertext)

            show_neoui_info(self, "Export Complete",
                            f"Key package exported successfully!\n\nLocation:\n{save_path}\n\nPlease keep this file safe and secure - it contains your encryption key.")
        finally:
            # Ensure password is cleared even if export fails
            _secure_clear_memory(temp_password.encode('utf-8') if temp_password else b'')
            temp_password = None

    def _km_import_ekp_via_ui(self):
        import_path = filedialog.askopenfilename(
            title="Import Key Package",
            filetypes=[("Encrypted Key Package", "*.ekp")],
        )
        if not import_path:
            return

        password = self._ask_password(
            "Import Key Package",
            "Enter the password for this .ekp file.",
            confirm=False,
        )
        if not password:
            return

        # Use password immediately and clear it as soon as possible
        temp_password = password
        password = None  # Clear the reference immediately

        try:
            with open(import_path, 'rb') as f:
                raw = f.read()
            if not raw.startswith(b"EKP1"):
                raise ValueError("Not a valid .ekp file.")
            if len(raw) < 4 + 16 + 12 + 16 + 1:
                raise ValueError(".ekp file is corrupted.")

            salt = raw[4:20]
            nonce = raw[20:32]
            tag = raw[32:48]
            ciphertext = raw[48:]

            security_level = (self.settings.get('encryption', {}) or {}).get('security_level', 'balanced')
            wrap_key = derive_key(temp_password, salt, security_level)
            cipher = Cipher(algorithms.AES(wrap_key), modes.GCM(nonce, tag))
            dec = cipher.decryptor()
            try:
                payload_bytes = dec.update(ciphertext) + dec.finalize()
            except Exception:
                raise ValueError("Incorrect password or file is corrupted.")

            payload = json.loads(payload_bytes.decode('utf-8'))
            key_id = payload.get('key_id') or str(uuid.uuid4())
            fernet_key = payload.get('fernet_key')
            if not fernet_key:
                raise ValueError("Key package is missing key data.")

            key_bytes = fernet_key.encode('ascii') if isinstance(fernet_key, str) else fernet_key
            Fernet(key_bytes)

            km = self._km_ensure_settings()
            reg = km.setdefault('registered_keys', {})

            if key_id in reg:
                key_id = str(uuid.uuid4())

            out_name = f"key_{key_id}.key"
            out_path = os.path.join(self._km_key_store_dir(), out_name)
            with open(out_path, 'wb') as f:
                f.write(self._km_pack_key_file(key_id, key_bytes.decode('ascii'), bind_mode='install'))

            imported_tag = (payload.get('tag') or '').strip() or f"Imported {key_id[:8]}"
            reg[key_id] = {'path': out_path, 'tag': imported_tag}
            km['active_key_id'] = key_id
            save_app_settings(self.settings)
            self._km_refresh_active_key()
            show_neoui_info(self, "Import Complete",
                            "Key package imported and registered successfully!\n\nThe key is now available for use and can be selected from the key management panel.")
        finally:
            # Ensure password is cleared even if import fails
            _secure_clear_memory(temp_password.encode('utf-8') if temp_password else b'')
            temp_password = None

    def _km_rebind_key(self, item: dict, bind_mode: str):
        bind_mode = (bind_mode or '').lower().strip()
        if bind_mode not in ('install', 'machine'):
            raise ValueError("Invalid bind mode.")

        key_id = item.get('key_id')
        if not key_id:
            raise ValueError("Key does not have a key id.")

        km = self._km_ensure_settings()
        reg = km.get('registered_keys') or {}
        path = (reg.get(key_id) or {}).get('path')
        if not path or not os.path.exists(path):
            raise ValueError("Key file not found.")

        parsed = self._km_try_parse_key_file(path)
        if not (parsed.get('valid') and parsed.get('key_id') == key_id and parsed.get('fernet_key')):
            raise ValueError("Key file is invalid.")

        new_bytes = self._km_pack_key_file(key_id, parsed.get('fernet_key'), bind_mode=bind_mode)
        with open(path, 'wb') as f:
            f.write(new_bytes)

        self._km_refresh_active_key()

    def open_key_manager(self):
        dlg = KeyManagerDialog(self)
        self.wait_window(dlg)

    # noinspection PyTypeChecker
    def create_widgets(self):  # toolbar_ui_crt_def (act on stup)
        toolbar = tk.Frame(self, bg="#0a1124")
        # Align toolbar with file listbox
        toolbar.pack(fill=X, padx=12, pady=0)
        # Keep a reference for later theming
        self.toolbar = toolbar
        toolbar.columnconfigure(3, weight=1)

        self.back_button = HoverButton(toolbar, text=" Back ", command=self.go_back, state=tk.DISABLED,
                                       bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.back_button.pack(side=tk.LEFT, padx=4)

        self.up_button = HoverButton(toolbar, text=" Up ", command=self.go_up, bg="#203161",
                                     fg="white", relief="flat", font=("Segoe UI", 11))
        self.up_button.pack(side=tk.LEFT, padx=4)

        self.forward_button = HoverButton(toolbar, text=" Forward ", command=self.go_forward, state=tk.DISABLED,
                                          bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.forward_button.pack(side=tk.LEFT, padx=4)

        # Refresh button
        self.refresh_button = HoverButton(toolbar, text=" Refresh ", command=self.refresh_view, bg="#203161",
                                          fg="white",
                                          relief="flat", font=("Segoe UI", 11))
        self.refresh_button.pack(side=tk.LEFT, padx=4)

        # Folder dropdown button
        self.folder_button = HoverButton(toolbar, text=" Folder ▼ ", command=self.show_folder_menu,
                                         bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.folder_button.pack(side=tk.LEFT, padx=4)

        # Add sort button next to folder button
        self.sort_button = HoverButton(toolbar, text="Sort ▼", command=self.show_sort_menu,
                                       bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.sort_button.pack(side=tk.LEFT, padx=4)

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
        drive_frame.pack(side=tk.LEFT, padx=4, expand=True, fill=tk.X)

        # Drive dropdown button - now inside the expandable frame
        self.drive_button = HoverButton(drive_frame, text=" Drives ▼", command=self.show_drive_menu,
                                        bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.drive_button.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Create drive menu
        self.drive_menu = tk.Menu(self, tearoff=0)
        self.drive_menu.configure(bg="#2a1f3a", fg="white", font=("Segoe UI", 11),
                                  activebackground="#614885", activeforeground="white")

        # Main body area: File Explorer + optional Drag & Drop panel
        self.body_frame = tk.Frame(self, bg="#0a1124")
        self.body_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 0))
        self.body_frame.grid_rowconfigure(0, weight=1)
        self.body_frame.grid_columnconfigure(0, weight=1)
        self.body_frame.grid_columnconfigure(1, weight=0)

        # File Explorer container (listbox + directory bar)
        self.file_explorer_frame = tk.Frame(self.body_frame, bg="#0a1124")
        self.file_explorer_frame.grid(row=0, column=0, sticky="nsew")
        self.file_explorer_frame.grid_rowconfigure(0, weight=1)
        self.file_explorer_frame.grid_columnconfigure(0, weight=1)

        # File listbox (inside file explorer container)
        try:
            if self.file_listbox is not None and self.file_listbox.winfo_exists():
                self.file_listbox.destroy()
        except Exception:
            pass

        # Get current theme for border styling
        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

        # Create a frame to hold the listbox with a border
        listbox_container = tk.Frame(
            self.file_explorer_frame,
            bg=theme["secondary_bg"],
            bd=0,
            highlightthickness=1,
            highlightbackground=theme["accent"],
        )
        listbox_container.pack(pady=(0, 0), expand=True, fill=tk.BOTH)

        self.file_listbox = tk.Listbox(
            listbox_container,
            bg="#0f1936",
            fg="white",
            selectmode=tk.SINGLE,
            font=("Segoe UI", 12),
            selectbackground="#2a4180",
            selectforeground="white",
            bd=0,
            highlightthickness=0,
        )
        self.file_listbox.pack(expand=True, fill=tk.BOTH)

        # Store reference to container for theme updates
        self.file_listbox_container = listbox_container
        self.file_listbox.bind("<Double-1>", self.file_dc_act)

        # Directory bar at the bottom (root-level, spans under both panels)
        self.dir_frame = tk.Frame(self, bg="#0a1124")
        self.dir_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(0, 0))

        # Directory label
        self.dir_label = tk.Label(
            self.dir_frame,
            text="Command & Directory",
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
            font=("Segoe UI", 12),
            bd=0,
            highlightthickness=1,
            highlightbackground="#2a4180",
            highlightcolor="#2a4180"
        )
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), pady=5)
        self.dir_entry.bind("<Return>", self._check_address_bar_commands)

        # Go button with theme colors
        self.go_btn = HoverButton(
            self.dir_frame,
            text=" ❯ ",
            command=lambda: self.navigate_to_folder(self.dir_entry.get()),
            bg="#203161",
            fg="white",
            relief="flat",
            font=("Segoe UI", 8)
        )
        self.go_btn.pack(side=tk.LEFT, padx=(0, 12), pady=3)

        # Drag & Drop panel (optional, toggled by view mode)
        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        self.drag_drop_frame = tk.Frame(
            self.body_frame,
            bg=theme["secondary_bg"],
            bd=0,
            highlightthickness=1,
            highlightbackground=theme["accent"],
        )
        self.drag_drop_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self._build_drag_drop_zone(self.drag_drop_frame)

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

        decrypt_button = HoverButton(toolbar, text=" Decrypt ", command=self.decrypt_file, bg=theme["success"],
                                     fg="white",
                                     relief="flat", font=("Segoe UI", 11))
        decrypt_button.pack(side=tk.LEFT, padx=4, pady=8)

        self.chk_button = HoverButton(toolbar, text=" Check ", command=self.check_with_defender,
                                      bg=theme["success"],  # Decrypt Green
                                      fg="white",
                                      relief="flat", font=("Segoe UI", 11))
        self.chk_button.pack(side=tk.LEFT, padx=4, pady=8)

        delete_button = HoverButton(toolbar, text=" Delete ", command=self.del_f, bg="#bf3e3b", fg="white",
                                    relief="flat", font=("Segoe UI", 11))
        delete_button.pack(side=tk.LEFT, padx=4, pady=8)

        key_button = HoverButton(toolbar, text=" Key ", command=self.open_key_manager, bg="#203161", fg="white",
                                 relief="flat", font=("Segoe UI", 11))
        key_button.pack(side=tk.LEFT, padx=4, pady=8)

        settings_button = HoverButton(toolbar, text=" Settings ", command=self.open_settings, bg="#203161", fg="white",
                                      relief="flat", font=("Segoe UI", 11))
        settings_button.pack(side=tk.LEFT, padx=4, pady=8)

        about_button = HoverButton(toolbar, text=" About ", command=self.show_about, bg="#203161", fg="white",
                                   relief="flat", font=("Segoe UI", 11))
        about_button.pack(side=tk.LEFT, padx=4, pady=8)

    def _build_drag_drop_zone(self, parent_frame):
        """Create the Drag & Drop UI and hook up DnD if available."""
        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

        # Rebuild-safe: clear previous contents if this is called again
        try:
            for child in list(parent_frame.winfo_children()):
                child.destroy()
        except Exception:
            pass

        # Ensure the outer frame matches the current theme
        try:
            parent_frame.configure(
                bg=theme["secondary_bg"],
                highlightthickness=1,
                highlightbackground=theme["accent"],
                bd=0,
            )
        except Exception:
            pass

        # Container padding
        container = tk.Frame(parent_frame, bg=theme["secondary_bg"], padx=14, pady=14)
        container.pack(fill="both", expand=True)
        self.dnd_container = container

        self.dnd_title_label = tk.Label(
            container,
            text="Drag & Drop",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 16, "bold"),
            justify="left",
        )
        self.dnd_title_label.pack(anchor="w")

        hint = "Drop files here to Encrypt / Decrypt."
        if not DND2_AVAILABLE:
            hint += "\n(Drag & drop support requires `tkinterdnd2`; use Browse as a fallback.)"

        self.dnd_desc_label = tk.Label(
            container,
            text=hint,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10),
            justify="left",
            wraplength=_ffe_px(300),
        )
        self.dnd_desc_label.pack(anchor="w", pady=(8, 10))

        # Big drop target label
        self.dnd_target = tk.Label(
            container,
            text="Drop files here",
            bg=theme["bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 12, "bold"),
            bd=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground=theme["accent"],
            padx=10,
            pady=35,
        )
        self.dnd_target.pack(fill="x")

        # Browse button fallback
        self.dnd_browse_btn = NeoUIHoverButton(
            container,
            text="Browse for files…",
            command=self._browse_files_for_drag_drop,
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
            font=(DEFAULT_FONT, 11, "bold"),
            relief="flat",
        )
        self.dnd_browse_btn.pack(fill="x", pady=(10, 8))

        # Create a frame to hold the listbox with a border
        dnd_listbox_container = tk.Frame(
            container,
            bg=theme["secondary_bg"],
            bd=0,
            highlightthickness=1,
            highlightbackground=theme["accent"],
        )
        dnd_listbox_container.pack(fill="both", expand=True, pady=(8, 0))

        self.dnd_listbox = tk.Listbox(
            dnd_listbox_container,
            bg=theme["bg"],
            fg=theme["text"],
            selectbackground=theme["accent"],
            selectforeground=theme["text"],
            font=(DEFAULT_FONT, 9),
            height=8,
            bd=0,
            highlightthickness=0,
        )
        self.dnd_listbox.pack(fill="both", expand=True)

        # Store reference to container for theme updates
        self.dnd_listbox_container = dnd_listbox_container

        # Register drop target if available
        if DND2_AVAILABLE and DND_FILES is not None:
            try:
                self.dnd_target.drop_target_register(DND_FILES)
                self.dnd_target.dnd_bind('<<Drop>>', self._on_drop_event)
            except Exception as e:
                print(f"[DEBUG] Drag&Drop registration failed: {e}")
                print("Are you running FFE uncompiled? If so, check your packages.")

    def _browse_files_for_drag_drop(self):
        try:
            paths = filedialog.askopenfilenames(title="Select files to encrypt/decrypt")
            if not paths:
                return
            self._process_dropped_files(list(paths))
        except Exception as e:
            show_neoui_error(self, "Error",
                             f"Failed to open file picker: {str(e)}\n\nPlease check if the application has permission to access files and try again.")

    def _parse_dnd_files(self, data: str):
        """Parse tkinterdnd2 DND_FILES payload into a list of file paths."""
        if not data:
            return []
        try:
            # tkinterdnd2 uses Tcl list semantics; splitlist handles braces/escaping
            return [p for p in self.tk.splitlist(data) if p]
        except Exception:
            # Fallback: naive split
            return [p.strip() for p in data.split() if p.strip()]

    def _on_drop_event(self, event):
        try:
            paths = self._parse_dnd_files(getattr(event, 'data', ''))
            if not paths:
                return
            self._process_dropped_files(paths)
        except Exception as e:
            show_neoui_error(self, "Error", f"Failed to process dropped files: {str(e)}")

    def _process_dropped_files(self, paths):
        """Queue dropped files and process them sequentially."""
        if not paths:
            return

        # Normalize + filter duplicates
        normalized = []
        seen = set()
        for p in paths:
            try:
                p = os.path.normpath(str(p))
            except Exception:
                continue
            if p not in seen:
                seen.add(p)
                normalized.append(p)

        if not normalized:
            return

        # Log into the panel listbox
        if hasattr(self, 'dnd_listbox') and self.dnd_listbox:
            for p in normalized:
                self.dnd_listbox.insert(tk.END, p)

        self._dnd_queue = list(normalized)
        self.after(1, self._process_next_dropped_file)

    def _process_next_dropped_file(self):
        if not hasattr(self, '_dnd_queue') or not self._dnd_queue:
            return

        file_path = self._dnd_queue.pop(0)
        self._process_single_dropped_file(file_path, on_done=lambda: self.after(1, self._process_next_dropped_file))

    def _process_single_dropped_file(self, file_path: str, on_done=None):
        """Encrypt/decrypt a single dropped file, prompting for password if needed."""
        try:
            if not os.path.exists(file_path):
                show_neoui_warning(self, "File Not Found", f"This path does not exist:\n\n{file_path}")
                return
            if os.path.isdir(file_path):
                show_neoui_error(self, "Not Supported",
                                 "Directories are not supported.\n\nPlease drop individual files only, not folders. You can select multiple files at once.")
                return

            if file_path.lower().endswith('.enc'):
                self._run_task_with_progress(
                    title=f"Decrypting {os.path.basename(file_path)}…",
                    operation_callback=lambda update: self._decrypt_path(file_path, update),
                    on_complete=lambda: self.acc_files(),
                    error_title="Decryption Failed",
                )
            else:
                self._run_task_with_progress(
                    title=f"Encrypting {os.path.basename(file_path)}…",
                    operation_callback=lambda update: self._encrypt_path(file_path, update),
                    on_complete=lambda: self.acc_files(),
                    error_title="Encryption Failed",
                )
        finally:
            if callable(on_done):
                on_done()

    def _run_task_with_progress(self, title, operation_callback, on_complete=None, error_title="Operation Failed"):
        """Progress runner for drag/drop tasks (keeps error titles consistent)."""
        progress_dialog = ProgressDialog(self, title=title)

        def _update(value, status=None):
            return self._update_progress(progress_dialog, value, status)

        def finish(success, message):
            try:
                if progress_dialog and progress_dialog.winfo_exists():
                    progress_dialog.destroy()
            except Exception:
                pass

            if success:
                try:
                    if callable(on_complete):
                        on_complete()
                except Exception:
                    pass
                # Only show a message if it's meaningful and not cancelled
                if isinstance(message, str) and message and message.strip().lower() != "cancelled":
                    show_neoui_info(self, "Done", message)
            else:
                show_neoui_error(self, error_title, str(message) if message else "An unknown error occurred")

        def runner():
            try:
                success, message = operation_callback(_update)
                self.after(0, lambda: finish(success, message))
            except Exception as e:
                self.after(0, lambda: finish(False, str(e)))

        threading.Thread(target=runner, daemon=True).start()
        self.wait_window(progress_dialog)

    def _is_password_encrypted(self, file_path: str) -> bool:
        try:
            with open(file_path, 'rb') as f:
                return f.read(3) == b"PWD"
        except Exception:
            return False

    def _ask_password(self, title: str, prompt: str, confirm: bool = False):
        dlg = PasswordDialog(self, title, prompt, confirm=confirm)
        dlg.wait_window()
        return dlg.result

    def _encrypt_path(self, file_path: str, update_progress):
        """Encrypt an arbitrary path using the configured default method."""
        default_method = (self.settings.get("encryption", {}) or {}).get("default_method", "password")

        if default_method == "password":
            password = self._ask_password(
                "Encrypt with Password",
                "Enter a password to encrypt this file.\n\nMake sure to remember it.",
                confirm=True,
            )
            if not password:
                return True, "Cancelled"

            # Use password immediately and clear it as soon as possible
            temp_password = password
            password = None  # Clear the reference immediately

            security_level = (self.settings.get("encryption", {}) or {}).get("security_level", "balanced")

            try:
                result = encrypt_with_password(
                    file_path,
                    temp_password,
                    progress_callback=update_progress,
                    security_level=security_level,
                )
            finally:
                # Ensure password is cleared even if encryption fails
                _secure_clear_memory(temp_password.encode('utf-8') if temp_password else b'')
                temp_password = None

            success = isinstance(result, str) and "successfully encrypted" in result.lower()
            if success:
                self.inc_stat("files_encrypted", 1)
            return success, result

        # Key-file encryption
        if not getattr(self, 'main_key', None):
            return False, "No active registered key is loaded. Use the Key menu to set up a key."
        result = encrypt_with_keyfile(
            file_path,
            self.main_key,
            use_password=False,
            progress_callback=update_progress,
        )
        success = isinstance(result, str) and "successfully encrypted" in result.lower()
        if success:
            self.inc_stat("files_encrypted", 1)
        return success, result

    def _decrypt_path(self, file_path: str, update_progress):
        """Decrypt an arbitrary .enc file; if password-encrypted, prompt for password."""
        if not file_path.lower().endswith('.enc'):
            return False, "Only .enc files can be decrypted."

        if self._is_password_encrypted(file_path):
            password = self._ask_password(
                "Password Required",
                "This file is password protected.\n\nEnter the password to decrypt it.",
                confirm=False,
            )
            if not password:
                return True, "Cancelled"

            # Use password immediately and clear it as soon as possible
            temp_password = password
            password = None  # Clear the reference immediately

            try:
                result = decrypt_with_password(file_path, temp_password, progress_callback=update_progress)
            finally:
                # Ensure password is cleared even if decryption fails
                _secure_clear_memory(temp_password.encode('utf-8') if temp_password else b'')
                temp_password = None

            success = isinstance(result, str) and "successfully decrypted" in result.lower()
            if success:
                self.inc_stat("files_decrypted", 1)
            return success, result

        # Key-file encrypted
        result = decrypt_with_keyfile(file_path, self.main_key, progress_callback=update_progress)

        # This function returns None on success for key-file decryption
        if result is None:
            self.inc_stat("files_decrypted", 1)
            return True, f"File '{os.path.basename(file_path)}' successfully decrypted!"

        # Otherwise, it's an error message
        return False, result

    def apply_view_mode(self):
        """Apply the selected view mode by showing/hiding the File Explorer and Drag & Drop panels."""
        if not hasattr(self, 'body_frame') or not hasattr(self, 'file_explorer_frame') or not hasattr(self,
                                                                                                      'drag_drop_frame'):
            return

        mode = (getattr(self, 'settings', {}) or {}).get('view_mode', 'file_explorer')

        # Reset grid positions
        try:
            self.file_explorer_frame.grid_remove()
        except Exception:
            pass
        try:
            self.drag_drop_frame.grid_remove()
        except Exception:
            pass

        # Configure weights
        self.body_frame.grid_columnconfigure(0, weight=1)
        self.body_frame.grid_columnconfigure(1, weight=0)

        if mode == 'file_explorer':
            self.file_explorer_frame.grid(row=0, column=0, sticky='nsew')
            # DnD hidden
        elif mode == 'mostly_file_explorer':
            self.body_frame.grid_columnconfigure(0, weight=3)
            self.body_frame.grid_columnconfigure(1, weight=1)
            self.file_explorer_frame.grid(row=0, column=0, sticky='nsew')
            self.drag_drop_frame.grid(row=0, column=1, sticky='nsew', padx=(10, 0))
        elif mode == 'mostly_drag_drop':
            # Make Drag & Drop the primary (larger) panel
            self.body_frame.grid_columnconfigure(0, weight=3)
            self.body_frame.grid_columnconfigure(1, weight=1)
            # Put DnD on the left, explorer on the right
            self.drag_drop_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
            self.file_explorer_frame.grid(row=0, column=1, sticky='nsew')
        elif mode == 'drag_drop_only':
            self.body_frame.grid_columnconfigure(0, weight=1)
            self.body_frame.grid_columnconfigure(1, weight=0)
            self.drag_drop_frame.grid(row=0, column=0, sticky='nsew')
        else:
            # Fallback
            self.file_explorer_frame.grid(row=0, column=0, sticky='nsew')

        try:
            self.update_idletasks()
        except Exception:
            pass

    def acc_hdd(self):
        drives = [chr(drive) + ":\\" for drive in range(65, 91) if os.path.exists(chr(drive) + ":\\")]
        return drives

    # noinspection PyTypeChecker
    def acc_files(self):
        try:
            self.file_listbox.delete(0, tk.END)
            file_entries = []

            show_hidden = False
            try:
                show_hidden = bool((self.settings.get("ui", {}) or {}).get("show_hidden_files", False))
            except Exception:
                show_hidden = False

            for entry in os.listdir(self.current_path):
                full_path = os.path.join(self.current_path, entry)

                if not show_hidden:
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

            try:
                self._maybe_persist_last_folder()
            except Exception:
                pass
        except Exception as e:
            show_neoui_error(self, "Error", f"Failed to load files:\n\n{str(e)}")

    def _maybe_persist_last_folder(self):
        try:
            ui = (self.settings.get("ui", {}) or {})
            if not ui.get("remember_last_folder", True):
                return
            cp = getattr(self, 'current_path', None)
            if not isinstance(cp, str) or not cp:
                return
            if not os.path.isdir(cp):
                return

            last_saved = getattr(self, '_last_folder_saved', None)
            if last_saved == cp:
                return

            self.settings.setdefault("ui", {})
            self.settings["ui"]["last_folder"] = cp
            save_app_settings(self.settings)
            self._last_folder_saved = cp
        except Exception:
            pass

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
                try:
                    if hasattr(self, 'status_label') and self.status_label is not None and self.status_label.winfo_exists():
                        self.status_label.config(text=f"Opening file: {full_path}")
                except Exception:
                    pass
                try:
                    if os.name == 'nt':
                        os.startfile(full_path)
                    else:
                        webbrowser.open_new(full_path)
                except Exception as e:
                    show_neoui_error(self, "Error", f"Failed to open file:\n\n{str(e)}")
            elif os.path.isdir(full_path):
                self.current_path = full_path
                self.history.append(self.current_path)
                self.history_index += 1
                self.acc_files()
            else:
                show_neoui_error(self, "Error", f"Invalid selection:\n\n{self.file_listbox.get(selected_index)}")

        except IndexError:
            pass  # No selection, so nothing to do
        except Exception as e:
            show_neoui_error(self, "Error", f"Failed to open file:\n\n{str(e)}")

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

    # add command and directory commands here

    def _check_address_bar_commands(self, event=None):
        command = self.dir_entry.get().strip().lower()
        self.dir_entry.delete(0, tk.END)  # Clear the input field

        if command == "enc":
            self.encrypt_file()
        elif command == "encrypt":
            self.encrypt_file()
        elif command == "dec":
            self.decrypt_file()
        elif command == "decrypt":
            self.decrypt_file()
        elif command == "about":
            self.show_about()
        elif command in ["settg", "setting", "settings"]:
            self.open_settings()
        elif command == "back":
            self.go_back()
        elif command == "fwd" or command == "forward":
            self.go_forward()
        elif command == "forward" or command == "forward":
            self.go_forward()
        elif command == "up":
            self.go_up()
        elif command == "quit":
            self.quit()
        elif command == "exit":
            self.quit()
        elif command == "help" or command == "?":
            self._show_help_commands()
        elif command == "home" or command == "~":
            self.navigate_to_folder(os.path.expanduser("~"))
        elif command == "desktop":
            self.navigate_to_folder(os.path.join(os.path.expanduser("~"), "Desktop"))
        elif command == "documents":
            self.navigate_to_folder(os.path.join(os.path.expanduser("~"), "Documents"))
        elif command == "downloads":
            self.navigate_to_folder(os.path.join(os.path.expanduser("~"), "Downloads"))
        elif command == "root" or command == "/":
            if os.name == 'nt':  # Windows
                self.navigate_to_folder("C:\\")
            else:  # Unix-like
                self.navigate_to_folder("/")
        elif command == "refresh" or command == "reload":
            self.refresh_view()
        elif command == "clear" or command == "cls":
            self.dir_entry.delete(0, tk.END)
        elif command == "new" or command == "newfile":
            self._create_new_file()
        elif command == "newfolder" or command == "mkdir":
            self._create_new_folder()
        elif command == "stats" or command == "statistics":
            self._show_statistics()
        elif command == "keys" or command == "keymgmt":
            self.open_key_manager()
        elif command == "theme":
            self.open_settings()
            # Focus on themes tab
            self.after(100, lambda: self.notebook.select(self.themes_frame))
        else:
            # Check if it's a valid directory
            if os.path.isdir(command):
                self.navigate_to_folder(command)
            else:
                # Show error for unknown command or invalid directory
                show_neoui_error(self, "Error",
                                 "Unknown Command or Directory\n\nPlease enter a valid command or navigate to an existing directory path.")

    def navigate_to_folder(self, folder_path):
        """Navigate to the specified folder"""
        if os.path.isdir(folder_path):
            self.current_path = os.path.abspath(folder_path)
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, self.current_path)
            self.acc_files()
            self.inc_stat("navigate_count", 1)
            self.refresh_view()

    def _show_help_commands(self):
        """Show help dialog with available commands"""
        help_text = """
Available Commands:
────────────────────────────────────

File Operations:
  enc, encrypt    - Encrypt selected file
  dec, decrypt    - Decrypt selected file
  new, newfile    - Create new file
  newfolder, mkdir- Create new folder

Navigation:
  home, ~         - Go to home directory
  desktop         - Go to desktop
  documents       - Go to documents folder
  downloads       - Go to downloads folder
  root, /         - Go to root directory
  back            - Go back in history
  fwd, forward    - Go forward in history
  up              - Go to parent directory

Utilities:
  help, ?         - Show this help
  settings        - Open settings
  theme           - Open settings to themes tab
  keys, keymgmt   - Open key manager
  stats, statistics- Show usage statistics
  about           - Show about dialog
  refresh, reload - Refresh current view
  clear, cls      - Clear address bar
  quit, exit      - Exit application

You can also enter any directory path to navigate there directly.
        """

        dialog = tk.Toplevel(self)
        dialog.title("Command Help")
        dialog.geometry("600x700")
        dialog.resizable(False, False)

        self.after(40, lambda: set_dark_title_bar(dialog))

        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        dialog.configure(bg=theme["bg"])
        dialog.transient(self)
        dialog.grab_set()

        text_widget = tk.Text(
            dialog,
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=("Consolas", 10),
            wrap=tk.WORD,
            padx=15,
            pady=15
        )
        text_widget.pack(fill="both", expand=True, padx=10, pady=10)
        text_widget.insert("1.0", help_text)
        text_widget.config(state="disabled")

        close_btn = NeoUIHoverButton(
            dialog,
            text="Close",
            command=dialog.destroy,
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
            font=(DEFAULT_FONT, 10)
        )
        close_btn.pack(pady=10)

        dialog.bind("<Escape>", lambda e: dialog.destroy())

    def _create_new_file(self):
        """Create a new file in current directory"""
        try:
            filename = tk.simpledialog.askstring(
                "New File",
                "Enter filename:",
                parent=self
            )
            if filename:
                filepath = os.path.join(self.current_path, filename)
                if not os.path.exists(filepath):
                    with open(filepath, 'w') as f:
                        f.write("")
                    self.refresh_view()
                    show_neoui_info(self, "Success",
                                    f"File '{filename}' created successfully!\n\nThe new file is now ready for use in the current directory.")
                else:
                    show_neoui_error(self, "Error",
                                     "File already exists!\n\nPlease choose a different name or delete the existing file first.")
        except Exception as e:
            show_neoui_error(self, "Error",
                             f"Failed to create file: {str(e)}\n\nPlease check file permissions and disk space, then try again.")

    def _create_new_folder(self):
        """Create a new folder in current directory"""
        try:
            foldername = tk.simpledialog.askstring(
                "New Folder",
                "Enter folder name:",
                parent=self
            )
            if foldername:
                folderpath = os.path.join(self.current_path, foldername)
                if not os.path.exists(folderpath):
                    os.makedirs(folderpath)
                    self.refresh_view()
                    show_neoui_info(self, "Success",
                                    f"Folder '{foldername}' created successfully!\n\nThe new folder is now available in the current directory.")
                else:
                    show_neoui_error(self, "Error",
                                     "Folder already exists!\n\nPlease choose a different name or navigate to the existing folder.")
        except Exception as e:
            show_neoui_error(self, "Error",
                             f"Failed to create folder: {str(e)}\n\nPlease check file permissions and disk space, then try again.")

    def _show_statistics(self):
        """Show usage statistics"""
        if not hasattr(self, 'settings') or 'stats' not in self.settings:
            show_neoui_info(self, "Statistics",
                            "No statistics available yet.\n\nStart encrypting and decrypting files to see usage statistics here.")
            return

        stats = self.settings['stats']
        stats_text = f"""
Usage Statistics:
────────────────────────────────────

Files Encrypted: {stats.get('files_encrypted', 0)}
Files Decrypted: {stats.get('files_decrypted', 0)}
Keys Generated: {stats.get('keys_generated', 0)}
Theme Changes: {stats.get('theme_changes', 0)}

Navigation:
  Times Navigated: {stats.get('navigate_count', 0)}
  Times Refreshed: {stats.get('refresh_count', 0)}

Theme Usage:
"""
        for theme, count in stats.get('theme_usage', {}).items():
            stats_text += f"  {theme}: {count} times\n"

        dialog = tk.Toplevel(self)
        dialog.title("Statistics")
        dialog.geometry("500x550")
        dialog.resizable(False, False)

        self.after(40, lambda: set_dark_title_bar(dialog))

        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
        dialog.configure(bg=theme["bg"])
        dialog.transient(self)
        dialog.grab_set()

        label = tk.Label(
            dialog,
            text=stats_text,
            bg=theme["bg"],
            fg=theme["text"],
            font=("Consolas", 10),
            justify="left"
        )
        label.pack(padx=20, pady=20)

        close_btn = NeoUIHoverButton(
            dialog,
            text="Close",
            command=dialog.destroy,
            bg=theme["accent"],
            fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
            font=(DEFAULT_FONT, 10)
        )
        close_btn.pack(pady=10)

        dialog.bind("<Escape>", lambda e: dialog.destroy())

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
        try:
            SettingsDialog(self)
        except Exception as e:
            print(f"Error opening settings dialog: {e}")
            import traceback
            traceback.print_exc()
            # Show a user-friendly error message
            try:
                show_neoui_error(
                    self,
                    "Settings Error",
                    "Failed to open the settings window.\n\nPlease restart the app and try again.\n\n"
                    f"Details: {str(e)}",
                )
            except Exception:
                print("Could not show error message dialog")

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

            # Update body_frame (container for file explorer and DND panels)
            if hasattr(self, 'body_frame') and self.body_frame:
                self.body_frame.configure(bg=theme["bg"])

            # Update file listbox
            self.update_file_listbox_theme(theme)

            # Update Drag & Drop panel (if present)
            if hasattr(self, 'drag_drop_frame') and self.drag_drop_frame:
                try:
                    self.drag_drop_frame.configure(
                        bg=theme["secondary_bg"],
                        highlightbackground=theme["accent"],
                        highlightthickness=1,
                    )
                except Exception:
                    pass

                # Update the inner container background (this was previously not updated, causing stale theme colors)
                if hasattr(self, 'dnd_container') and self.dnd_container is not None:
                    try:
                        self.dnd_container.configure(bg=theme["secondary_bg"])
                    except Exception:
                        pass

                for wname in [
                    'dnd_title_label',
                    'dnd_desc_label',
                ]:
                    w = getattr(self, wname, None)
                    if w is not None:
                        try:
                            w.configure(bg=theme["secondary_bg"], fg=theme["text"])
                        except Exception:
                            pass

                if hasattr(self, 'dnd_target') and self.dnd_target is not None:
                    try:
                        self.dnd_target.configure(
                            bg=theme["bg"],
                            fg=theme["text"],
                            highlightbackground=theme["accent"],
                            highlightthickness=1,
                        )
                    except Exception:
                        pass

                if hasattr(self, 'dnd_listbox_container') and self.dnd_listbox_container is not None:
                    try:
                        self.dnd_listbox_container.configure(
                            bg=theme["secondary_bg"],
                            highlightbackground=theme["accent"]
                        )
                    except Exception:
                        pass

                if hasattr(self, 'dnd_listbox') and self.dnd_listbox is not None:
                    try:
                        self.dnd_listbox.configure(
                            bg=theme["bg"],
                            fg=theme["text"],
                            selectbackground=theme["accent"],
                            selectforeground=theme["text"],
                        )
                    except Exception:
                        pass

                if hasattr(self, 'dnd_browse_btn') and isinstance(self.dnd_browse_btn, NeoUIHoverButton):
                    try:
                        self.dnd_browse_btn.update_theme(
                            bg=theme["accent"],
                            fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                            active_bg=theme["accent"],
                            active_fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                        )
                    except Exception:
                        pass

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
                            r, g, b = tuple(int(theme["accent"][i:i + 2], 16) for i in (1, 3, 5))
                            r = min(255, r + 20);
                            g = min(255, g + 20);
                            b = min(255, b + 20)
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
                if hasattr(self, 'chk_button'):
                    # Update chk_button with a fresh theme reference
                    chk_theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])
                    self.chk_button.configure(bg=chk_theme["success"], activebackground=chk_theme["success"])
                    # Update hover brightness so it doesn't turn into the old theme color
                    if hasattr(self.chk_button, 'default_bg'):
                        self.chk_button.default_bg = theme["success"]
                        self.chk_button.bright_bg = self.brighten_color(theme["success"], 20)
                # Update hover colors for folder button
                if hasattr(self.folder_button, 'default_bg'):
                    self.folder_button.default_bg = theme["accent"]
                    try:
                        # Brighten the color for hover effect
                        r, g, b = tuple(int(theme["accent"][i:i + 2], 16) for i in (1, 3, 5))
                        r = min(255, r + 20);
                        g = min(255, g + 20);
                        b = min(255, b + 20)
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
                        r, g, b = tuple(int(theme["accent"][i:i + 2], 16) for i in (1, 3, 5))
                        r = min(255, r + 20);
                        g = min(255, g + 20);
                        b = min(255, b + 20)
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

        # Force a complete redraw of the window (may fail during shutdown)
        try:
            self.update()
        except Exception:
            return

        # Update sort button (guard against destroyed widgets)
        try:
            if hasattr(self, 'sort_button') and self.sort_button is not None and self.sort_button.winfo_exists():
                self.sort_button.configure(
                    bg=theme["accent"],
                    fg=NeoUIThemes.get_button_text_color(self.current_theme, "accent"),
                    activebackground=theme["accent"],
                    activeforeground=NeoUIThemes.get_button_text_color(self.current_theme, "accent")
                )
                if hasattr(self.sort_button, 'default_bg'):
                    self.sort_button.default_bg = theme["accent"]
                    try:
                        r, g, b = tuple(int(theme["accent"][i:i + 2], 16) for i in (1, 3, 5))
                        r = min(255, r + 20);
                        g = min(255, g + 20);
                        b = min(255, b + 20)
                        self.sort_button.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                    except Exception:
                        self.sort_button.bright_bg = theme["accent"]
        except Exception:
            pass

        # Update drive menu (guard against being torn down)
        try:
            if hasattr(self, 'drive_menu') and self.drive_menu is not None:
                self.drive_menu.configure(
                    bg=theme["secondary_bg"],
                    fg=theme["text"],
                    activebackground=theme["accent"],
                    activeforeground=theme["text"]
                )
        except Exception:
            pass

        # Initialize or update context menu (guard against destroyed widgets)
        try:
            if hasattr(self, 'file_listbox') and self.file_listbox is not None and self.file_listbox.winfo_exists():
                if hasattr(self, 'context_menu') and self.context_menu is not None:
                    try:
                        self.context_menu.destroy()
                    except Exception:
                        pass
                self.context_menu = FileContextMenu(self, theme)
                self.file_listbox.bind("<Button-3>", self.show_context_menu)
        except Exception:
            pass

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
                    r, g, b = tuple(int(bg[i:i + 2], 16) for i in (1, 3, 5))
                    r = min(255, r + 20);
                    g = min(255, g + 20);
                    b = min(255, b + 20)
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
                    r, g, b = tuple(int(theme["success"][i:i + 2], 16) for i in (1, 3, 5))
                    r = min(255, r + 20);
                    g = min(255, g + 20);
                    b = min(255, b + 20)
                    self.encrypt_button.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                except Exception:
                    self.encrypt_button.bright_bg = theme["success"]

        if hasattr(self, 'encrypt_dropdown_btn'):
            self.encrypt_dropdown_btn.configure(bg=theme["success"])
            if hasattr(self.encrypt_dropdown_btn, 'default_bg'):
                self.encrypt_dropdown_btn.default_bg = theme["success"]
                try:
                    r, g, b = tuple(int(theme["success"][i:i + 2], 16) for i in (1, 3, 5))
                    r = min(255, r + 20);
                    g = min(255, g + 20);
                    b = min(255, b + 20)
                    self.encrypt_dropdown_btn.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                except Exception:
                    self.encrypt_dropdown_btn.bright_bg = theme["success"]

    def update_file_listbox_theme(self, theme):
        """Update theme for the file listbox."""
        try:
            # Update the container border
            if hasattr(self, 'file_listbox_container') and self.file_listbox_container:
                self.file_listbox_container.configure(
                    bg=theme["secondary_bg"],
                    highlightbackground=theme["accent"]
                )

            # Update the listbox itself
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
        self._km_ensure_settings()
        self._km_refresh_active_key()
        if self.main_key:
            return self.main_key

        app_dir = self._km_get_app_dir()
        legacy_path = os.path.join(app_dir, 'main_key.key')

        try:
            if os.path.exists(legacy_path):
                legacy_item = self._km_try_parse_key_file(legacy_path)
                if legacy_item.get('kind') == 'legacy_raw' and legacy_item.get('valid') and legacy_item.get(
                        'fernet_key'):
                    km = self._km_ensure_settings()
                    if not (km.get('registered_keys') or {}):
                        self._km_register_selected(legacy_item)
                        self.after(700, lambda: show_neoui_warning(
                            self,
                            "Key Migration",
                            "FFE detected an existing legacy key file and registered it with this install.\n\n"
                            "You can manage keys from the Key menu."
                        ))
                        return self.main_key
        except Exception:
            pass

        return None

        # noinspection PyTypeChecker

    def show_encrypt_dropdown(self):
        """Show the encryption options dropdown menu with zero flash."""
        if self.encrypt_dropdown is not None:
            self.close_encrypt_dropdown()
            return

        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

        # 1. Create window and IMMEDIATELY make it invisible via alpha, NOT withdraw
        self.encrypt_dropdown = tk.Toplevel(self)
        self.encrypt_dropdown.attributes('-alpha', 0.0)
        self.encrypt_dropdown.overrideredirect(True)

        # 2. Build the UI while it's invisible
        frame = tk.Frame(
            self.encrypt_dropdown,
            bg=theme["secondary_bg"],
            bd=1,
            relief=tk.SOLID,
            highlightbackground=theme["accent"]
        )
        frame.pack(fill="both", expand=True)

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
                command=lambda m=method: self.on_encrypt_method_selected(m),
                padx=15,
                pady=8,
                anchor="w"
            )
            btn.pack(fill=tk.X)

            # Add hover effect
            btn.bind("<Enter>",
                     lambda e, b=btn: b.config(bg=theme["accent"], fg=theme.get("btn_text_on_accent", "white")))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=theme["secondary_bg"], fg=theme["text"]))

        # 3. Force calculation of size while alpha is 0
        self.encrypt_dropdown.update_idletasks()

        req_w = self.encrypt_dropdown.winfo_reqwidth()
        req_h = self.encrypt_dropdown.winfo_reqheight()

        # 4. Calculate coordinates relative to the button
        x = self.encrypt_button.winfo_rootx()
        y = self.encrypt_button.winfo_rooty() + self.encrypt_button.winfo_height()

        # 5. Set geometry and lift to top BEFORE making visible
        self.encrypt_dropdown.geometry(f"{req_w}x{req_h}+{x}+{y}")
        self.encrypt_dropdown.lift()

        # 6. Start the fade animation manually
        # This prevents the "flash" because deiconify/withdraw aren't used
        def _start_fade():
            if self.encrypt_dropdown:
                _ffe_fade_in(self.encrypt_dropdown)

        self.after(1, _start_fade)

        # Bind focus out to close
        self.encrypt_dropdown.bind("<FocusOut>", lambda e: self.close_encrypt_dropdown())
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
            self.encrypt_with_password()
        else:
            self.encrypt_with_key_file()

    def encrypt_with_key_file(self):
        """Encrypt the selected file using the key file."""
        try:
            if not getattr(self, 'main_key', None):
                show_neoui_error(self, "Key Required",
                                 "No active registered key is loaded.\n\nOpen the Key menu to set up or import a key.\n\nYou need a valid encryption key to encrypt files.")
                return
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_neoui_error(self, "Nope",
                                 "Can't encrypt a directory.\n\nPlease select a specific file to encrypt. Directories cannot be encrypted directly.")
                return

            def encrypt_operation(update_progress):
                result = encrypt_with_keyfile(
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

    def encrypt_with_password(self):
        """Encrypt the selected file using a password."""
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_neoui_error(self, "Error",
                                 "Can't encrypt a directory.\n\nPlease select a specific file to encrypt. Directories cannot be encrypted directly.")
                return

            # Use the standard password dialog
            password = self._ask_password(
                "Encrypt with Password",
                "Enter a password to encrypt this file.\n\nMake sure to remember it.",
                confirm=True,
            )
            if not password:
                return  # User cancelled

            # Use password immediately and clear it as soon as possible
            temp_password = password
            password = None  # Clear the reference immediately

            def encrypt_operation(update_progress):
                nonlocal temp_password
                try:
                    result = encrypt_with_password(
                        full_path,
                        temp_password,
                        progress_callback=update_progress
                    )
                    success = isinstance(result, str) and "successfully encrypted" in result.lower()
                    return success, result
                finally:
                    # Ensure password is cleared even if encryption fails
                    _secure_clear_memory(temp_password.encode('utf-8') if temp_password else b'')
                    temp_password = None

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
        default_method = self.settings.get("encryption", {}).get("default_method", "password")

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
                error_msg = str(e)
                app.after(0, lambda: on_operation_complete(False, error_msg))
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
                    show_neoui_error(app, "Decryption Failed",
                                     f"The file could not be decrypted.\n\nError details: {error_msg}")

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

    def check_with_defender(self):
        """Scan the selected file with Windows Defender and show results in a neoui dialog."""
        try:
            selected_index = self.file_listbox.curselection()
            if not selected_index:
                show_neoui_error(self, "Error", "You haven't selected a file. Please select one before continuing.")
                return

            file_path = self.file_paths[selected_index[0]]

            if os.path.isdir(file_path):
                show_neoui_error(self, "Invalid Selection", "Please select a file, not a directory.")
                return

            if not os.path.isfile(file_path):
                show_neoui_error(self, "File Not Found", f"The file does not exist:\n{file_path}")
                return

            # Find Windows Defender MpCmdRun.exe
            mpcmdrun = None
            possible_paths = [
                r"C:\Program Files\Windows Defender\MpCmdRun.exe",
                os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'MpCmdRun.exe'),
                os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'Windows Defender', 'MpCmdRun.exe'),
            ]

            for path in possible_paths:
                if os.path.exists(path):
                    mpcmdrun = path
                    break

            if not mpcmdrun:
                show_neoui_error(
                    self,
                    "Windows Defender Not Found",
                    "Could not locate Windows Defender (MpCmdRun.exe).\n\n"
                    "Please ensure Windows Defender is installed and enabled on your system."
                )
                return

            # Show scanning progress
            progress_dialog = ProgressDialog(self, "Scanning with Windows Defender...")
            progress_dialog.update_progress(10, "Initializing scan...")

            # Run Windows Defender scan in a separate thread
            import subprocess
            import threading

            def run_scan():
                try:
                    progress_dialog.update_progress(20, "Updating signatures...")

                    # First, update signatures to ensure latest definitions
                    result = subprocess.run(
                        [mpcmdrun, "-SignatureUpdate"],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=120
                    )

                    progress_dialog.update_progress(40, "Scanning file...")

                    # Run the scan - MpCmdRun.exe -Scan -ScanType 3 -File <path>
                    # ScanType 3 = Custom scan for a specific file/path
                    result = subprocess.run(
                        [mpcmdrun, "-Scan", "-ScanType", "3", "-File", file_path],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=300  # 5 minute timeout
                    )

                    progress_dialog.update_progress(90, "Processing results...")

                    # Parse the result
                    stdout = result.stdout
                    stderr = result.stderr
                    combined_output = (stdout + " " + stderr).lower()

                    # Determine scan result
                    scan_successful = False
                    threat_found = False
                    threat_name = None
                    error_message = None

                    # Check return code and output for various scenarios
                    return_code = result.returncode

                    # Success codes: 0 = no threats, 2 = threats found (on some versions)
                    # Error codes: various non-zero codes indicate errors

                    # Look for specific threat indicators in output
                    threat_keywords = [
                        "found", "threat", "malware", "virus", "trojan",
                        "detected", "infection", "quarantined", "removed"
                    ]

                    clean_keywords = [
                        "no threats found", "no threats detected",
                        "found no threats", "clean", "scanned successfully"
                    ]

                    error_keywords = [
                        "access is denied", "not supported", "invalid parameter",
                        "file not found", "path not found", "cannot find"
                    ]

                    # Check for threat indicators
                    has_threat_indicator = any(kw in combined_output for kw in threat_keywords)
                    has_clean_indicator = any(kw in combined_output for kw in clean_keywords)
                    has_error_indicator = any(kw in combined_output for kw in error_keywords)

                    # Extract threat name if present
                    if "threat" in combined_output:
                        import re
                        threat_match = re.search(r'threat[:\s]+([^\n\r]+)', combined_output)
                        if threat_match:
                            threat_name = threat_match.group(1).strip()

                    # Determine scan status
                    if return_code == 0:
                        # Return code 0 typically means no threats found
                        if has_threat_indicator and not has_clean_indicator:
                            threat_found = True
                        else:
                            threat_found = False
                        scan_successful = True
                    elif return_code in [2, 2147942405]:
                        # Return code 2 typically means threats were found
                        threat_found = True
                        scan_successful = True
                    elif return_code == 2147942402 or "timeout" in combined_output:
                        error_message = "Scan timed out. The file may be large or the system is busy."
                        scan_successful = False
                    else:
                        # Other return codes - check for error indicators
                        if has_error_indicator:
                            if "access is denied" in combined_output:
                                error_message = "Access denied. Please ensure you have permission to scan this file."
                            elif "not supported" in combined_output:
                                error_message = "This file type is not supported for scanning."
                            elif "file not found" in combined_output:
                                error_message = "The specified file was not found."
                            else:
                                error_message = f"Scan error (code: {return_code})"
                        elif has_threat_indicator:
                            threat_found = True
                            scan_successful = True
                        else:
                            # Unknown status - assume scan completed but unclear results
                            scan_successful = True
                            error_message = f"Scan completed with code: {return_code}"
                            if stderr:
                                error_message += f"\nDetails: {stderr.strip()}"

                    # Schedule UI update on main thread
                    self.after(0, lambda: self._show_defender_results(
                        progress_dialog, file_path, scan_successful, threat_found,
                        threat_name, error_message, stdout, stderr
                    ))

                except subprocess.TimeoutExpired:
                    self.after(0, lambda: self._show_defender_results(
                        progress_dialog, file_path, False, False,
                        None, "Scan timed out after 5 minutes.", "", "Timeout"
                    ))
                except Exception as e:
                    self.after(0, lambda: self._show_defender_results(
                        progress_dialog, file_path, False, False,
                        None, f"An error occurred: {str(e)}", "", str(e)
                    ))

            # Start scan in separate thread
            threading.Thread(target=run_scan, daemon=True).start()

        except Exception as e:
            show_neoui_error(
                self,
                "Scan Error",
                f"An error occurred while preparing the scan:\n{str(e)}"
            )

    def _show_defender_results(self, progress_dialog, file_path, scan_successful,
                               threat_found, threat_name, error_message, stdout, stderr):
        """Show the scan results in a dialog after the scan completes."""
        try:
            # Close progress dialog
            if progress_dialog and progress_dialog.winfo_exists():
                progress_dialog.destroy()

            # Build the result message
            filename = os.path.basename(file_path)

            if not scan_successful:
                message = f"❌ Scan Failed\n\n{error_message or 'Unknown error occurred.'}"
                if stderr and stderr.strip():
                    message += f"\n\nDetails:\n{stderr.strip()}"
                dialog_type = "error"
            elif threat_found:
                if threat_name:
                    message = f"Threat Detected!\n\nWindows Defender found a threat:\n\n{threat_name}\n\nFile: {filename}\n\nLocation: {file_path}"
                else:
                    message = f"Threat Detected!\n\nWindows Defender found a potential threat in:\n{filename}\n\nFile: {file_path}"
                dialog_type = "error"
            else:
                message = f"No Threats Found\n\nWindows Defender scan completed successfully.\n\nFile: {filename}\n\nLocation: {file_path}"
                dialog_type = "success"

            # Show results in a neoui dialog
            dialog = neouiDialog(
                self,
                "Scan Complete",
                message,
                dialog_type
            )

            # Apply dark mode to the dialog
            self.after(40, lambda: set_dark_title_bar(dialog))

        except Exception as e:
            show_neoui_error(
                self,
                "Display Error",
                f"An error occurred while displaying results:\n{str(e)}"
            )

    def decrypt_file(self):
        if self.decrypting:
            return

        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_neoui_error(self, "Nope",
                                 "Can't decrypt a directory.\n\nPlease select a specific encrypted file to decrypt. Directories cannot be decrypted.")
                return

            if not full_path.endswith(".enc"):
                show_neoui_error(self, "Invalid File Type",
                                 "Only .enc files can be decrypted.\n\nPlease select an encrypted file with the .enc extension.")
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
                w, h = 400, 280
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
                            if any(msg in result.lower() for msg in
                                   ["error", "wrong password", "incorrect password", "invalid password",
                                    "decryption failed"]):
                                return False, ("Incorrect Password\n\n"
                                               "The password you entered does not match the one used to encrypt this file. "
                                               "Please check for typos and try again.\n\n"
                                               "• Make sure Caps Lock is turned off\n"
                                               "• Check for any extra spaces before or after the password\n"
                                               "• If you've forgotten the password, you'll need to obtain the correct one to decrypt this file")
                        return False, result or "Decryption failed. The password may be incorrect or the file may be corrupted."
                    except Exception as e:
                        error_msg = str(e).lower()
                        if any(msg in error_msg for msg in
                               ["wrong password", "incorrect password", "invalid password", "decryption failed",
                                "invalid tag"]):
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
                                lambda value, status=None: self.after(10, lambda: progress_dialog.update_progress(value,
                                                                                                                  status or "Decrypting..."))
                            )
                            self.after(10, lambda: self.on_decrypt_complete((success, result)))
                        except Exception as e:
                            self.after(10, lambda: show_neoui_error(self, "Decryption Error",
                                                                    f"Failed to decrypt file: {str(e)}"))
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
                    show_neoui_error(self, "Key Required",
                                     "No active registered key is loaded.\n\nOpen the Key menu to set up or import a key.\n\nYou need a valid encryption key to encrypt files.")
                    return

                def decrypt_operation(update_progress):
                    try:
                        result = decrypt_with_keyfile(
                            full_path,
                            self.main_key,
                            progress_callback=update_progress
                        )
                        # decrypt_with_keyfile returns None on success for key-file decryption
                        if result is None:
                            return True, f"File '{os.path.basename(full_path)}' successfully decrypted!"
                        return False, result
                    except Exception as e:
                        return False, f"Decryption failed: {str(e)}"

                self._run_with_progress(
                    "Decrypting File...",
                    decrypt_operation,
                    lambda msg: self.on_decrypt_complete((True, msg))
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
        """Show the About dialog with application information and social links."""
        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

        # Create the window
        win = tk.Toplevel(self)
        win.withdraw()  # Hide initially
        win.attributes('-alpha', 0.0)  # Make transparent
        win.title("About Friend File Encryptor")
        win.configure(bg=theme["secondary_bg"])
        win.resizable(False, False)
        win.transient(self)

        # Ensure window is fully initialized before applying dark mode
        def init_window():
            win.update_idletasks()
            win.update()
            set_dark_title_bar(win)

            # Force a theme refresh after a short delay
            win.after(200, lambda: set_dark_title_bar(win))

        # Initial dark mode application
        win.after(100, init_window)

        # Main content frame
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
            text='Version 3.0.0 "Amaryllis"',
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
            "Build: ffe_042926_300",
            "neoUI 2.0",
            "Python 3.14.0",
            "Windows Edition",  # linucc when??
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
            row = tk.Frame(main, bg=theme["secondary_bg"]);
            row.pack(fill="x", pady=4)
            lbl = tk.Label(row, text=label_text, bg=theme["secondary_bg"], fg=theme["text"], font=(DEFAULT_FONT, 11))
            lbl.pack(side="left", anchor="w")
            # spacer expands to push the button to the right
            spacer = tk.Frame(row, bg=theme["secondary_bg"]);
            spacer.pack(side="left", expand=True, fill="x")
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
            text="Summoned into existence by AVX_Advanced!",
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

        tk.Frame(main, height=2, bg=theme["accent"]).pack(fill="x", pady=(6, 11))

        btns = tk.Frame(main, bg=theme["secondary_bg"]);
        btns.pack(fill="x", pady=(0, 0))
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
        # Ensure minimum reasonable size
        w = max(w, 500)
        h = max(h, 600)
        x = (win.winfo_screenwidth() // 2) - (w // 2)
        y = (win.winfo_screenheight() // 2) - (h // 2)
        win.geometry(f"{w}x{h}+{x}+{y}")
        win.deiconify()  # Show window with fade effect
        win.grab_set()
        win.focus_set()

    # DO NOT MAKE THE BELOW WINDOW RESIZABLE

    def show_imports(self, parent_window):
        """Display a window showing all imports used in FFE with neoui styling."""
        theme = NeoUIThemes.THEMES.get(self.current_theme, NeoUIThemes.THEMES["Ocean Deep"])

        win = tk.Toplevel(parent_window)
        win.withdraw()  # Hide initially
        win.attributes('-alpha', 0.0)  # Make transparent
        win.title("Dependencies")
        win.configure(bg=theme["secondary_bg"])

        win.minsize(400, 800)
        win.resizable(True, True)  # DO NOT MAKE RESIZABLE I BEG YOU

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

        std_lib_frame = add_section("Python Version", content_frame)  # Python Ver
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

        std_lib_frame = add_section("Python Standard Library", content_frame)  # Standard Lib
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

        third_party_frame = add_section("Third-party Packages", content_frame)  # Third Party
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
        win.deiconify()  # Show window with fade effect
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
                                                    NeoUIThemes.THEMES.get(self.current_theme,
                                                                           NeoUIThemes.THEMES["Ocean Deep"]))

            self.context_menu.show_delete_dialog(full_path)

        except IndexError:
            show_neoui_error(self, "Error",
                             "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_neoui_error(self, "Error", f"Something went wrong while trying to delete {str(e)}")

    def update_ffe(self):
        """Update mechanism disabled: open the GitHub releases page."""
        try:
            show_neoui_info(
                self,
                "Updates",
                "In-app update downloading is disabled.\n\nOpening GitHub releases page...",
            )
        except Exception:
            pass
        try:
            webbrowser.open_new("https://github.com/AVXAdvanced/FFE/releases")
        except Exception:
            pass


print("FFEApp MainLoop Occurs here.")
print("Bottom of code reached.")

if __name__ == "__main__":
    _ffe_enable_windows_dpi_awareness()
    app = FFEApp()
    app.mainloop()
