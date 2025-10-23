import os
import requests
import tkinter as tk
from tkinter import messagebox, ttk
import textwrap
import json
from cryptography.fernet import Fernet
from packaging import version
import re
import webbrowser
import threading

SETTINGS_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "ffedata.json")
LEGACY_SETTINGS_FILE = os.path.join(SETTINGS_DIR, "ffe_settings.json")

def fesys_gen_key():
    return Fernet.generate_key()


def load_app_settings():
    """Load app settings with sane defaults. Migrate legacy file if present."""
    defaults = {
        "theme": "Dark Blue",
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
    """Persist app settings to SETTINGS_FILE safely."""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)
    except Exception:
        # Non-fatal if we cannot save
        pass


def fesys_save_key(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)


def fesys_encrypt_file(file_path, main_key):
    try:
        cipher_main = Fernet(main_key)
        new_key = Fernet.generate_key()
        cipher_file = Fernet(new_key)

        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = cipher_file.encrypt(file_data)
        encrypted_key = cipher_main.encrypt(new_key)
        encrypted_file_path = file_path + ".enc"

        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data + b"|||" + encrypted_key)

        return f"File '{os.path.basename(file_path)}' successfully encrypted!"
    except Exception as e:
        return f"Error during encryption: {str(e)}"


def fesys_decrypt_file(file_path, main_key):
    try:
        if not file_path.endswith(".enc"):
            return "Only .enc files can be decrypted."

        cipher_main = Fernet(main_key)

        with open(file_path, "rb") as encrypted_file:
            full_encrypted_data = encrypted_file.read()

        try:
            encrypted_data, encrypted_key = full_encrypted_data.split(b"|||")
        except ValueError:
            return "Error: Encrypted file is corrupted or not in the correct format."

        decrypted_key = cipher_main.decrypt(encrypted_key)
        cipher_file = Fernet(decrypted_key)
        decrypted_data = cipher_file.decrypt(encrypted_data)
        decrypted_file_path = file_path[:-4]

        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        return f"File '{os.path.basename(file_path[:-4])}' successfully decrypted!"
    except Exception as e:
        return f"Error during decryption: {str(e)}"


class HoverButton(tk.Button):
    def __init__(self, master, **kwargs):
        tk.Button.__init__(self, master, **kwargs)
        self.default_bg = self["background"]
        self.bright_bg = self.brighten_color(self.default_bg, 20)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self["background"] = self.bright_bg

    def on_leave(self, e):
        self["background"] = self.default_bg

    def brighten_color(self, color, brightness_factor):
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


# ===== Modern dialog components (from Aetherion FET) - scoped to dialogs only =====
class AetherThemeColors:
    THEMES = {
        "Dark Blue": {
            "bg": "#0a1124",
            "secondary_bg": "#0f1936",
            "accent": "#2c4580",
            "success": "#2d8879",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Midnight Purple": {
            "bg": "#1a1025",
            "secondary_bg": "#2a1f3a",
            "accent": "#614885",
            "success": "#4a9c6d",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Dark Green": {
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
        "Arctic": {
            "bg": "#0f1419",
            "secondary_bg": "#1a2027",
            "accent": "#3d4a59",
            "success": "#3d7a5f",
            "error": "#bf3e3b",
            "warning": "#bf8f3b",
            "text": "white"
        },
        "Sunset": {
            "bg": "#1a1410",
            "secondary_bg": "#261b14",
            "accent": "#d4804d",
            "success": "#e6b800",
            "error": "#ff4d4d",
            "warning": "#ffa64d",
            "text": "white"
        },
        "Cyberpunk": {
            "bg": "#0f0f1a",
            "secondary_bg": "#16162b",
            "accent": "#2b2b52",
            "success": "#00ff9f",
            "error": "#ff003c",
            "warning": "#ffb300",
            "text": "#00fff2",
            "button_text": "#000000"
        },
        "High Contrast": {
            "bg": "#000000",
            "secondary_bg": "#141414",
            "accent": "#3366cc",
            "success": "#00cc00",
            "error": "#cc0000",
            "warning": "#cccc00",
            "text": "#ffffff"
        }
    }

    @staticmethod
    def get_dialog_colors(dialog_type, theme_name):
        theme = AetherThemeColors.THEMES.get(theme_name, AetherThemeColors.THEMES["Dark Blue"])
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
        # For our purposes, white text is fine for the Dark Blue theme
        return "white"


DEFAULT_FONT = "Segoe UI"


class AetherHoverButton(tk.Button):
    def __init__(self, master, **kwargs):
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
        self["background"] = self.bright_bg

    def _on_leave(self, e):
        self["background"] = self.default_bg

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


class ModernDialog(tk.Toplevel):
    TITLE_FONT_SIZE = 29
    VERSION_FONT_SIZE = 16
    CONTENT_FONT_SIZE = 11

    def __init__(self, parent, title, message, dialog_type="info", title_font_size=None):
        super().__init__(parent)
        self.result = None

        # Theme
        theme_name = getattr(parent, 'current_theme', 'Dark Blue')
        theme = AetherThemeColors.THEMES.get(theme_name, AetherThemeColors.THEMES["Dark Blue"])
        accent_color = AetherThemeColors.get_dialog_colors(dialog_type, theme_name)

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

            yes_btn = AetherHoverButton(btn_frame, text="✓", command=self._yes, bg=accent_color,
                                        fg=AetherThemeColors.get_button_text_color(theme_name, "success"),
                                        font=(DEFAULT_FONT, 11), relief="flat")
            yes_btn.grid(row=0, column=0, sticky="ew", padx=2, pady=5)

            no_btn = AetherHoverButton(btn_frame, text="❌", command=self._no, bg=theme["accent"],
                                       fg=AetherThemeColors.get_button_text_color(theme_name, "accent"),
                                       font=(DEFAULT_FONT, 11), relief="flat")
            no_btn.grid(row=0, column=1, sticky="ew", padx=2, pady=5)
        else:
            ok_btn = AetherHoverButton(btn_frame, text="✓", command=self._ok, bg=accent_color,
                                       fg=AetherThemeColors.get_button_text_color(theme_name, dialog_type),
                                       font=(DEFAULT_FONT, 11), relief="flat")
            ok_btn.pack(fill="x", padx=5, pady=5)

        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

        self.grab_set()
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


def show_modern_info(parent, title, message):
    d = ModernDialog(parent, title, message, "info")
    d.wait_window()
    return d.result


def show_modern_warning(parent, title, message):
    d = ModernDialog(parent, title, message, "warning")
    d.wait_window()
    return d.result


def show_modern_error(parent, title, message):
    d = ModernDialog(parent, title, message, "error")
    d.wait_window()
    return d.result


def show_modern_question(parent, title, message):
    d = ModernDialog(parent, title, message, "question")
    d.wait_window()
    return d.result

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title("Settings")
        theme = AetherThemeColors.THEMES.get(parent.current_theme, AetherThemeColors.THEMES["Dark Blue"])
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

        # Notebook with tabs (we will hide native tabs and use a custom selector)
        notebook = ttk.Notebook(main_frame)
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

        # Build custom selector bar and hide native tabs
        self._build_selector_bar(main_frame, theme)
        try:
            for tab_id in list(notebook.tabs()):
                notebook.hide(tab_id)
        except Exception:
            pass

        # Populate
        self._populate_na_tab(self.general_frame, theme)
        self._populate_themes_tab(self.themes_frame, theme)
        self._populate_na_tab(self.encryption_frame, theme)
        self._populate_stats_tab(self.stats_frame, theme)
        self._populate_update_tab(self.update_frame, theme)

        # Buttons at bottom
        buttons = tk.Frame(main_frame, bg=theme["secondary_bg"]) 
        buttons.pack(fill="x", pady=(10, 0))

        close_btn = AetherHoverButton(
            buttons,
            text="✓",
            command=self.destroy,
            bg=AetherThemeColors.get_dialog_colors("info", self.parent.current_theme),
            fg=AetherThemeColors.get_button_text_color(self.parent.current_theme, "info"),
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

    def _populate_na_tab(self, frame, theme):
        inner = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=20)
        inner.pack(expand=True, fill="both")
        label = tk.Label(
            inner,
            text="Page Not Available",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 14, "bold"),
        )
        label.pack(expand=True)

    def _populate_themes_tab(self, frame, theme):
        container = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=10)
        container.pack(expand=True, fill="both")

        tk.Label(
            container,
            text="Interface Theme",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 12, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        self.theme_var = tk.StringVar(value=self.parent.current_theme)
        themes = list(AetherThemeColors.THEMES.keys())

        # Two-column layout similar to Aetherion
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
            tk.Radiobutton(
                row,
                text=name,
                variable=self.theme_var,
                value=name,
                bg=theme["secondary_bg"],
                fg=theme["text"],
                selectcolor=theme["accent"],
                activebackground=theme["secondary_bg"],
                activeforeground=theme["text"],
                font=(DEFAULT_FONT, 11),
                pady=3,
                command=self._on_theme_change,
            ).pack(side="left", anchor="w")

        hint = tk.Label(
            container,
            text="Themes affect dialog/windows styling. Main window will remain unchanged.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 9, "italic"),
        )
        hint.pack(anchor="w", pady=(8, 0))

    def _on_theme_change(self):
        chosen = self.theme_var.get()
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
        # Optionally re-tint this dialog to reflect new theme
        theme = AetherThemeColors.THEMES.get(chosen, AetherThemeColors.THEMES["Dark Blue"])
        self.configure(bg=theme["secondary_bg"]) 
        # Re-apply tab styling for new theme
        self._apply_notebook_style(chosen)
        # Apply theme across the main FFE window as requested
        if hasattr(self.parent, 'apply_theme'):
            self.parent.apply_theme()
        # Restyle selector bar
        self._style_selector(AetherThemeColors.THEMES.get(chosen, AetherThemeColors.THEMES["Dark Blue"]))

    def _populate_stats_tab(self, frame, theme):
        container = tk.Frame(frame, bg=theme["secondary_bg"], padx=10, pady=10)
        container.pack(expand=True, fill="both")

        tk.Label(
            container,
            text="Usage Statistics",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 12, "bold"),
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
            font=(DEFAULT_FONT, 12, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        desc = tk.Label(
            container,
            text="Check for updates to FFE.",
            bg=theme["secondary_bg"],
            fg=theme["text"],
            font=(DEFAULT_FONT, 10),
        )
        desc.pack(anchor="w", pady=(0, 10))

        check_btn = AetherHoverButton(
            container,
            text=" Check for Updates ",
            command=self.parent.update_ffe,
            bg=theme["accent"],
            fg=AetherThemeColors.get_button_text_color(self.parent.current_theme, "accent"),
            font=(DEFAULT_FONT, 11),
            relief="flat",
        )
        check_btn.pack(anchor="w")

    def _build_selector_bar(self, parent, theme):
        # Create a custom, theme-aware tab selector with buttons and an accent indicator
        bar = tk.Frame(parent, bg=theme["secondary_bg"])
        bar.pack(fill="x", pady=(0, 6))
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

        for name, frame in tabs:
            btn = AetherHoverButton(
                bar,
                text=f"  {name}  ",
                command=make_handler(name, frame),
                bg=theme["secondary_bg"],
                fg=theme["text"],
                relief="flat",
                font=(DEFAULT_FONT, 11)
            )
            btn.pack(side="left", padx=(0, 8), pady=0)
            # Accent indicator line under each button (shown only for selected)
            indicator = tk.Frame(bar, bg=theme["secondary_bg"], height=2)
            indicator.pack_propagate(False)
            indicator.place(in_=btn, relx=0, rely=1.0, relwidth=1.0, y=0)
            self.tab_buttons[name] = {"button": btn, "indicator": indicator}

        # Default selection: show General page immediately
        self.selected_tab_name = "General"
        try:
            self.notebook.select(self.general_frame)
        except Exception:
            pass
        self._update_selector_active()

    def _style_selector(self, theme):
        # Re-style selector bar and buttons to current theme
        if hasattr(self, 'selector_bar') and self.selector_bar:
            self.selector_bar.configure(bg=theme["secondary_bg"])
        if hasattr(self, 'tab_buttons'):
            for name, obj in self.tab_buttons.items():
                btn = obj["button"]
                ind = obj["indicator"]
                btn.configure(bg=theme["secondary_bg"], fg=theme["text"]) 
                ind.configure(bg=theme["secondary_bg"])  # will be overridden for selected
        # Refresh active state colors
        self._update_selector_active()

    def _update_selector_active(self):
        # Apply selected styling: accent text + accent underline for active, subtle for others
        theme_name = getattr(self.parent, 'current_theme', 'Dark Blue')
        theme = AetherThemeColors.THEMES.get(theme_name, AetherThemeColors.THEMES["Dark Blue"])
        accent = theme["accent"]
        norm_fg = theme["text"]
        sel_fg = AetherThemeColors.get_button_text_color(theme_name, "accent")
        for name, obj in getattr(self, 'tab_buttons', {}).items():
            btn = obj["button"]
            ind = obj["indicator"]
            if name == getattr(self, 'selected_tab_name', ''):
                btn.configure(bg=theme["secondary_bg"], fg=sel_fg)
                ind.configure(bg=accent, height=2)
                # Make the selected notebook page visible
                # (no-op if already visible)
            else:
                btn.configure(bg=theme["secondary_bg"], fg=norm_fg)
                ind.configure(bg=theme["secondary_bg"], height=2)

    def _apply_notebook_style(self, theme_name):
        """Style ttk.Notebook tabs to match Aetherion's Settings aesthetics."""
        style = ttk.Style()
        # Prefer 'clam' if available for better ttk visuals
        if 'clam' in style.theme_names():
            style.theme_use('clam')
        else:
            style.theme_use('default')

        theme = AetherThemeColors.THEMES.get(theme_name, AetherThemeColors.THEMES["Dark Blue"])
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


class FFEApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Friend File Encryptor - Version 2.2.0")
        self.geometry("1070x800")
        self.configure(bg="#0a1124")
        self.minsize(1070, 800)

        # Load saved settings (theme persistence)
        self.settings = load_app_settings()
        self.current_theme = self.settings.get("theme", "Dark Blue")
        self.main_key = self.load_main_key()

        self.current_path = "C:/"
        self.history = [self.current_path]
        self.history_index = 0
        self.file_listbox = tk.Listbox(self, bg="#0f1936", fg="white", selectmode=tk.SINGLE, font=("Segoe UI", 12),
                                       selectbackground="#2a4180", selectforeground="white")
        self.file_listbox.bind("<Double-1>", self.file_dc_act)
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
                self.after(0, on_failure)

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
        toolbar.pack(fill=tk.X, padx=10, pady=0)
        # Keep a reference for later theming
        self.toolbar = toolbar
        toolbar.columnconfigure(2, weight=1)

        self.back_button = HoverButton(toolbar, text=" Back ", command=self.go_back, state=tk.DISABLED,
                                       bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.back_button.pack(side=tk.LEFT, padx=5)

        self.forward_button = HoverButton(toolbar, text=" Forward ", command=self.go_forward, state=tk.DISABLED,
                                          bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.forward_button.pack(side=tk.LEFT, padx=5)

        self.refresh_button = HoverButton(toolbar, text=" Refresh ", command=self.refresh_view, bg="#203161", fg="white",
                                        relief="flat", font=("Segoe UI", 11))
        self.refresh_button.pack(side=tk.LEFT, padx=5)

        self.drive_selector = tk.StringVar(value=self.current_path)
        self.drive_menu = tk.OptionMenu(toolbar, self.drive_selector, *self.acc_hdd(), command=self.update_drive)
        self.drive_menu["menu"].config(bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.drive_menu.config(bg="#203161", fg="white", font=("Segoe UI", 11), relief="flat")
        self.drive_menu.pack(side=tk.LEFT, padx=20, expand=True, fill=tk.X)

        # Keep original file listbox padding
        self.file_listbox.pack(pady=8, padx=15, expand=True, fill=tk.BOTH)
        self.file_listbox.bind("<Double-1>", self.file_dc_act)

        encrypt_button = HoverButton(toolbar, text=" Encrypt ", command=self.encrypt_file, bg="#469c57", fg="white",
                                     relief="flat", font=("Segoe UI", 11))
        encrypt_button.pack(side=tk.LEFT, padx=5, pady=8)

        decrypt_button = HoverButton(toolbar, text=" Decrypt ", command=self.decrypt_file, bg="#469c57", fg="white",
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
        _theme = AetherThemeColors.THEMES.get(self.current_theme, AetherThemeColors.THEMES["Dark Blue"])
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
        theme = AetherThemeColors.THEMES.get(self.current_theme, AetherThemeColors.THEMES["Dark Blue"])
        # Root window
        self.configure(bg=theme["bg"])
        # Toolbar frame
        if hasattr(self, 'toolbar') and self.toolbar:
            self.toolbar.configure(bg=theme["bg"])
            # Style toolbar children
            for child in self.toolbar.winfo_children():
                if isinstance(child, tk.Button):
                    text = child.cget("text").strip().lower()
                    if "delete" in text:
                        bg = theme["error"]
                    elif "encrypt" in text or "decrypt" in text:
                        bg = theme["success"]
                    else:
                        bg = theme["accent"]
                    child.configure(bg=bg, fg=theme.get("button_text", theme["text"]))
                    # Update hover colors if it's a HoverButton
                    if hasattr(child, 'default_bg'):
                        child.default_bg = bg
                        # mimic brighten
                        try:
                            # reuse brighten logic via a temp AetherHoverButton to compute color, or inline
                            r, g, b = tuple(int(bg[i:i+2], 16) for i in (1, 3, 5))
                            r = min(255, r + 20); g = min(255, g + 20); b = min(255, b + 20)
                            child.bright_bg = f"#{r:02x}{g:02x}{b:02x}"
                        except Exception:
                            child.bright_bg = bg
                elif isinstance(child, tk.OptionMenu):
                    child.configure(bg=theme["accent"], fg=theme["text"], highlightthickness=0)
                    try:
                        child["menu"].configure(bg=theme["accent"], fg=theme["text"])  # type: ignore
                    except Exception:
                        pass
        # File listbox
        try:
            self.file_listbox.configure(bg=theme["secondary_bg"], fg=theme["text"],
                                        selectbackground=theme["accent"], selectforeground=theme["text"])
        except Exception:
            pass

        # Status label (bottom info bar)
        try:
            self.status_label.configure(bg=theme["bg"], fg=theme["text"]) 
            self.status_label.update_idletasks()
        except Exception:
            pass

        # Flush pending UI updates to reflect theme changes instantly
        try:
            self.update_idletasks()
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

    def update_drive(self, new_drive):
        self.current_path = new_drive
        self.history = [new_drive]  # Directly set the history with the new path
        self.history_index = 0
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

    def encrypt_file(self):
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_modern_error(self, "Nope", "Can't encrypt a directory. Select a file.")
                return

            result = fesys_encrypt_file(full_path, self.main_key)
            self.status_label.config(text=result)
            self.acc_files()
            try:
                if isinstance(result, str) and "successfully encrypted" in result.lower():
                    self.inc_stat("files_encrypted", 1)
            except Exception:
                pass

        except IndexError:
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Welp, we couldn't encrypt that one: {str(e)}")

    def decrypt_file(self):
        if self.decrypting:
            return
        self.decrypting = True

        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                show_modern_error(self, "Nope", "Can't decrypt a directory. Please Select a file.")
                self.decrypting = False
                return

            if not full_path.endswith(".enc"):
                show_modern_error(self, "Nope", "Only .enc files can be decrypted.")
                self.decrypting = False
                return

            result = fesys_decrypt_file(full_path, self.main_key)
            self.status_label.config(text=result)
            self.acc_files()
            try:
                if isinstance(result, str) and "successfully decrypted" in result.lower():
                    self.inc_stat("files_decrypted", 1)
            except Exception:
                pass

        except IndexError:
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Failed to decrypt file: {str(e)}")
        finally:
            self.decrypting = False

    def show_about(self):
        show_modern_info(self, "About Friend File Encryptor", """Friend File Encryptor  -  FFE

Version 2.2.0 
Build: ffe_101625_220_lyra
Build Date: 10/16/2025
Windows Edition

Social Links:

GitHub: github.com/AVXAdvanced/FFE
X/Twitter: x.com/ffe_world
ProductHunt: producthunt.com/products/ffe

Made with <3 by AVX_Advanced
                         """)

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
                show_modern_error(self, "Nope", "Cannot delete a directory. Please Select a file.")
                return

            if os.path.exists(full_path):
                confirm = show_modern_question(self, "Sure?",
                                              f"Do you really want to get rid of '{os.path.basename(full_path)}'?")
                if confirm:
                    os.remove(full_path)
                    self.status_label.config(text=f"Yay it's gone.. one could say it's deleted!")
                    self.acc_files()
                    self.inc_stat("files_deleted", 1)
            else:
                show_modern_error(self, "Where'd it go?",
                                     "We couldn't find that file. You might not have sufficient permissions to modify it.")

        except IndexError:
            show_modern_error(self, "Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            show_modern_error(self, "Nope", f"Guess that one's staying. Couldn't delete {str(e)}")

    def update_ffe(self):

        try:
            current_version = "1.0.0"

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
                show_modern_info(self, "Hurray", "You're already up to date. No updates currently availible.")

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
