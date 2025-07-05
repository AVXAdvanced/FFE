import os
import requests
import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from packaging import version
import re
import webbrowser
import threading

def fesys_gen_key():
    return Fernet.generate_key()


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


class FFEApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Friend File Encryptor - Version 2.1.0")
        self.geometry("1070x800")
        self.configure(bg="#0a1124")
        self.minsize(1070, 800)

        self.main_key = self.load_main_key()

        self.current_path = "C:/"
        self.history = [self.current_path]
        self.history_index = 0
        self.file_listbox = tk.Listbox(self, bg="#0f1936", fg="white", selectmode=tk.SINGLE, font=("Segoe UI", 12),
                                       selectbackground="#2a4180", selectforeground="white")
        self.file_listbox.bind("<Double-1>", self.file_dc_act)
        self.create_widgets()
        self.acc_files()
        self.decrypting = False
        self.hovered_index = None
        self.brighten_factor = 20

        self.ffe_websrv_chk("https://www.github.com/AVXAdvanced/FFE", self.no_ffe_web)

    def no_ffe_web(self):
        messagebox.showwarning("Online Features Unavailable", """FFE's Online Features aren't available.

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
        toolbar.columnconfigure(2, weight=1)

        self.back_button = HoverButton(toolbar, text=" Back ", command=self.go_back, state=tk.DISABLED,
                                       bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.back_button.pack(side=tk.LEFT, padx=5)

        self.forward_button = HoverButton(toolbar, text=" Forward ", command=self.go_forward, state=tk.DISABLED,
                                          bg="#203161", fg="white", relief="flat", font=("Segoe UI", 11))
        self.forward_button.pack(side=tk.LEFT, padx=5)

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

        update_button = HoverButton(toolbar, text=" Update ", command=self.update_ffe, bg="#203161", fg="white",
                                    relief="flat", font=("Segoe UI", 11))
        update_button.pack(side=tk.LEFT, padx=5, pady=8)

        help_button = HoverButton(toolbar, text=" Help ", command=self.show_help, bg="#203161", fg="white",
                                  relief="flat", font=("Segoe UI", 11))
        help_button.pack(side=tk.LEFT, padx=5, pady=8)

        about_button = HoverButton(toolbar, text=" About ", command=self.show_about, bg="#203161", fg="white",
                                   relief="flat", font=("Segoe UI", 11))
        about_button.pack(side=tk.LEFT, padx=5, pady=8)

        self.status_label = tk.Label(self, text="Select a file to encrypt. Double click folders to navigate.",
                                     bg="#0a1124", fg="white", font=("Segoe UI", 11))
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

    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.current_path = self.history[self.history_index]
            self.acc_files()

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
            messagebox.showwarning("Key File Missing", """FFE has created a new Key File.

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
                messagebox.showerror("Nope", "Can't encrypt a directory. Select a file.")
                return

            result = fesys_encrypt_file(full_path, self.main_key)
            self.status_label.config(text=result)
            self.acc_files()

        except IndexError:
            messagebox.showerror("Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            messagebox.showerror("Nope", f"Welp, we couldn't encrypt that one: {str(e)}")

    def decrypt_file(self):
        if self.decrypting:
            return
        self.decrypting = True

        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                messagebox.showerror("Nope", "Can't decrypt a directory. Please Select a file.")
                self.decrypting = False
                return

            if not full_path.endswith(".enc"):
                messagebox.showerror("Nope", "Only .enc files can be decrypted.")
                self.decrypting = False
                return

            result = fesys_decrypt_file(full_path, self.main_key)
            self.status_label.config(text=result)
            self.acc_files()

        except IndexError:
            messagebox.showerror("Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            messagebox.showerror("Nope", f"Failed to decrypt file: {str(e)}")
        finally:
            self.decrypting = False

    def show_about(self):
        messagebox.showinfo("About Friend File Encryptor", """Friend File Encryptor  -  FFE

Version 2.1.0 
Build: ffe_070525_210_lyra
MFHC: FFE-LYRA 
Build Date: 7/5/2025
Windows Edition

"Begging for less compiler errors"

Social Links:

GitHub: github.com/AVXAdvanced/FFE
X/Twitter: x.com/ffe_world
ProductHunt: producthunt.com/products/ffe

Made with <3 by AVX_Advanced
                         """)

    def show_help(self):
        response = messagebox.askyesno("Need Help?", """    Need Help using FFE?

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

        if response == tk.YES:
            webbrowser.open_new("https://github.com/AVXAdvanced/FFE")

    def del_f(self):
        try:
            selected_index = self.file_listbox.curselection()[0]
            full_path = self.file_paths[selected_index]

            if os.path.isdir(full_path):
                messagebox.showerror("Nope", "Cannot delete a directory. Please Select a file.")
                return

            if os.path.exists(full_path):
                confirm = messagebox.askyesno("Sure?",
                                              f"Do you really want to get rid of '{os.path.basename(full_path)}'?")
                if confirm:
                    os.remove(full_path)
                    self.status_label.config(text=f"Yay it's gone.. one could say it's deleted!")
                    self.acc_files()
            else:
                messagebox.showerror("Where'd it go?",
                                     "We couldn't find that file. You might not have sufficient permissions to modify it.")

        except IndexError:
            messagebox.showerror("Where'd it go?",
                                 "You haven't selected a file. Please select one before continuing.")
        except Exception as e:
            messagebox.showerror("Nope", f"Guess that one's staying. Couldn't delete {str(e)}")

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
                messagebox.showerror("Error",
                                     "An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually.")
                return

            if version.parse(latest_version) > version.parse(current_version):
                confirm = messagebox.askyesno("Update Available", f"""Version {latest_version} is available. 

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
                messagebox.showinfo("Hurray", "You're already up to date. No updates currently availible.")

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Update Error",
                                 f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"Error checking updates: {e}")
        except KeyError as e:
            messagebox.showerror("Update Error",
                                 f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"Error parsing GitHub API: {e}")
        except Exception as e:
            messagebox.showerror("Update Error",
                                 f"An error occurred. Head to github.com/FFE/AVXAdvanced to check for updates manually. Error Code: {e}")
            self.status_label.config(text=f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    app = FFEApp()
    app.mainloop()
