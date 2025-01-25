from cryptography.fernet import Fernet
import os
import sys
import time
import json
import psutil
import random
import requests


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')
    
clear_console()
input("""
#################################################
#                                               #
#            #######   #######   #######        #
#           ##        ##        ##              #
#          ######    #######   #######          #
#         ##        ##        ##                #
#        ##        ##        #######            #
#                                               #
#               Welcome to FFE!                 #
#                Version 0.5.1                  #
#          github.com/AVXAdvanced/FFE           #
#                                               #
#             (c)2025 AVX_Advanced              #
#################################################
#            Press ENTER to continue.           #
#################################################
""")
time.sleep(1.3)
clear_console()

def generate_random_key():
    return Fernet.generate_key()

def save_key(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def load_key(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

def encrypt_file(file_path, cipher):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_file_path = file_path + ".enc"
        encrypted_data = cipher.encrypt(file_data)
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)
        print("File encrypted successfully!")
    except Exception as e:
        print(f"Error during encryption: {e}")

def decrypt_file(file_path, keys):
    try:
        if not file_path.endswith(".enc"):
            print("The specified file is not an encrypted file.")
            return

        with open(file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()

        for key in keys:
            cipher = Fernet(key)
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
                decrypted_file_path = file_path[:-4]
                with open(decrypted_file_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)
                print(f"File decrypted successfully using key: {key.decode()}")
                return
            except Exception:
                continue  

        print("Decryption failed: No valid keys found.")
    except Exception as e:
        print(f"Error during decryption: {e}")

def replace_key():
    # Get the path of the script's folder
    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_key_path = os.path.join(script_dir, 'main_key.txt')  # Replace 'main_key.txt' with your actual filename

    # Ask for the new key
    new_key = input("Enter new key: ")

    # Replace the key in the file
    with open(main_key_path, 'w') as file:
        file.write(new_key)
    print(f"Key has been replaced in {main_key_path}.")

def change_main_key():
    new_key = generate_random_key()
    save_key(new_key, "main_key.key")
    print("Main key changed successfully!")

def load_keys():
    if os.path.exists("keys.json"):
        with open("keys.json", "r") as keys_file:
            return json.load(keys_file)
    return []

def save_keys(keys):
    with open("keys.json", "w") as keys_file:
        json.dump(keys, keys_file)

def add_key():
    new_key = generate_random_key()
    keys = load_keys()
    keys.append(new_key.decode())  
    save_keys(keys)
    print(f"New key added successfully: {new_key.decode()}")

def import_key():
    new_key_file = input("Enter the path of the key file to import: ")
    try:
        new_key = load_key(new_key_file)
        keys = load_keys()
        keys.append(new_key.decode())  
        save_keys(keys)
        print("Key imported successfully!")
    except Exception as e:
        print(f"Error importing the key: {e}")

def export_key():
    keys = load_keys()
    if not keys:
        print("No keys available to export.")
        return

    print("Available keys:")
    for idx, key in enumerate(keys):
        print(f"{idx + 1}: {key}")

    choice = int(input("Select the key number to export: ")) - 1
    if choice < 0 or choice >= len(keys):
        print("Invalid choice.")
        return

    key_to_export = keys[choice]
    export_path = input("Enter the path to save the exported .key file (e.g., exported_key.key): ")
    try:
        with open(export_path, "wb") as key_file:
            key_file.write(key_to_export.encode())
        print("Key exported successfully!")
    except Exception as e:
        print(f"Error exporting the key: {e}")

def manage_keys():
    keys = load_keys()
    if not keys:
        print("No keys available to manage.")
        return

    print("Current Keys:")
    for idx, key in enumerate(keys):
        print(f"{idx + 1}: {key}")

    choice = input("Enter the number of the key to PERMANENTLY DELETE it or 'q' to go back: ")
    if choice == 'q':
        return

    try:
        choice = int(choice) - 1
        if choice < 0 or choice >= len(keys):
            print("Invalid choice.")
            return

        keys.pop(choice)  
        save_keys(keys)   
        clear_console()
        print("Key deleted successfully!")
    except ValueError:
        clear_console()
        print("That doesn't seem right. Numbers only please!")

# If you're reading this, that means you actually took time to look through FFE's code. Nice! 
# (Un)Stragically placed by AVX_Advanced 

def main_menu():
    clear_console()
    print("""
################ - HOME MENU - ##################
#                                               #
#  1. Encrypt a File                            #
#  2. Decrypt a File                            #
#  3. Key Update Guide                          #                                             
#  4. Support FFE                               #
#  5. About                                     #
#                                               #
#################################################
#                   q. EXIT                     #
#################################################
""")
    choice = input("Enter your choice: ")
    return choice

def dev_menu():
    clear_console()
    print("""
############### - DEVELOPER MENU - ##############
#                                               #
#  1. Generate Random Key                       #
#  2. View current main key                     #
#  3. Advanced Version Info                     #
#                                               #
#################################################                                                                             
#              Q. EXIT DEV MENU                 #                                
#################################################                                 
""")
    choice = input("Enter your choice: ")
    return choice

def main():
    clear_console()

    if not os.path.exists("main_key.key"):
        key = generate_random_key()
        save_key(key, "main_key.key")
        input("""
################## - ERROR - ####################
#              No Main Key Found!               #
#################################################
#                                               # 
#        The main key file wasn't found         #
#          This is normal if you just           #
#                installed FFE.                 #
#                                               #
#   If you attempted to update your key file,   #
#     and you're seeing this please consult:    #
#                                               #
#     https://github.com/AVXAdvanced/FFE/       #
#                                               #
#                                               #
#################################################
#          A new Key File was created.          #
#            Press ENTER to continue.           #
#################################################
""")
        time.sleep(6)
        clear_console()
        input("""
################### - INFO - ####################
#                                               #
#      New Key File created successfully!       #
#                                               #
#      To use an external key file please       #
#        select "Key File Update Guide"         #
#              in the home menu.                #
#                                               #
#################################################                                               
#          Press Enter to continue...           #
#################################################
""")

    main_key = load_key("main_key.key")
    keys = load_keys()
    keys = [main_key.decode()] + keys 
    cipher = Fernet(main_key)

    while True:
        choice = main_menu()
        if choice == "1":
            clear_console()
            file_to_encrypt = input("""
################  - ENCRYPT - ###################
#          Here you can encrypt files.          #
#          Any file type is supported.          #
#                                               #
#      Remember to back up your key file.       #
#  If it's lost your files CANNOT be recovered. #
#                                               #
#################################################
#    Enter the path of the file you want to     #
#    encrypt or drag it here from explorer.     # 
#################################################
""")
            encrypt_file(file_to_encrypt, cipher)
            input("Press Enter to go back to the home menu...")
            clear_console()
        elif choice == "2":
            clear_console()
            file_to_decrypt = input("""
################  - DECRYPT - ###################
#          Here you can decrypt files.          #
#       You can only decrypt ".enc" files.      #
#                                               #
#      This will only work if you have the      #
#      matching key file to the file that       #
#             you wish to decrypt.              #
#                                               #
#################################################
#    Enter the path of the file you want to     #
#    decrypt or drag it here from explorer.     # 
#################################################
""")
            decrypt_file(file_to_decrypt, keys)
            input("Press Enter to go back to the home menu...")
        elif choice == "":
            replace_key()
        elif choice == "4":
            clear_console()
            print("We're glad to see that you are interested in supporting FFE!")
            print("There are many ways you can support the FFE project.")
            print("For example, you can:")
            print("")
            print("- Give us ideas or make new concepts")
            print("- Request changes or new features")
            print("")
            print("This is all possible in the FFE GitHub! There you can make comments, suggestions, and feature requests.")
            print("https://github.com/AVXAdvanced/FFE")
            print("")
            print("You can (and should) ask questions! I (or someone from the community) will surely answer them for you.")
            print("")
            print("Thanks for using FFE and considering to help us out!")
            print("")
            print("")
            input("Press Enter to go back to the home menu...")
        elif choice == "3":
            clear_console()
            input("""
############  - KEY UPDATE GUIDE -  #############
#                                               #
#      1. Locate your FFE install folder.       #
#   2. Drag your new key file into the folder.  #
#    3. If Windows tells you that file already  #
#           exists, select "Replace".           #
#                                               #
#         For more information, visit:          #
#          github.com/AVXAdvanced/FFE           #
#                                               #
#################################################
#  Press ENTER to go back to the home menu...   #
#################################################
""")
        elif choice == "":
            manage_keys()
            input("Press Enter to go back to the home menu...")
        elif choice == "5":
            clear_console()
            print("""
#################  - ABOUT -  ###################
#                                               #
#         FFE (Friend File Encryptor)           #
#              Version 0.5.1 Beta               #
#             Build: FFE1252025LYEE             #
#                                               #
#                                               #
#            (c)2025 AVX_Advanced               #
#       Do not copy this program without        #
#      permission of the original creator.      #
#                                               #
#################################################
""")
            input("Press Enter to go back to the home menu...")
                  
        elif choice == "":  
            while True:
                dev_choice = dev_menu()
                if dev_choice == "1":
                    clear_console()
                    random_key = generate_random_key()
                    print(f"Generated Key: {random_key.decode()}")
                    input("Press Enter to go back to the developer menu...")
                elif dev_choice == "2":
                    clear_console()
                    print(f"Current Main Key: {main_key.decode()}")
                    input("Press Enter to go back to the developer menu...")
                elif dev_choice == "3":
                    clear_console()
                    print("FFE - Friend File Encryptor Version 0.5.1B (English)")
                    print("Developer Beta")
                    print("Build: FFE1252025LYEE")
                    print("TUI (cmd-line) (pwrshell) Version")
                    print("Python Version 3.13.1 (64-Bit) ")
                    print("")
                    print("")
                    input("Press Enter to go back to the developer menu...")
                elif dev_choice == "q":
                    break
                elif dev_choice == "Q":
                    break
                else:
                    clear_console()
                    print("That choice ain't valid. Seems like you mistyped. Please retry.")
        elif choice == "q":
            clear_console()
            input("""
################### - EXIT - ####################
#                                               #
#         You have chosen to exit FFE.          #
#                                               #
#              Have a nice day!                 #                  
#                                               #
#################################################
#             Press ENTER to exit.              #
#################################################
""")
            clear_console()
            sys.exit()
        else:
            print("That choice ain't valid. Seems like you mistyped. Please retry.")
            input("Press Enter to go back to the main menu...")

if __name__ == "__main__":
    main()
            
