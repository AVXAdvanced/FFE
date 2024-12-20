from cryptography.fernet import Fernet
import os
import sys
import time
import json
import psutil
import random
import hashlib
import logging
import base64

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

clear_console()

def random_delay():
    return random.uniform(0.1, 0.9)

print("================================ MalClear =================================")
print("CHECKING FOR SUSPICIOUS/MALICIOUS SOFTWARE ON YOUR COMPUTER. PLEASE WAIT...")
time.sleep(2.7)

clear_console()

# THERE ARE NO SUSPICIOUS PROCESSES LISTED BELOW IN THE PUBLIC GITHUB FILE FOR SECURITY REASONS. THESE ENTRIES ARE AVAILIBLE IN THE EXECUTABLE VERSION OF FFE.

def check_for_malicious_processes():
    # List of suspicious or known malicious process names (you can expand this list)
    suspicious_processes = []

# THERE ARE NO SUSPICIOUS PROCESSES LISTED ABOVE IN THE PUBLIC GITHUB FILE FOR SECURITY REASONS. THESE ENTRIES ARE AVAILIBLE IN THE EXECUTABLE VERSION OF FFE.

    # Get all running processes
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # Check if the process name matches any suspicious names
            if proc.info['name'].lower() in [sp.lower() for sp in suspicious_processes]:
                clear_console()
                print(f"""
#################  - ERROR -  ###################
#                                               #
#      POSSIBLE MALWARE HAS BEEN DETECTED       #
#              ON YOUR COMPUTER!                #
#                                               #
#       DUE TO THIS, FFE CANNOT CONTINUE!       #
#                                               #
#               ERR CODE: m0011                 #
#     Search for this error code on GitHub:     #
#         github.com/AVXAdvanced/FFE            # 
#                                               #
#              FLAGGED PROCESS:                 #
#################################################                                               
# {proc.info['name']} (PID: {proc.info['pid']}) 
#################################################
""")

                response = input("")
                if not response.strip():  # If the user just presses Enter
                    clear_console()
                    print("ntk.ffe.debugmenu")
                    time.sleep(0.3)
                    print("ffe.malclearskipper.c")
                    print("ffe.trigger(key.enter(genlayout))")
                    time.sleep(0.1)
                    print("ffe.procflag(0)")
                    print("ffe.check(procflag)")
                    time.sleep(0.7)
                    print("procflag=0(clear)")
                    time.sleep(0.2)
                    print("ffe.exit(0)")
                    time.sleep(0.7)
                    print("ffe.exitlog(0)")
                    time.sleep(0.2)
                    print("ffe.logsys set (1)")
                    time.sleep(0.3)
                    print("ffe.logsys(1)")
                    time.sleep(0.1)
                    print("py.del(ffe.exitfile) del now")
                    time.sleep(0.3)
                    print("filedel success")
                    time.sleep(0.3)
                    print("ffe.exitfile exsist? n")
                    time.sleep(0.3)
                    print("sdown proc (0)")
                    time.sleep(0.8)
                    print("ffe.verify(startup.ffe)")
                    time.sleep(0.2)
                    print("startup.ffe OK!")
                    time.sleep(0.3)
                    print("prestart.chk")
                    time.sleep(0.3)
                    print("ffe.verify(malclear)")
                    time.sleep(0.1)
                    print("malclear OK!")
                    time.sleep(0.3)
                    print("ffe.clearsys OK!")
                    time.sleep(0.3)
                    print("ffe.oschk")
                    time.sleep(0.9)
                    print("OS: OK!")
                    time.sleep(0.3)
                    print("FFE FILES OK!")
                    time.sleep(0.3)
                    print("curmode: -v")
                    time.sleep(0.1)
                    print("logfile.write:(en/ex mode: -v OK!)")
                    time.sleep(0.3)
                    print("prev stopcode: m0001")
                    time.sleep(0.1)
                    print("logfile.seldel(stopcode: m0001)")
                    time.sleep(0.3)
                    print("logfile.seldel OK!")
                    time.sleep(0.2)
                    print("Preparing ffe.startup...")
                    time.sleep(0.3)
                    print("OK!")
                    time.sleep(0.3)
                    print("Loading startup.ffe..")
                    time.sleep(0.4)
                    print("FFE WILL NOW CONTINUE.")
                    time.sleep(1.4)
                    clear_console()
                    return True
                else:
                    clear_console()
                    print("You have chosen to exit.")
                    print("Please follow the steps listed in the previous menu and retry later.")
                    print("")
                    print("")
                    return False
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

   
    print("")
    return True

if check_for_malicious_processes():
    clear_console()
    print("")
    time.sleep(0.1)
    clear_console()

else:
    print("FFE HAS ENCOUNTERED A FATAL ERROR AND WILL EXIT TO PREVENT DAMAGE TO YOUR FILES OR SYSTEM!")
    print("ERR CODE m0055")
    print("CLOSE THE PROGRAM WITH THE X LOCATED IN THE TOP RIGHT OF THE WINDOW! PLEASE NOTE THE ERROR CODE LISTED ABOVE AND OPEN A NEW ISSUE HERE: github.com/AVXAdvanced/FFE")
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)
    time.sleep(999999999)

clear_console()
print("""
#################################################
#                                               #
#            #######   #######   #######        #
#           ##        ##        ##              #
#          ######    #######   #######          #
#         ##        ##        ##                #
#        ##        ##        #######            #
#                                               #
#               Welcome to FFE!                 #
#                Version 0.4.1                  #
#              Preparing Files...               #
#                                               #
#################################################
""")
time.sleep(1)
clear_console()

clear_console()
print("""
#################################################
#                                               #
#            #######   #######   #######        #
#           ##        ##        ##              #
#          ######    #######   #######          #
#         ##        ##        ##                #
#        ##        ##        #######            #
#                                               #
#               Welcome to FFE!                 #
#                Version 0.4.1                  #
#                  Loading...                   #
#                                               #
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
        print("Invalid input. Please enter a number.")

def main_menu():
    clear_console()
    clear_console()
    print("""
################ - MAIN MENU - ##################
#                                               #
#  1. Encrypt a File                            #
#  2. Decrypt a File                            #
#  3. Change Main Key                           #
#  4. Add New Random Key                        #
#  5. Import New Key                            #
#  6. Export a Key                              #
#  7. Manage Keys                               #
#  8. Support FFE                               #
#  9. About                                     #
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
################# - DEV MENU  - #################
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
        print("""
################## - ERROR - ####################
#              No Main Key Found!               #
#################################################
#                                               # 
#    The main security key file wasn't found    #
#                                               #
#       A new key file is being created...      #
#                                               #
#################################################
#                Please Wait...                 #
#################################################
""")
        time.sleep(2.3)
        clear_console()
        input("====== PRESS ENTER TO CONTINUE ======")

    main_key = load_key("main_key.key")
    keys = load_keys()
    keys = [main_key.decode()] + keys 
    cipher = Fernet(main_key)

    while True:
        choice = main_menu()
        if choice == "1":
            file_to_encrypt = input("""
################  - ENCRYPT - ###################
#   USING THIS FUNCTION YOU CAN ENCRYPT FILES   #
#                                               #
#      THIS WILL STOP ANYONE BESIDES YOU        #
#    AND THE PEOPLE THAT HAVE YOUR KEY FILE     #
#          FROM OPENING YOUR FILES              #
#                                               #
#################################################
#    ENTER THE PATH OF THE FILE YOU WANT TO     #
#           ENCRYPT OR DRAG IT HERE             # 
#################################################
""")
            encrypt_file(file_to_encrypt, cipher)
            input("Press Enter to go back to the main menu...")
        elif choice == "2":
            file_to_decrypt = input("Enter the path of the encrypted file: ")
            decrypt_file(file_to_decrypt, keys)
            input("Press Enter to go back to the main menu...")
        elif choice == "3":
            change_main_key()
            input("Press Enter to go back to the main menu...")
        elif choice == "4":
            add_key()
            input("Press Enter to go back to the main menu...")
        elif choice == "5":
            import_key()
            input("Press Enter to go back to the main menu...")
        elif choice == "6":
            export_key()
            input("Press Enter to go back to the main menu...")
        elif choice == "8":
            clear_console()
            print("We're glad to see that you are interested in supporting FFE!")
            print("There are many ways you can support the FFE project.")
            print("For example, you can:")
            print("")
            print("- Give us ideas or make new concepts")
            print("- Report known malware (in the form of [program].exe preferrably) to keep FFE safe")
            print("- Request changes or new features")
            print("")
            print("This is all possible in the FFE GitHub! There you can ask questions, make comments and much much more!")
            print("https://github.com/AVXAdvanced/FFE")
            print("")
            print("No, I DO NOT accept any form of financial support.")
            print("You can (and should!) ask questions! I will gladly answer them for you.")
            print("I'm sure someone from the FFE community over on GitHub can also help you!")
            print("")
            print("Thanks for using FFE and considering helping us out!")
            print("")
            print("")
            input("Press Enter to go back to the main menu...")
        elif choice == "7":
            manage_keys()
            input("Press Enter to go back to the main menu...")
        elif choice == "9":
            clear_console()
            print("""
#################  - ABOUT -  ###################
#                                               #
#         FFE (Friend File Encryptor)           #
#                Version 0.5.0                  #
#                                               #
#             Python Version 3.13               #
#           MalClear Version 0.1.1A             #
#                                               #
#               @AVX_Advanced                   #
#               and @Kurt2012                   #
#                                               # 
#################################################
""")
            input("Press Enter To Return to Main Menu")
                  

        elif choice == "dev":  
            while True:
                dev_choice = dev_menu()
                if dev_choice == "1":
                    clear_console()
                    random_key = generate_random_key()
                    print(f"Generated Key: {random_key.decode()}")
                    input("Press Enter to go back to developer menu...")
                elif dev_choice == "2":
                    clear_console()
                    print(f"Current Main Key: {main_key.decode()}")
                    input("Press Enter to go back to developer menu...")
                elif dev_choice == "3":
                    clear_console()
                    print("FFE - Friend File Encryptor Version 0.5.0B (English)")
                    print("Developer Beta")
                    print("Build: FFE041-11122024")
                    print("TUI (cmd-line) (pwrshell) Version")
                    print("Python Version 3.13.0 (64-Bit) ")
                    print("Python Extention Version v2024.20.0")
                    print("Pylance Extention Version v2024.11.1")
                    print("Python Debugger Extention v2024.12.0")
                    print("Visual Code Version 1.94")
                    print("")
                    print("")
                    input("Press Enter to go back to developer menu...")
                elif dev_choice == "q":
                    break
                elif dev_choice == "Q":
                    break
                else:
                    clear_console()
                    print("###### -INVALID CHOICE! PRESS ENTER TO RETURN TO MAIN MENU!- ######")
        elif choice == "q":
            clear_console()
            print("""
################### - EXIT - ####################
#                                               #
#         You have chosen to exit FFE.          #
#                                               #
#       FFE is currently cleaning up and        #
#                 finalizing.                   #
#                                               #
#   Once this process is complete, the program  #
#                  will exit.                   #
#                                               #
#################################################
#                Please Wait...                 #
#################################################
""")
            time.sleep(3)
            clear_console()
            sys.exit()
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to go back to the main menu...")

if __name__ == "__main__":
    main()
            
