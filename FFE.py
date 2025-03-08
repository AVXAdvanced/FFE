from cryptography.fernet import Fernet
import os
import sys
import json
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
#                Version 1.0.0                  #
#          github.com/AVXAdvanced/FFE           #
#                                               #
#             (c)2025 AVX_Advanced              #
#             All Rights Reserved.              #
#################################################
#            Press ENTER to continue.           #
#################################################
""")
clear_console()

def fesys_err_backend():
    print(f"Current Info couldn't be loaded. This appears to be an issue on our side.")

def fesys_err_offline():
    print("Current Info couldn't be loaded. You seem to be offline.")

def fesys_txt_info (doc_id="13wX9-_44rq2-WzgpRfekaXaPu9l1i3kX5pAaSALqEeA"):
    url = f"https://docs.google.com/document/d/13wX9-_44rq2-WzgpRfekaXaPu9l1i3kX5pAaSALqEeA/export?format=txt"
    
    try:
        response = requests.get(url, timeout=5)  
        response.raise_for_status()  
        print(response.text.strip())  
    
    except requests.exceptions.ConnectionError:
        fesys_err_offline()
    
    except requests.exceptions.HTTPError as e:
        fesys_err_backend()

    except requests.exceptions.RequestException as e:
        fesys_err_backend()

def fesys_gen_key():
    return Fernet.generate_key()

def fesys_save_key(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def fesys_load_key(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

def fesys_encrypt_file(file_path, cipher):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_file_path = file_path + ".enc"
        encrypted_data = cipher.encrypt(file_data)
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)
        clear_console()
        input("""
#################################################
#       Success! Press ENTER to continue.       #
#################################################
""")
    except Exception as e:
        clear_console()
        input("""
#################################################
#      An error occoured. Please Try Again.     #
#          Press ENTER to continue.             #
#################################################
""")

def fesys_decrypt_file(file_path, keys):
    try:
        if not file_path.endswith(".enc"):
            clear_console()
            input("""
#################################################
#           That isn't a valid file.            #
#           Press ENTER to continue.            #
#################################################
""")
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
                key_str = key.decode() if isinstance(key, bytes) else key
                input("""
#################################################
#       Success! Press ENTER to continue.       #
#################################################
                         """)
                return
            except Exception:
                continue  
        clear_console()
        input("""
#################################################
#  You don't have permission to decrypt this.   #
#          Press ENTER to continue.             #
#################################################
""")
    except Exception as e:
        clear_console()
        input("""
#################################################
#      An error occoured. Please Try Again.     #
#          Press ENTER to continue.             #
#################################################
""")
      
# C/O        

def fesys_load_keys():
    if os.path.exists("keys.json"):
        with open("keys.json", "r") as keys_file:
            return json.load(keys_file)
    return []

# C/O

def ffe_help_info():
    fesys_txt_info("")
    input("""
################  - SUPPORT -  ##################
#                                               #
#          If you need help using FFE,          #
#        or you have a question about it,       #
#        visit github.com/AVXAdvanced/FFE       #
#                                               #  
#        There, you can check the Wiki,         #
#             or open a new issue.              #
#                                               #
#################################################
#  Press ENTER to go back to the home menu...   #
#################################################
""")

def ffe_key_transfer_guide():
    fesys_txt_info("")
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

def ffe_about():
    fesys_txt_info("")
    input("""
#################  - ABOUT -  ###################
#                                               #
#         FFE (Friend File Encryptor)           #
#                Version 1.0.0                  #
#            Build: FFE03072025LYEE             #
#                                               #                                               
#            (c)2025 AVX_Advanced               #
#            All Rights Reserved.               #
#                                               #
#################################################
#     Press ENTER to return to home menu.       #
#################################################
""")

def ffe_exit_msg():
    input("""
################### - EXIT - ####################
#                                               #
#          Thanks for using FFE today!          #
#           FFE is now ready to exit.           #
#                                               #
#              Have a nice day!                 #                  
#                                               #
#################################################
#             Press ENTER to exit.              #
#################################################
""")

def ffe_invld_opt():
    input("""
################## - ERROR - ####################
#                                               #
#           That option is invalid.             #
#                                               #
#     Please select an option from the menu     #
#                and try again.                 #                  
#                                               #
#################################################
#      Press ENTER to return to home menu.      #
#################################################
""")    

# If you're reading this, that means you actually took time to look through FFE's code. Nice! 
# (Un)Strategically placed by AVX_Advanced 

def ffe_main_menu():
    clear_console()
    fesys_txt_info("")
    print("""
################ - HOME MENU - ##################
#                                               #
#  1. Encrypt a File                            #
#  2. Decrypt a File                            #
#  3. Key Update Guide                          #                                             
#  4. Help & Support                            #
#  5. About                                     #
#  Q. Exit                                      #
#                                               #
#################################################
#          Type your selection below:           #
#################################################
""")
    choice = input("")
    return choice

def fesys_main():
    clear_console()

    if not os.path.exists("main_key.key"):
        input("""
################## - ERROR - ####################
#              No Main Key Found!               #
#################################################
#                                               # 
#        The main key file wasn't found.        #
#          This is normal if you just           #
#                installed FFE.                 #
#                                               #
#       If you updated FFE, close it now.       #
#       Go to 'C:/Program Files/FFE 0.8.0',     #
#      and replace the 'main_key.key' file      #
#              with the one from                #
#        your previous FFE installation.        #
#                                               #
#            Go to the FFE Wiki on              #
#        "github.com/AVXAdvanced/FFE"           #
#             for more information.             #                           
#                                               #
#################################################
#         A new Key File will be created.       #
#            Press ENTER to continue.           #
#################################################
""")
        clear_console()
        key = fesys_gen_key()
        fesys_save_key(key, "main_key.key")
        clear_console()
        input("""
################### - INFO - ####################
#                                               #
#      New Key File created successfully!       #
#                                               #                                               
#################################################                                               
#          Press Enter to continue...           #
#################################################
""")

    main_key = fesys_load_key("main_key.key")
    keys = fesys_load_keys()
    keys = [main_key.decode()] + keys 
    cipher = Fernet(main_key)

    while True:
        choice = ffe_main_menu()
        if choice == "1":
            clear_console()
            fesys_txt_info("")
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
            fesys_encrypt_file(file_to_encrypt, cipher)
            clear_console()
        elif choice == "2":
            clear_console()
            fesys_txt_info("")
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
            fesys_decrypt_file(file_to_decrypt, keys)
        elif choice == "4":
            clear_console()
            ffe_help_info()
        elif choice == "3":
            clear_console()
            ffe_key_transfer_guide()
        elif choice == "5":
            clear_console()
            ffe_about()      
        elif choice == "q":
            clear_console()
            ffe_exit_msg()
            clear_console()
            sys.exit()
        else:
            clear_console()
            ffe_invld_opt()

if __name__ == "__main__":
    fesys_main()
            
