from cryptography.fernet import Fernet
import os
import sys
import json

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
#                Version 0.6.0                  #
#          github.com/AVXAdvanced/FFE           #
#                                               #
#             (c)2025 AVX_Advanced              #
#################################################
#            Press ENTER to continue.           #
#################################################
""")
clear_console()

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
        input("""
#################################################
#       Success! Press ENTER to continue.       #
#################################################
""")
    except Exception as e:
        input("""
#################################################
#      An error occoured. Please Try Again.     #
#          Press ENTER to continue.             #
#################################################
""")

def fesys_decrypt_file(file_path, keys):
    try:
        if not file_path.endswith(".enc"):
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

        input("""
#################################################
#  You don't have permission to decrypt this.   #
#          Press ENTER to continue.             #
#################################################
""")
    except Exception as e:
        input("""
#################################################
#      An error occoured. Please Try Again.     #
#          Press ENTER to continue.             #
#################################################
""")
        
def fesys_load_keys():
    if os.path.exists("keys.json"):
        with open("keys.json", "r") as keys_file:
            return json.load(keys_file)
    return []

def ffe_help_info():
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
    input("""
#################  - ABOUT -  ###################
#                                               #
#         FFE (Friend File Encryptor)           #
#              Version 0.6.0 Beta               #
#             Build: FFE212025LYEE              #
#                                               #                                               
#            (c)2025 AVX_Advanced               #
#       Do not copy this program without        #
#      permission of the original creator.      #
#                                               #
#################################################
#     Press ENTER to return to home menu.       #
#################################################
""")

# If you're reading this, that means you actually took time to look through FFE's code. Nice! 
# (Un)Strategically placed by AVX_Advanced 

def ffe_main_menu():
    clear_console()
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
#             Enter your selection:             #
#################################################
""")
    choice = input("")
    return choice

def fesys_main():
    clear_console()

    if not os.path.exists("main_key.key"):
        key = fesys_gen_key()
        fesys_save_key(key, "main_key.key")
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
#         A new Key File will be created.       #
#            Press ENTER to continue.           #
#################################################
""")
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

    main_key = fesys_load_key("main_key.key")
    keys = fesys_load_keys()
    keys = [main_key.decode()] + keys 
    cipher = Fernet(main_key)

    while True:
        choice = ffe_main_menu()
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
            fesys_encrypt_file(file_to_encrypt, cipher)
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
            input("""
            #################################################
            #     That option isn't valid. Try Again.       #
            #     Press ENTER to return to Home Menu.       # 
            #################################################
            """)
            

if __name__ == "__main__":
    fesys_main()
            
