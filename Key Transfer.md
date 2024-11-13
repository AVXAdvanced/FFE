# Encryption/Decryption Key Transfer Guide

When you upgrade FFE all of your Key Files would be gone. If you want to keep them, please follow this guide carefully.

**1. Install the FFE update**

First, Install FFE as you would normally. The default Install folder is:

C:\Users\[Your Windows User Name]\AppData\Local\Programs\FFE [Version Number]

DO NOT START THE PROGRAM YET!

**2. Navigate to your old Installation folder**

Now, navigate to the installation folder of the older install of FFE. The folder path will look something like:

C:\Users\[Your Windows User Name]\AppData\Local\Programs\FFE [Version Number]

**3. Copy Required Files**

When you have navigated to the correct folder, copy the following files:

main_key.key (Required)
keys.json (If any other keys were added. Version 0.6.0 or higher only. If this file doesnt exsist, don't worry.)

**4. Navigate to your new Installation Folder**

When you have copied the file(s) navigate to your NEW installation folder. This should look something like this:

C:\Users\[Your Windows User Name]\AppData\Local\Programs\FFE [Version Number]

Here, paste the file(s) into the root of the folder.

**Done!**

If you've done everything correctly, FFE should start without any errors. If FFE reports no Key File Found, check that main_key.key is in the root of the folder "FFE [Version Number]".

Now, you don't have to give your friends new files! :)
