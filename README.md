# FFE (Friend File Encryptor)

FFE is a new (and easier) way to share files with your friends (or really anyone who you want) without other people taking a peek.

Practically, everyone who uses this program has his/her own Key File (also known as main_key). If you have a friend group of 3, for example, everyone shares their 
key files with everyone. If you then encrypt a file (encryption will always accour from the main_key) your friends will also have your key file, which means that
all of your friends can open your file. 

FFE supports a single main key (which is changable) and up to 25 extra key files.

FFE is written in Python, and is fairly lightweight and meant to be accessible for everyone.
The Requirements will most likely decrease as testing goes on.

A Linux Build is in development, and macOS support is in consideration. (Linux is currently higher priority due to ChromeOS and me being able to test better on Linux)
Remember that Linux support may vary upon the distro you're using, but as it comes out feel free to test on other distros, as i'd highly appreciate it! :)

The program currently supports Windows (x64/x86) only.

FFE requires the following:

 Windows 8 (x64/x86) or higher
 Microsoft Visual C++ 2015 Redistributable (x64/x86) - 14.0.23026 or higher.
 500 MB Availible HDD/SSD space or more

FFE features a basic malware detection feature (due to the vulnerabilities in Python) that informs you upon startup if suspicious programs are found running.
Please report any known malware here in the GitHub (under issues preferrably) so I can make FFE safer for everyone.

FFE is currently in Open Beta so please expect and report bugs/errors here in the GitHub so I can fix them.
Remember, fixing bugs may take a while, but I will try my best! :)

Thanks for considering FFE!
