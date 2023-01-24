"""Coursework for 667V0033 1CWK50
Student name: Moses Oghenegare Kelvin
Student ID: 22540149@stu.mmu.ac.uk
This application was developed using code samples from:
30% Lecturer provided enc.py
5% https://leimao.github.io/blog/Python-Send-Gmail/ (Used this to send the AWS KMS generated key ID to the user encrypting the file or folder for secure storage)
20% https://docs.aws.amazon.com/kms/latest/developerguide/overview.html (Had to read and follow the documentation to execute using AWS KMS to encrypt the private key)
20% https://www.udemy.com/course/100-days-of-code/  (My Personal development following Tutor Angela Yu)
10% https://stackoverflow.com/  (Needed to create random alias so user dont have to specify, checked stackoverflow to solution)

All comments are original
"""

import sys
from globe import Kelvin


options = ['0. Generate Your Unique ID ','1. Generate RSA key', '2. Folder Encryption', '3. Folder Decryption', '4. File Encryption', '5. File Decryption', '6. Exit']

while True:
    print("Please select an option:")
    for i in range(len(options)):
        print(options[i])

    selection = int(input("~Python3: "))

    if selection == 0:
        kel= Kelvin()
        Kelvin.generate_id()
    elif selection == 1:
        rsa = Kelvin()
        Kelvin.generate_new_keys()
    elif selection == 2:
        enc = Kelvin()
        Kelvin.folder_encryption()
    elif selection == 3:
        dec = Kelvin()
        Kelvin.decrypt_new_folder()
    elif selection == 4:
        enc = Kelvin()
        Kelvin.encrypt_new_file()
    elif selection == 5:
        dec = Kelvin()
        Kelvin.decrypt_new_file()
    elif selection == 6:
        sys.exit()
    else:
        print('selection not available')
