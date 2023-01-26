"""Coursework for 667V0033 1CWK50
Student name: Moses Oghenegare Kelvin
Student ID: 22540149
This application was developed using code samples from:
30% Lecturer provided enc.py
5% https://leimao.github.io/blog/Python-Send-Gmail/ (Used this to send the AWS KMS generated key ID to the user encrypting the file or folder for secure storage)
20% https://docs.aws.amazon.com/kms/latest/developerguide/overview.html (Had to read and follow the documentation to execute using AWS KMS to encrypt the private key)
10% https://www.udemy.com/course/100-days-of-code/  (My Personal development following Tutor Angela Yu)
10% https://stackoverflow.com/  (Needed to create random alias so user dont have to specify, checked stackoverflow for solution)
15% Original code from me
10% Group input by (Anuoluwa Osunjuyigbe - 22552903, Akiniyi Akingbile - 22492631, Olunmide Adesola-Bammeke -22553796)

All comments are original
"""
import os
from pathlib import Path
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import boto3
import random
import string
import smtplib, ssl
from email.message import EmailMessage

# Firstly I create a boto3 session with my AWS access key Id and secret access key and then specified the region
# This is done so that my python script will have the neccessary permision to update my AWS KMS Customer Managed Keys list
session = boto3.Session(
    #For the purpose of making this public i am removing values of the AWS access key 
    aws_access_key_id='A**********************',
    #For the purpose of making this public i am removing values of the AWS secret key
    aws_secret_access_key='***********************',
    region_name='us-east-1'
)

# This Creates the boto3 KMS client we will be using for our connection to Aws KMs
client = session.client('kms')

#I then create a  class named Kelvin where all my methods that will be called in app.py will be defined. 
class Kelvin:
        
    #This method is to generate the AWS KMS Key that would be used to envelope the RSA private key on the user machine to add extra security
    def generate_id():
        # We have to set the alias of the key we want to create
        # This line of code Generate a random word 
        random_word = ''.join(random.choices(string.ascii_letters, k=5))

        # This line of code generates a random number
        random_number = random.randint(0, 100)

        # This line then Concatenate the random word and number
        random_word_number = random_word + str(random_number)

        # This line then Concatenate the prefix of our AWS KMS alias and the random_word_number we just generated
        alias = 'alias/py-'+ random_word_number

        #This line prompts the user for an Input because I want my application to send the ID of the AWS Key we are creating 
        #To their Email Address for safe keeping
        receiver_email =  input("please input the email address your unique ID will be sent to:")
        # This line Creates the key
        response = client.create_key(
        KeyUsage='ENCRYPT_DECRYPT',
        )

        # We Get the key ID of the new key and save it in a vairable named key_id
        key_id = response['KeyMetadata']['KeyId']


        # This function Creates an alias for the key we want to create collecting two arguments, 
        # The alias we specified on line 97 and the key_id generated on like 108
        client.create_alias(
        AliasName=alias,
        TargetKeyId=key_id
        )

        #This line then prints the unique ID to the terminal and informs the user that the key ID has been sent to their email
        print(f'Unique Key created with ID: {key_id} and has been sent to your email address {receiver_email}')

        #We set up Gmail smtp with the following settings
        #Firstly we input the port for SSL secure connection
        port = 465
        #Then the smtp gmail server
        smtp_server = "smtp.gmail.com"
        #Here we put in the a dummy email for the public version so I don't get spams
        sender_email = "k*********0@gmail.com"
        #To have this script always run without asking for password we created an APP password in my google account
        #Again to protect my account from intrusion i'd be replacing the password with astericks for the public repository 
        password = "****************************"

        #Here I set the details for the message that will be sent to the user
        msg = EmailMessage()
        msg.set_content(f'Your Unique Key  ID is: {key_id} please keep this information safe')
        msg['Subject'] = "Kelvin Moses Encryption App"
        msg['From'] = sender_email
        msg['To'] = receiver_email

        #This uses all the information we have inputed to set up a connection and send the email
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.send_message(msg, from_addr=sender_email, to_addrs=receiver_email)

    #This method generates new RSA Keys that would be used for Encrypting and Decrypting Folders and Files
    def generate_new_keys():
       
        #This lines prompts the  user for the directory path to save the public and private keys
        dir_path = input('Enter a new folder name or specify a path to save an encrypted version of your keys: ')
        key = RSA.generate(2048)
        os.makedirs(dir_path, exist_ok=True)
        
        #Thes lines of code will save private key (temporarily) in specified directory
        private_key = key.export_key()
        file_out = open(os.path.join(dir_path,"private.pem"), "wb")
        file_out.write(private_key)
        file_out.close()

        #This starts the process of encrypting the private key using the generated AWS keys
        key_id =input("Input Unique Encryption ID: \n")

        # This code reads the private key file that was stored plainly
        file_path= dir_path + '/private.pem'
        with open(file_path, 'rb') as f:
            plaintext = f.read()

    # We now Encrypt the file using the key attached to the ID that we inputed on line 53
        response = client.encrypt(KeyId=key_id, Plaintext=plaintext)

     # After the encryption is done, this code deletes the exposed generated private key
        file_path = os.path.join(dir_path,"private.pem")
        if os.path.exists(file_path):
             os.remove(file_path)
        else:
            print(f"oops! There is an error, please start again!")

    # Then writes an encrypted version of the private key to a new file
        with open(file_path, 'wb') as f:
            f.write(response['CiphertextBlob'])

        #This Lines of code is used to save public key in specified directory, we do not encrypt the public key as it cant be used to decrypt a file.
        public_key = key.publickey().export_key()
        file_out = open(os.path.join(dir_path,"public.pem"), "wb")
        file_out.write(public_key)
        file_out.close()
    
      #This line then prints the unique ID to the terminal and informs the user that the key ID has been sent to their email
        print('RSA Pulblic and Private Keys Generated Successfully!')

   #Here I create a method to handle folder encryption
    def folder_encryption():
        #We prompt the user for the following inputs
        print('Note that if the folder or files you want to encrpty are in the same directory as your terminal root all you have to do is input the file or folder name \n')
        Directory = input("Enter the folder name path you wish to encrypt: (use / instead of \ ):  ")
        dir_path = input('Enter the folder name or path of the folder you wish to save your encrypted Files to (use / instead of \ ):  ')
        receiver = input('Please enter the recepient public key file name or path with the correct file extention (use / instead of \ ):  ')
        #This line checks if the folder you want to save your encrypted files to already exists
        os.makedirs(dir_path, exist_ok=True)
        
        #This line checks if the folder you inputed for encryption is indeed a directory
        assert Path(Directory).is_dir()
        for new_path in sorted(Path(Directory).iterdir(), key=lambda p: str(p).lower()):
            with open(new_path, 'rb') as p:
                new_file_name = os.path.basename(new_path)
                #This line sets the name for the new encrypted file
                encrypted_path_text = 'encrypted_' + new_file_name
                #This line reads the public RSA key that was inputed                     
                recipient_key = RSA.import_key(open(receiver).read())
                AES_key_generate = get_random_bytes(32)

                rsa_cipher = PKCS1_OAEP.new(recipient_key) 
                enc_AES_key = rsa_cipher.encrypt(AES_key_generate)

                File_to_encrypt = p.read()
                File_to_encrypt = bytearray(File_to_encrypt) 

                aes_cipher = AES.new(AES_key_generate, AES.MODE_EAX)
                # This Encrypts the file and generates the Cipher text and the hash functions
                ciphertext, tag = aes_cipher.encrypt_and_digest(File_to_encrypt) 
                # We now open the file that was just created 
                encrypted_path_object = open(os.path.join(dir_path,encrypted_path_text), 'wb')
                # And then store our results to the file that we just opened 
                [ encrypted_path_object.write(x) for x in (enc_AES_key, aes_cipher.nonce, tag, ciphertext) ] 
                encrypted_path_object.close() 
                p.close()
        print('Encryption Complete! Check the Directory you input for your encrypted files') 

    #Here i create a method to handle folder decyption 
    def decrypt_new_folder():
            
            # Prompt user for the directory that contains the encrypted files
            print('Note that if the folder or files you want to decrpty are in the same directory as your terminal root  all you have to do is inpute the file or folder name \n')
            encrypted_dir = input('Enter the encrypted folder path or name: ')
            dir_path = input('Enter an existing folder name or path of the folder you wish to save your encrypted Files to (use / instead of \ ):  ')
            # Prompt user for RSA private key
            private_key_path = input('Enter the private key name or path :  ')
            assert Path(encrypted_dir).is_dir()
            with open(private_key_path , 'rb') as f:
                plaintext = f.read()

            # This gets the unique AWS KMS Key ID
            key_id = input("Input your Unique Key ID: \n")
            # Decrypt the file using credentials from AWS KMS
            response = client.decrypt(CiphertextBlob=plaintext)

            # Write the decrypted private key data to a new file
            with open(private_key_path, 'wb') as f:
                f.write(response['Plaintext'])
            
            # The following lines of code uses the decrypted RSA private key to decrypt the encrypted files

            for new_path in sorted(Path(encrypted_dir).iterdir(), key=lambda p: str(p).lower()):
                with open(new_path, 'rb') as encrypted_file:
                    new_file_name = os.path.basename(new_path)   
                    decrypted_file_text = 'decrypted_' + new_file_name
                    # We now open the file that was just created 
                    decrypted_file_object = open(os.path.join(dir_path,decrypted_file_text), 'wb')

                    private_key = RSA.import_key(open(private_key_path).read())
                    enc_AES_key,nonce, tag,ciphertext = \
                    [encrypted_file.read(x) for x in (private_key.size_in_bytes(),16,16,-1) ]

                    # Decrypt the session key with the decrypted private RSA key
                    cipher_rsa = PKCS1_OAEP.new(private_key)
                    AES_key = cipher_rsa.decrypt(enc_AES_key)

                    # Decrypt the data with the AES session key
                    cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
                    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                    decrypted_file_object.write(data)
                    decrypted_file_object.close()  
            print('Decryption Complete! Check the Root Directory For Your decrypted files') 
            
            #The following lines of code encrypts the temporarily exposed private key
            # Read the RSA private key
            file_path= private_key_path
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            # Gives access to Encrypt the private key using the AWS KMS ID
            response = client.encrypt(KeyId=key_id, Plaintext=plaintext)

            # Delete the exposed generated RSA private key
            if os.path.exists(file_path):
                    os.remove(file_path)
            else:
                print(f"oops! There is an error, please start again!")

            # Write the encrypted data to a new file
            with open(file_path, 'wb') as f:
                f.write(response['CiphertextBlob'])

    #This method encrypts a file using AES and RSA
    def encrypt_new_file():
           
            print('Note that if the folder or files you want to decrpty are in the same directory as your terminal root  all you have to do is inpute the file or folder name \n')
            # Prompt user for file path to encrypt
            file_path = input("Enter the file name or file path you wish to encrypt (use / instead of \ ): ")
            # Prompt user for directory to save the encrypted file
            dir_path = input('Enter the Directory Path you wish to save your encrypted Files(use / instead of \ ): ')
            # Prompt user for the recipient's public key
            receiver_key_path = input('Please enter the recepient public key file name or path with the correct file extention (use / instead of \ ): ')
            # Create the directory if it doesn't exist
            os.makedirs(dir_path, exist_ok=True)
            with open(file_path, 'rb') as original_file:
                # Read the contents of the file you want to encrypt
                original_file_contents = original_file.read()
                # Create a new file name for the encrypted file
                encrypted_file_name = 'encrypted_' + os.path.basename(file_path)                     
                # Import the generated RSA public key
                recipient_key = RSA.import_key(open(receiver_key_path).read())
                # This line generates a new AES key
                AES_key_generate = get_random_bytes(32)
                # Create an RSA cipher with the public key imported on line 266
                rsa_cipher = PKCS1_OAEP.new(recipient_key) 
                enc_AES_key = rsa_cipher.encrypt(AES_key_generate)
                original_file_contents = bytearray(original_file_contents) 
                aes_cipher = AES.new(AES_key_generate, AES.MODE_EAX)
                # Encrypting the file and generating the Cipher text and the hash digest
                ciphertext, tag = aes_cipher.encrypt_and_digest(original_file_contents)
                # opening the file just created 
                encrypted_path_object = open(os.path.join(dir_path,encrypted_file_name), 'wb') 
                # This line now stores the result in a file
                [ encrypted_path_object.write(x) for x in (enc_AES_key, aes_cipher.nonce, tag, ciphertext) ] 
                encrypted_path_object.close() 
                original_file.close()
            print('Encryption Done! Check the Directory you input for your encrypted file') 

    #This method decrypts a file
    def decrypt_new_file():
            
            # Prompt user for file path to decrypt
            file_path = input('Enter the encrypted file name or  path (use / instead of \ ): ')
            #This line gets the location you want to save the encrpyted file to
            dir_path = input('Enter an existing folder name or folder path you wish to save your encrypted Files to (use / instead of \ ):  ')
            # Prompt user for RSA private key
            private_key_path = input('Enter the private key name or path : ')
            with open(private_key_path , 'rb') as f:
                plaintext = f.read()
            # This line gets the AWS KMS Encryption key ID
            key_id = input("Input your unique Key ID")
            # Decrypt the RSA Key  using the AWS KMS ID
            response = client.decrypt(CiphertextBlob=plaintext)
            # This line writes the decrypted RSA key to a new file
            with open(private_key_path, 'wb') as f:
                f.write(response['Plaintext'])
            # This Imports the decrypted RSA private key
            private_key = RSA.import_key(open(private_key_path).read())
            with open(file_path, 'rb') as encrypted_file:
                # This lines Read the AES key, nonce, tag, and ciphertext from the file
                enc_AES_key,nonce, tag,ciphertext = \
                [encrypted_file.read(x) for x in (private_key.size_in_bytes(),16,16,-1) ]
                # This Create a new file for the decrypted data
                decrypted_file_name = 'decrypted_' + os.path.basename(file_path) 
                decrypted_file_object = open(os.path.join(dir_path,decrypted_file_name), 'wb')
                # Decrypt the AES key using the private RSA key
                cipher_rsa = PKCS1_OAEP.new(private_key)
                AES_key = cipher_rsa.decrypt(enc_AES_key)
                # These lines decrypt the data using the AES key and nonce
                cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                decrypted_file_object.write(data)
                # This two lines closes the files
                decrypted_file_object.close()
                encrypted_file.close()
                print('Decryption Done! Check the folder you specified for your decrypted file') 
            
            #The following lines of code encrypts the temporarily exposed private key
            # Read the file
            file_path= private_key_path
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            # Gives access to Encrypt the private key using the AWS KMS ID
            response = client.encrypt(KeyId=key_id, Plaintext=plaintext)

            # Delete the exposed generated private key
            if os.path.exists(file_path):
                    os.remove(file_path)
            else:
                print(f"oops! There is an error, please start again!")

            # Write the encrypted data to a new file
            with open(file_path, 'wb') as f:
                f.write(response['CiphertextBlob'])