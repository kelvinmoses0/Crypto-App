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
    aws_access_key_id='AKIA4HM2VZWSBHCD556I',
    aws_secret_access_key='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',
    region_name='us-east-1'
)

# Create a boto3 KMS client 
client = session.client('kms')

#I then create a  class named Kelvin where all my methods that will be called in app.py will be defined. 
class Kelvin:
    
    #This first method is generate new RSA Keys that would be used for Encrypting and Decrypting Folders and Files
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
        key_id =input("Input Unique Encryption ID")

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
    
    
    #This method is to generate the AWS KMS Key that would be used to envelope the private key on the user machine to add extra security
    def generate_id():
        # We have to set the alias of the key we want tocreate
        # This Generate a random word
        random_word = ''.join(random.choices(string.ascii_letters, k=5))

        # This generates a random number
        random_number = random.randint(0, 100)

        # Concatenate the random word and number
        random_word_number = random_word + str(random_number)

        alias = 'alias/py-'+ random_word_number

        #Input Email Address
        receiver_email =  input("please input your email address (example johndoe@stu.mmu.ac.uk)")
        # Create the key
        response = client.create_key(
        KeyUsage='ENCRYPT_DECRYPT',
        )

        # Get the key ID of the new key
        key_id = response['KeyMetadata']['KeyId']


        # Create an alias for the key
        client.create_alias(
        AliasName=alias,
        TargetKeyId=key_id
        )

        print(f'Unique Key created with ID: {key_id} and has been sent to your email address {receiver_email}')

        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        sender_email = "kelvinmoses0@gmail.com"  # Enter your address
        password = "xgojsghmylyuxvbw"

        msg = EmailMessage()
        msg.set_content(f'Your Unique Key  ID is: {key_id} please keep this information safe')
        msg['Subject'] = "Kelvin Moses Encryption App"
        msg['From'] = sender_email
        msg['To'] = receiver_email

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.send_message(msg, from_addr=sender_email, to_addrs=receiver_email)

   
    def folder_encryption():
        Directory = input("Enter the folder you wish to encrypt: (use / instead of \ )")
        dir_path = input('Enter the Directory Path you wish to save your encrypted Files(use / instead of \ ):')
        receiver = input('Please enter the recepient public key file name or path with the correct file extention (use / instead of \ ): ')
        os.makedirs(dir_path, exist_ok=True)
        assert Path(Directory).is_dir()
        for new_path in sorted(Path(Directory).iterdir(), key=lambda p: str(p).lower()):
            with open(new_path, 'rb') as p:
                new_file_name = os.path.basename(new_path)

                encrypted_path_text = 'cipher_' + new_file_name                     
                recipient_key = RSA.import_key(open(receiver).read())
                AES_key_generate = get_random_bytes(32)

                rsa_cipher = PKCS1_OAEP.new(recipient_key) 
                enc_AES_key = rsa_cipher.encrypt(AES_key_generate)

                # original_message = open(p, 'rb')
                textFile = p.read()
                textFile = bytearray(textFile) 

                aes_cipher = AES.new(AES_key_generate, AES.MODE_EAX)
                ciphertext, tag = aes_cipher.encrypt_and_digest(textFile) # Encrypting the file and generating the Cipher text and the hash digest(hash function)
                encrypted_path_object = open(os.path.join(dir_path,encrypted_path_text), 'wb') # opening the file just created 
                [ encrypted_path_object.write(x) for x in (enc_AES_key, aes_cipher.nonce, tag, ciphertext) ] # Storing our result in a file
                encrypted_path_object.close() 
                p.close()
        print('Encryption Done. Check the Directory you input for your Cipher Text') 

    def decrypt_new_folder():
            """
            Decrypts all files in a given directory using AES and RSA decryption
            """
            # Prompt user for directory containing encrypted files
            encrypted_dir = input('Enter the encrypted folder path: ')
            # Prompt user for RSA private key
            private_key_path = input('Enter the private key name or path : ')
            assert Path(encrypted_dir).is_dir()
            with open(private_key_path , 'rb') as f:
                plaintext = f.read()

            # Encryption key
            key_id = input("Input Key ID")
            # Decrypt the file using the key
            response = client.decrypt(CiphertextBlob=plaintext)

            # Write the decrypted data to a new file
            with open(private_key_path, 'wb') as f:
                f.write(response['Plaintext'])
            
            for new_path in sorted(Path(encrypted_dir).iterdir(), key=lambda p: str(p).lower()):
                with open(new_path, 'rb') as encrypted_file:
                    new_file_name = os.path.basename(new_path)   
                    decrypted_file_text = 'decrypted_' + new_file_name
                    decrypted_file_object = open(decrypted_file_text, 'wb')

                    private_key = RSA.import_key(open(private_key_path).read())
                    enc_AES_key,nonce, tag,ciphertext = \
                    [encrypted_file.read(x) for x in (private_key.size_in_bytes(),16,16,-1) ]

                    # Decrypt the session key with the private RSA key
                    cipher_rsa = PKCS1_OAEP.new(private_key)
                    AES_key = cipher_rsa.decrypt(enc_AES_key)

                    # Decrypt the data with the AES session key
                    cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
                    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                    decrypted_file_object.write(data)
                    decrypted_file_object.close()  
                print('Decryptiuon Done. Check the Directory you input for your decrypted folder') 

            # Read the file
            file_path= private_key_path
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            # Encrypt the file using the key
            response = client.encrypt(KeyId=key_id, Plaintext=plaintext)

            # Delete the exposed generated private key
            if os.path.exists(file_path):
                    os.remove(file_path)
            else:
                print(f"oops! There is an error, please start again!")

            # Write the encrypted data to a new file
            with open(file_path, 'wb') as f:
                f.write(response['CiphertextBlob'])


    def encrypt_new_file():
            """
            Encrypts a given file using AES and RSA encryption.
            Prompts the user for the file path, directory to save the encrypted file, and the recipient's public key.
            """
            # Prompt user for file path to encrypt
            file_path = input("Enter the file you wish to encrypt: (use / instead of \ )")
            # Prompt user for directory to save the encrypted file
            dir_path = input('Enter the Directory Path you wish to save your encrypted Files(use / instead of \ ):')
            # Prompt user for the recipient's public key
            receiver_key_path = input('Please enter the recepient public key file name or path with the correct file extention (use / instead of \ ): ')
            # Create the directory if it doesn't exist
            os.makedirs(dir_path, exist_ok=True)
            with open(file_path, 'rb') as original_file:
                # Read the contents of the file
                original_file_contents = original_file.read()
                # Create a new file name for the encrypted file
                encrypted_file_name = 'cipher_' + os.path.basename(file_path)                     
                # Import the recipient's public key
                recipient_key = RSA.import_key(open(receiver_key_path).read())
                # Generate a new AES key
                AES_key_generate = get_random_bytes(32)
                # Create an RSA cipher with the recipient's public key
                rsa_cipher = PKCS1_OAEP.new(recipient_key) 
                enc_AES_key = rsa_cipher.encrypt(AES_key_generate)
                original_file_contents = bytearray(original_file_contents) 
                aes_cipher = AES.new(AES_key_generate, AES.MODE_EAX)
                # Encrypting the file and generating the Cipher text and the hash digest(hash function)
                ciphertext, tag = aes_cipher.encrypt_and_digest(original_file_contents)
                # opening the file just created 
                encrypted_path_object = open(os.path.join(dir_path,encrypted_file_name), 'wb') 
                # Storing our result in a file
                [ encrypted_path_object.write(x) for x in (enc_AES_key, aes_cipher.nonce, tag, ciphertext) ] 
                encrypted_path_object.close() 
                original_file.close()
            print('Encryption Done. Check the Directory you input for your Cipher Text') 


    def decrypt_new_file():
            """
            Decrypts a given file using AES and RSA decryption
            """
            # Prompt user for file path to decrypt
            file_path = input('Enter the encrypted file path: ')
            # Prompt user for RSA private key
            private_key_path = input('Enter the private key name or path : ')
            with open(private_key_path , 'rb') as f:
                plaintext = f.read()
            # Encryption key
            key_id = input("Input Key ID")
            # Decrypt the file using the key
            response = client.decrypt(CiphertextBlob=plaintext)
            # Write the decrypted data to a new file
            with open(private_key_path, 'wb') as f:
                f.write(response['Plaintext'])
            # Import private key
            private_key = RSA.import_key(open(private_key_path).read())
            with open(file_path, 'rb') as encrypted_file:
                # Read the AES key, nonce, tag, and ciphertext from the file
                enc_AES_key,nonce, tag,ciphertext = \
                [encrypted_file.read(x) for x in (private_key.size_in_bytes(),16,16,-1) ]
                # Create a new file for decrypted data
                decrypted_file_name = 'decrypted_' + os.path.basename(file_path) 
                decrypted_file_object = open(decrypted_file_name, 'wb')
                # Decrypt the AES key using the private RSA key
                cipher_rsa = PKCS1_OAEP.new(private_key)
                AES_key = cipher_rsa.decrypt(enc_AES_key)
                # Decrypt the data using the AES key and nonce
                cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                decrypted_file_object.write(data)
                # Close the files
                decrypted_file_object.close()
                encrypted_file.close()
                print('Decryption Done. Check the  decrypted file') 
            
            # Read the file
            file_path= private_key_path
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            # Encrypt the file using the key
            response = client.encrypt(KeyId=key_id, Plaintext=plaintext)

            # Delete the exposed generated private key
            if os.path.exists(file_path):
                    os.remove(file_path)
            else:
                print(f"oops! There is an error, please start again!")

            # Write the encrypted data to a new file
            with open(file_path, 'wb') as f:
                f.write(response['CiphertextBlob'])