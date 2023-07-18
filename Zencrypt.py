import os
import sys
import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from tqdm import tqdm
from colorama import Fore, Style

def derive_key(password, salt, key_length):
    return PBKDF2(password, salt, dkLen=key_length)

def encrypt_file(input_file, output_directory, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt, 32)
    cipher = AES.new(key, AES.MODE_EAX)

    with open(input_file, 'rb') as file:
        plaintext = file.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    encrypted_filename = os.path.basename(input_file) + '.enc'
    os.makedirs(output_directory, exist_ok=True)
    encrypted_file = os.path.abspath(os.path.join(output_directory, encrypted_filename))

    with open(encrypted_file, 'wb') as file:
        file.write(salt)
        file.write(cipher.nonce)
        file.write(tag)
        file.write(ciphertext)

    os.remove(input_file)  

    return True

def decrypt_file(input_file, output_directory, password):
    try:
        with open(input_file, 'rb') as file:
            salt = file.read(16)
            nonce = file.read(16)
            tag = file.read(16)
            ciphertext = file.read()

        key = derive_key(password, salt, 32)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        decrypted_filename = os.path.splitext(os.path.basename(input_file))[0]
        os.makedirs(output_directory, exist_ok=True)
        decrypted_file = os.path.abspath(os.path.join(output_directory, decrypted_filename))

        with open(decrypted_file, 'wb') as file:
            file.write(plaintext)

        os.remove(input_file)  

        return True

    except FileNotFoundError:
        return False

def display_banner():
    banner = r"""
__________                                         __   
\____    /____   ____   ___________ ___.__._______/  |_ 
  /     // __ \ /    \_/ ___\_  __ <   |  |\____ \   __\
 /     /\  ___/|   |  \  \___|  | \/\___  ||  |_> >  |  
/_______ \___  >___|  /\___  >__|   / ____||   __/|__|  
        \/   \/     \/     \/       \/     |__|         
    """
    print(Fore.YELLOW + banner + Style.RESET_ALL)

def display_files_in_directory(directory):
    files = os.listdir(directory)

    print("Files in the chosen directory:")
    for i, file in enumerate(files):
        print(f"{i+1}. {file}")

def get_user_input():
    print("Select an option:")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    option = input("Enter the option number: ")
    if option not in ['1', '2']:
        print("Invalid option. Please select 1 or 2.")
        sys.exit(1)

    directory = input("Enter the directory: ")
    filename = input("Enter the filename: ")

    return option, directory, filename

def main():
    display_banner()
    option, directory, filename = get_user_input()

    if directory == '-':
        directory = os.getcwd()

    output_directory = directory

    password = getpass.getpass("Enter the encryption/decryption password: ")

    display_files_in_directory(directory)

    if option == '1':
        input_file = os.path.join(directory, filename)
        print(f"Encrypting file: {filename}")
        with tqdm(total=os.path.getsize(input_file), unit='B', unit_scale=True) as progress:
            if encrypt_file(input_file, output_directory, password):
                os.remove(input_file)  
                progress.update(os.path.getsize(input_file))
                print("Encrypted Successfully")
            else:
                print("Failed to encrypt file. File not found.")

    elif option == '2':
        input_file = os.path.join(directory, filename)
        print(f"Decrypting file: {filename}")
        with tqdm(total=os.path.getsize(input_file), unit='B', unit_scale=True) as progress:
            if decrypt_file(input_file, output_directory, password):
                os.remove(input_file)  
                progress.update(os.path.getsize(input_file))
                print("Decrypted Successfully")
            else:
                print("Failed to decrypt file. File not found.")

if __name__ == "__main__":
    main()
