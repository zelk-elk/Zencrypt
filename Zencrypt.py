import os
import sys
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from colorama import Fore, Style, init

init()

def derive_key(password, salt, key_length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file, output_directory, password):
    salt = os.urandom(16)
    key = derive_key(password, salt, 32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    with open(input_file, 'rb') as file:
        plaintext = file.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_filename = os.path.basename(input_file) + '.enc'
    os.makedirs(output_directory, exist_ok=True)
    encrypted_file = os.path.abspath(os.path.join(output_directory, encrypted_filename))

    with open(encrypted_file, 'wb') as file:
        file.write(salt)
        file.write(iv)
        file.write(ciphertext)

    return True

def decrypt_file(input_file, output_directory, password):
    try:
        with open(input_file, 'rb') as file:
            salt = file.read(16)
            iv = file.read(16)
            ciphertext = file.read()

        key = derive_key(password, salt, 32)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        decrypted_filename = os.path.splitext(os.path.basename(input_file))[0]
        os.makedirs(output_directory, exist_ok=True)
        decrypted_file = os.path.abspath(os.path.join(output_directory, decrypted_filename))

        with open(decrypted_file, 'wb') as file:
            file.write(plaintext)

        return True

    except FileNotFoundError:
        return False

def display_banner():
    banner = f"""{Fore.YELLOW}
__________                                         __
\____    /____   ____   ___________ ___.__._______/  |_
  /     // __ \ /    \_/ ___\_  __ <   |  |\____ \   __\\
 /     /\  ___/|   |  \  \___|  | \/\___  ||  |_> >  |
/_______ \___  >___|  /\___  >__|   / ____||   __/|__|
        \/   \/     \/     \/       \/     |__|
{Style.RESET_ALL}"""
    print(banner)

def display_files_in_directory(directory):
    files = os.listdir(directory)

    print(f"{Fore.YELLOW}Files in the chosen directory:{Style.RESET_ALL}")
    for i, file in enumerate(files):
        print(f"{Fore.CYAN}{i+1}. {file}{Style.RESET_ALL}")

def get_user_input():
    print(f"{Fore.YELLOW}Select an option:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}1. Encrypt a file{Style.RESET_ALL}")
    print(f"{Fore.CYAN}2. Decrypt a file{Style.RESET_ALL}")
    print(f"{Fore.CYAN}3. Quit{Style.RESET_ALL}")
    option = input(f"{Fore.YELLOW}Enter the option number: {Style.RESET_ALL}")
    if option not in ['1', '2', '3']:
        print(f"{Fore.RED}Invalid option. Please select 1, 2, or 3.{Style.RESET_ALL}")
        sys.exit(1)

    if option in ['1', '2']:
        directory = input(f"{Fore.YELLOW}Enter the directory: {Style.RESET_ALL}")
        filename = input(f"{Fore.YELLOW}Enter the filename: {Style.RESET_ALL}")
        return option, directory, filename
    else:
        return option, None, None

def main():
    display_banner()

    while True:
        option, directory, filename = get_user_input()

        if option == '3':
            print(f"{Fore.YELLOW}Exiting Zencrypt...{Style.RESET_ALL}")
            sys.exit()

        if option in ['1', '2']:
            if directory == '-':
                directory = os.getcwd()

            output_directory = directory

            password = getpass.getpass(f"{Fore.YELLOW}Enter the encryption/decryption password: {Style.RESET_ALL}")

            if option == '1':
                input_file = os.path.join(directory, filename)
                print(f"{Fore.YELLOW}Encrypting file: {filename}{Style.RESET_ALL}")
                if encrypt_file(input_file, output_directory, password):
                    os.remove(input_file)
                    print(f"{Fore.GREEN}Encrypted Successfully{Style.RESET_ALL}")
                    print("=" * 30)
                else:
                    print(f"{Fore.RED}Failed to encrypt file. File not found.{Style.RESET_ALL}")

            elif option == '2':
                input_file = os.path.join(directory, filename)
                print(f"{Fore.YELLOW}Decrypting file: {filename}{Style.RESET_ALL}")
                if decrypt_file(input_file, output_directory, password):
                    os.remove(input_file)
                    print(f"{Fore.GREEN}Decrypted Successfully{Style.RESET_ALL}")
                    print("=" * 30)
                else:
                    print(f"{Fore.RED}Failed to decrypt file. File not found.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
