# Zencrypt - File Encryption and Decryption Tool

Zencrypt is a command-line tool for encrypting and decrypting files using AES encryption. It provides a simple and secure way to protect your sensitive files. 
With Zencrypt, you can encrypt your files with a password of your choice and decrypt them whenever needed.

## Requirements

- Python 3.6+
- pip (Python package manager)

## Installation

1. Clone the repository or download the source code.
2. Navigate to the project directory:
cd Zencrypt

3. Install the required packages:
pip install -r requirements.txt


## Usage

To run the Zencrypt tool, open a terminal or command prompt and navigate to the project directory.

### Encrypting a File

To encrypt a file, follow these steps:

1. Choose the **Encrypt** option in the tool.
2. Enter the directory of the file you want to encrypt. If the file is in the current directory, you can input a hyphen (`-`).
3. Enter the filename of the file you want to encrypt.
4. Press enter.
5. Enter a password when prompted and press enter. Note that the password input will not be displayed for security reasons.

### Decrypting a File

To decrypt a file, follow these steps:

1. Choose the **Decrypt** option in the tool.
2. Enter the directory of the encrypted file you want to decrypt. If the file is in the current directory, you can input a hyphen (`-`).
3. Enter the filename of the encrypted file with the `.enc` extension.
4. Press enter.
5. Enter the same password used while enryption.

## Important Note

During the encryption and decryption process, you might encounter some error messages related to file not found. Please ignore these errors as they are part of the tool's functionality and do not affect the encryption or decryption process.
And also please don't think that changing the file format via removing the 'enc' extension will get you access to the encrypted file, it will only make it inaccessible.

ZELK - DWG


