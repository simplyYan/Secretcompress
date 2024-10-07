import zipfile
import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
from getpass import getpass
import base64

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_zip(password: str, zip_path: str, output_path: str):
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(zip_path, 'rb') as file:
        zip_data = file.read()
    encrypted_data = encryptor.update(zip_data) + encryptor.finalize()

    with open(output_path, 'wb') as enc_file:
        enc_file.write(salt + iv + encrypted_data)

    print(f"File '{zip_path}' successfully encrypted as '{output_path}'.")

def decrypt_zip(password: str, encrypted_path: str, output_path: str):
    with open(encrypted_path, 'rb') as enc_file:
        salt = enc_file.read(16)
        iv = enc_file.read(16)
        encrypted_data = enc_file.read()

    key = generate_key_from_password(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        zip_data = decryptor.update(encrypted_data) + decryptor.finalize()
        with open(output_path, 'wb') as file:
            file.write(zip_data)
        print(f"File '{encrypted_path}' successfully decrypted as '{output_path}'.")
    except InvalidKey:
        print("Incorrect password! Unable to decrypt the file.")

def create_zip(directory_path: str, zip_path: str):
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
        for root, _, files in os.walk(directory_path):
            for file in files:
                zip_file.write(os.path.join(root, file),
                               os.path.relpath(os.path.join(root, file), directory_path))
    print(f"Directory '{directory_path}' compressed into '{zip_path}'.")

def main():
    print("Welcome to Secretcompress!")
    choice = input("Choose an option: (1) Encrypt, (2) Decrypt: ")

    if choice == '1':
        directory_path = input("Enter the path of the directory to be compressed and encrypted: ")
        zip_path = "temp.zip"
        create_zip(directory_path, zip_path)

        password = getpass("Enter the encryption password: ")
        encrypted_path = input("Enter the output encrypted file name (e.g., file.enc): ")
        encrypt_zip(password, zip_path, encrypted_path)

        os.remove(zip_path)  

    elif choice == '2':
        encrypted_path = input("Enter the path of the encrypted file (.enc): ")
        password = getpass("Enter the decryption password: ")
        output_path = input("Enter the output directory name (e.g., output.zip): ")
        decrypt_zip(password, encrypted_path, output_path)

        with zipfile.ZipFile(output_path, 'r') as zip_file:
            zip_file.extractall(os.path.splitext(output_path)[0])

        os.remove(output_path)  

    else:
        print("Invalid option. Please choose (1) or (2).")

if __name__ == "__main__":
    main()