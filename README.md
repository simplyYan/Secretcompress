# Secretcompress

**Secretcompress** is a command-line tool written in Python to securely encrypt and decrypt `.zip` files using a user-defined keyword. The tool uses AES-256 encryption with a password-based key derivation function (PBKDF2), allowing the password to be any word of any length. This offers strong security while keeping the password manageable and easy to remember.

## Features

- **Secure Encryption**: Uses AES-256 encryption for maximum security.
- **Password-based Key**: Encrypts and decrypts files based on a keyword chosen by the user, making it easy to remember without sacrificing security.
- **File Compression**: Compresses a directory into a `.zip` file before encryption.
- **Simple CLI Interface**: Easy-to-use command-line interface for both encryption and decryption operations.

## Requirements

- **Python 3.x**
- **cryptography** module: Install it via `pip`:

  ```bash
  pip install cryptography
  ```

## Installation

1. Clone or download the repository.
2. Install dependencies as listed in **Requirements**.

## Usage

### Encrypting a Directory

To encrypt a directory, **Secretcompress** will first compress the directory into a `.zip` file and then encrypt it using a keyword.

```bash
python secretcompress.py
```

1. Choose the encryption option (`1`).
2. Enter the path of the directory to be compressed and encrypted.
3. Enter your chosen password.
4. Specify the output encrypted file name (e.g., `myfile.enc`).

The tool will generate an encrypted file with the `.enc` extension.

### Decrypting an Encrypted File

To decrypt an encrypted `.enc` file:

```bash
python secretcompress.py
```

1. Choose the decryption option (`2`).
2. Enter the path of the encrypted file (`.enc`).
3. Enter the decryption password.
4. Specify the output directory or `.zip` file name for the decrypted contents.

If the password is correct, the decrypted `.zip` file will be created. The contents will also be extracted automatically into a folder with the same name as the decrypted file (minus the extension).

## Example

Encrypt a directory:

```bash
$ python secretcompress.py
Welcome to Secretcompress!
Choose an option: (1) Encrypt, (2) Decrypt: 1
Enter the path of the directory to be compressed and encrypted: my_folder
Enter the encryption password: ********
Enter the output encrypted file name (e.g., file.enc): my_encrypted_file.enc
```

Decrypt a file:

```bash
$ python secretcompress.py
Welcome to Secretcompress!
Choose an option: (1) Encrypt, (2) Decrypt: 2
Enter the path of the encrypted file (.enc): my_encrypted_file.enc
Enter the decryption password: ********
Enter the output directory name (e.g., output.zip): decrypted_folder
```

## Security

Secretcompress uses PBKDF2 with SHA-256 to derive a secure encryption key from the user’s password. Each encryption operation generates a unique salt and IV, ensuring that even identical files will have different encrypted outputs.
