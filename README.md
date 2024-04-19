# Secret-Keeper

## Overview
This program provides a secure way to encrypt and decrypt files using various algorithms and hash functions. It supports AES (128-bit and 256-bit) and 3DES encryption algorithms, along with SHA256 and SHA512 hash functions for key derivation and HMAC validation. This document outlines how to set up and use the program.

## Prerequisites
Before running the program, ensure you have Python installed on your system. The program is compatible with Python 3.6 and above. You can download Python from the official website: [https://www.python.org/downloads/](https://www.python.org/downloads/).

## Installation

### 1. Clone or Download the Program
First, obtain a copy of the program. If you have `git` installed, you can clone the repository using the following command:

```sh
git clone <repository-url>
```

Alternatively, download the source code as a ZIP file from the project's page and extract it to a directory of your choice.

### 2. Install Dependencies
Navigate to the directory containing the program files in your terminal or command prompt. Install the required Python packages by running:

```sh
pip install -r requirements.txt
```

This will install `pycryptodome`, which is necessary for the program's cryptographic operations.

## Usage

The program can be used to encrypt or decrypt files from the command line. Navigate to the program's directory in your terminal or command prompt to begin.

### Encryption

To encrypt a file, use the following syntax:

```sh
python script.py encrypt <file_path> <password> [algorithm] [hash_function] [iterations]
```

- `<file_path>`: Path to the file you wish to encrypt.
- `<password>`: Password used for encryption.
- `[algorithm]`: (Optional) Encryption algorithm. Can be `AES128`, `AES256`, or `3DES`. Defaults to `AES256`.
- `[hash_function]`: (Optional) Hash function used for key derivation. Can be `SHA256` or `SHA512`. Defaults to `SHA256`.
- `[iterations]`: (Optional) Number of iterations for key derivation. Defaults to `100000`.

Example:

```sh
python script.py encrypt myfile.txt mypassword AES256 SHA512 100000
```

This command will encrypt `myfile.txt` using AES-256 with SHA-512 for key derivation, performing 100,000 iterations. The encrypted file will be saved as `myfile.txt.enc`.

### Decryption

To decrypt a previously encrypted file, use the following syntax:

```sh
python script.py decrypt <encrypted_file_path> <password> [output_path]
```

- `<encrypted_file_path>`: Path to the encrypted file.
- `<password>`: Password used for decryption.
- `[output_path]`: (Optional) Path to save the decrypted file. If not specified, the original filename will be used (by removing `.enc`).

Example:

```sh
python script.py decrypt myfile.txt.enc mypassword
```

This command will decrypt `myfile.txt.enc` using the password `mypassword` and save the decrypted content to `myfile.txt`.

## Security Considerations

- Keep your encryption password secure and do not share it.
- Be aware that using weak passwords or exposing your encrypted files to unauthorized parties can compromise the security of your data.
- Always keep a backup of your original files in a secure location.

## Troubleshooting

- If you encounter issues with encryption or decryption, verify that you have entered the correct password and selected the appropriate algorithm and hash function.
- Ensure all prerequisites are installed and up to date.
- Check the Python version if you encounter syntax errors or compatibility issues.

For further assistance, consult the program's FAQ or support resources.
