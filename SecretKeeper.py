import os
import sys
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA512, HMAC
from Crypto.Util.Padding import pad, unpad

# Constants for supported algorithms, hash functions, and other configurations
SUPPORTED_ALGORITHMS = {'3DES': DES3, 'AES128': AES, 'AES256': AES}
HASH_FUNCTIONS = {'SHA256': SHA256, 'SHA512': SHA512}
BLOCK_SIZE_3DES = DES3.block_size
BLOCK_SIZE_AES = AES.block_size
DIGEST_SIZE_SHA256 = SHA256.digest_size
DIGEST_SIZE_SHA512 = SHA512.digest_size
CONFIG_PARAMS = ('algorithm', 'hash_function', 'iterations')


def encrypt_file(file_path, password, algorithm='AES256', hash_function='SHA256', iterations=100000):
    """
    Encrypts a file using the specified encryption algorithm and hash function.

    Parameters:
    - file_path (str): The path to the file that will be encrypted. This file should be accessible and readable.
    - password (str): The password used to generate the encryption key. It's crucial to keep this password secure.
    - algorithm (str, optional): The encryption algorithm to use. Supported values are 'AES128', 'AES256', and '3DES'.
      Defaults to 'AES256'.
    - hash_function (str, optional): The hash function used for key derivation. Supported values are 'SHA256' and 'SHA512'.
      Defaults to 'SHA256'.
    - iterations (int, optional): The number of iterations to use for the key derivation function (PBKDF2). Increasing this number
      can enhance security but also increases the time taken to derive the key. Defaults to 100000.

    Returns:
    - output_file_path (str): The path to the encrypted file, which is the original file path with '.sec' appended.
    """
     
    # Validate algorithm and hash function
    if algorithm not in SUPPORTED_ALGORITHMS or hash_function not in HASH_FUNCTIONS:
        raise ValueError('Unsupported algorithm or hash function.')

    try:
        # Read the file data
        with open(file_path, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

    # Generate master key
    salt = get_random_bytes(16)
    master_key = PBKDF2(password, salt, count=iterations, hmac_hash_module=HASH_FUNCTIONS[hash_function])

    # Derive encryption and HMAC keys
    encryption_key = PBKDF2(master_key, b'encryption', dkLen=32, count=1, hmac_hash_module=HASH_FUNCTIONS[hash_function])
    hmac_key = PBKDF2(master_key, b'hmac', dkLen=32, count=1, hmac_hash_module=HASH_FUNCTIONS[hash_function])

    # Generate IV
    block_size = BLOCK_SIZE_AES if 'AES' in algorithm else BLOCK_SIZE_3DES
    iv = get_random_bytes(block_size)

    # Initialize cipher
    if algorithm == 'AES128':
        cipher = AES.new(encryption_key[:16], AES.MODE_CBC, iv)
    elif algorithm == 'AES256':
        cipher = AES.new(encryption_key[:32], AES.MODE_CBC, iv)
    elif algorithm == '3DES':
        cipher = DES3.new(encryption_key[:24], DES3.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported encryption algorithm")

    # Encrypt data and compute HMAC
    encrypted_data = cipher.encrypt(pad(data, block_size))
    hmac_obj = HMAC.new(hmac_key, digestmod=HASH_FUNCTIONS[hash_function])
    hmac_obj.update(iv + encrypted_data)
    hmac_value = hmac_obj.digest()

    # Construct metadata
    metadata = f'{algorithm}-{hash_function}-{iterations}'.encode()
    metadata_length = len(metadata).to_bytes(2, 'big')

    # Write encrypted file
    output_file_path = f'{file_path}.sec'
    try:
        with open(output_file_path, 'wb') as out_file:
            out_file.write(metadata_length + metadata + salt + iv + hmac_value + encrypted_data)
    except IOError as e:
        print(f"Error writing encrypted file: {e}")
        sys.exit(1)

    print(f'File encrypted successfully: {output_file_path}')
    return output_file_path

def decrypt_file(file_path, password, output_path="decrypted_plaintext.txt"):
    """
    Decrypts a previously encrypted file using the specified password.

    Parameters:
    - file_path (str): The path to the encrypted file. This file should be accessible and readable.
    - password (str): The password used for decryption. This should match the password used for encryption.
    - output_path (str, optional): The path where the decrypted file will be saved. If not provided, the function
      will attempt to infer the original filename by removing '.enc' from the encrypted file's name.

    Returns:
    - output_file_path (str): The path to the decrypted file.
    """

    try:
        with open(file_path, 'rb') as enc_file:
            metadata_length = int.from_bytes(enc_file.read(2), 'big')
            metadata = enc_file.read(metadata_length).decode().split('-')
            algorithm, hash_function, iterations = metadata
            salt = enc_file.read(16)
            iv = enc_file.read(BLOCK_SIZE_AES if 'AES' in algorithm else BLOCK_SIZE_3DES)
            hmac_value = enc_file.read(DIGEST_SIZE_SHA512 if 'SHA512' in hash_function else DIGEST_SIZE_SHA256)
            encrypted_data = enc_file.read()
    except IOError as e:
        print(f"Error reading encrypted file: {e}")
        sys.exit(1)

    # Regenerate master key and derive encryption and HMAC keys
    master_key = PBKDF2(password, salt, count=int(iterations), hmac_hash_module=HASH_FUNCTIONS[hash_function])
    encryption_key = PBKDF2(master_key, b'encryption', dkLen=32, count=1, hmac_hash_module=HASH_FUNCTIONS[hash_function])
    hmac_key = PBKDF2(master_key, b'hmac', dkLen=32, count=1, hmac_hash_module=HASH_FUNCTIONS[hash_function])

    # Verify HMAC to check integrity and authenticity
    hmac_obj = HMAC.new(hmac_key, digestmod=HASH_FUNCTIONS[hash_function])
    hmac_obj.update(iv + encrypted_data)
    try:
        hmac_obj.verify(hmac_value)
    except ValueError:
        print('Invalid HMAC - the file may have been tampered with or the password is incorrect.')
        sys.exit(1)

    # Initialize cipher for decryption
    if algorithm == 'AES128':
        cipher = AES.new(encryption_key[:16], AES.MODE_CBC, iv)
    elif algorithm == 'AES256':
        cipher = AES.new(encryption_key[:32], AES.MODE_CBC, iv)
    elif algorithm == '3DES':
        cipher = DES3.new(encryption_key[:24], DES3.MODE_CBC, iv)
    else:
        print("Unsupported encryption algorithm")
        sys.exit(1)

    # Decrypt data
    try:
        data = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE_AES if 'AES' in algorithm else BLOCK_SIZE_3DES)
    except (ValueError, KeyError) as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)

    # Write decrypted data to file
    output_file_path = output_path or file_path.replace('.sec', '')
    try:
        with open(output_file_path, 'wb') as out_file:
            out_file.write(data)
    except IOError as e:
        print(f"Error writing decrypted file: {e}")
        sys.exit(1)

    print(f'File decrypted successfully: {output_file_path}')
    return output_file_path

def main():
    
    # ANSI escape codes for colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

    """Main function to parse command-line arguments and call encrypt/decrypt functions."""
    if len(sys.argv) < 4 or sys.argv[1] not in ['encrypt', 'decrypt']:
        print(f'{RED}Usage:{RESET}\n'
            f'  {GREEN}To encrypt:{RESET} python {CYAN}SecretKeeper.py{RESET} {MAGENTA}encrypt{RESET} <file_path> <password> '
            f'[{YELLOW}algorithm{RESET}={BLUE}AES256{RESET}] '
            f'[{YELLOW}hash_function{RESET}={BLUE}SHA256{RESET}] '
            f'[{YELLOW}iterations{RESET}={BLUE}100000{RESET}]\n'
            f'  {GREEN}To decrypt:{RESET} python {CYAN}SecretKeeper.py{RESET} {MAGENTA}decrypt{RESET} <file_path> <password> '
            f'[{YELLOW}output_path{RESET}]\n'
            f'{RED}Supported algorithms:{RESET} 3DES, AES128, {BLUE}AES256 (default){RESET}\n'
            f'{RED}Supported hash functions:{RESET} SHA256 {BLUE}(default){RESET}, SHA512\n'
            f'{RED}Default iterations:{RESET} {BLUE}100000{RESET}\n')
        sys.exit(1)

    operation = sys.argv[1]
    file_path = sys.argv[2]
    password = sys.argv[3]
    extra_args = sys.argv[4:]

    try:
        if operation == 'encrypt':
            config = {k: (int(v) if k == 'iterations' else v) for k, v in zip(CONFIG_PARAMS, extra_args)}
            encrypt_file(file_path, password, **config)
        else:
            output_path = extra_args[0] if extra_args else None
            decrypt_file(file_path, password, output_path)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

    #    python file_crypto.py encrypt plaintext.txt yourpassword AES256 SHA256 100000
    #    python file_crypto.py decrypt plaintext.txt.sec yourpassword
    #    encrypt plaintext.txt yourpassword AES256 SHA512 100000

   