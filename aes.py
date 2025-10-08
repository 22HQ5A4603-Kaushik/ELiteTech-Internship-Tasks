# filename: advanced_encryptor.py

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sys

# Function to derive 256-bit AES key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,  # more iterations for stronger security
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a file with AES-256 CBC
def encrypt_file(file_path: str, password: str):
    if not os.path.isfile(file_path):
        print("[!] Error: File does not exist.")
        return
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        salt = os.urandom(16)  # 16 bytes salt
        iv = os.urandom(16)    # 16 bytes IV
        key = derive_key(password, salt)
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        encrypted_file = file_path + '.enc'
        with open(encrypted_file, 'wb') as f:
            f.write(salt + iv + encrypted_data)
        
        print(f"[+] Encryption successful! Saved as: {encrypted_file}")
    
    except Exception as e:
        print(f"[!] Encryption failed: {e}")

# Decrypt a file with AES-256 CBC
def decrypt_file(encrypted_file_path: str, password: str):
    if not os.path.isfile(encrypted_file_path):
        print("[!] Error: File does not exist.")
        return
    
    if not encrypted_file_path.endswith('.enc'):
        print("[!] Warning: File does not have '.enc' extension. Proceeding anyway.")
    
    try:
        with open(encrypted_file_path, 'rb') as f:
            file_data = f.read()
        
        salt = file_data[:16]
        iv = file_data[16:32]
        encrypted_data = file_data[32:]
        
        key = derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        decrypted_file = encrypted_file_path.replace('.enc', '.dec')
        with open(decrypted_file, 'wb') as f:
            f.write(data)
        
        print(f"[+] Decryption successful! Saved as: {decrypted_file}")
    
    except (ValueError, KeyError):
        print("[!] Decryption failed: Incorrect password or corrupted file.")
    except Exception as e:
        print(f"[!] Decryption failed: {e}")

# User-friendly CLI
def main():
    print("="*50)
    print("          Advanced AES-256 File Encryptor")
    print("="*50)
    
    choice = input("Choose action (encrypt/decrypt): ").strip().lower()
    if choice not in ['encrypt', 'decrypt']:
        print("[!] Invalid choice. Exiting.")
        sys.exit(1)
    
    file_path = input("Enter file path: ").strip()
    password = input("Enter password: ").strip()
    
    if not password:
        print("[!] Password cannot be empty. Exiting.")
        sys.exit(1)
    
    if choice == 'encrypt':
        encrypt_file(file_path, password)
    else:
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()
