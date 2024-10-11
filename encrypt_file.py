from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a 32-byte key from the given password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    # Read the file data
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Generate a random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # Generate the key from the password and salt
    key = generate_key(password, salt)

    # Pad the data to make it a multiple of the block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Create the cipher object and encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted file along with the salt and IV
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    print(f"File encrypted and saved to {encrypted_file_path}")

if __name__ == "__main__":
    # Replace these with the actual file path and password you want to use
    file_path = "/Users/rudycazares/Desktop/paystub.pdf"  # Change this to your file path
    password = "eluserEncryption"  # Change this to your password

    encrypt_file(file_path, password)


