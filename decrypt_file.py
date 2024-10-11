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

def decrypt_file(file_path: str, password: str):
    # Read the encrypted file data
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Extract the salt, IV, and encrypted data from the file
    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    # Generate the key from the password and salt
    key = generate_key(password, salt)

    # Create the cipher object and decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(padded_data) + unpadder.finalize()

    # Save the decrypted data back to a file
    decrypted_file_path = file_path.replace('.enc', '_decrypted.ext')
    with open(decrypted_file_path, 'wb') as f:
        f.write(original_data)

    print(f"File decrypted and saved to {decrypted_file_path}")

if __name__ == "__main__":
    # Replace these with the actual file path and password you want to use
    file_path = "/Users/rudycazares/Desktop/paystub.pdf.enc"  # Change this to your encrypted file path
    password = "eluserEncryption"  # Change this to your password

    decrypt_file(file_path, password)
