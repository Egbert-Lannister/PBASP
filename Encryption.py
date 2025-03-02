import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class TailoredPRF:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        # Generate a random 128-bit salt
        salt = os.urandom(16)
        # Derive a key from the salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(self.key)
        # Create a cipher instance
        cipher = Cipher(algorithms.AES(key), modes.CBC(salt))
        # Encrypt the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data, salt

    def decrypt(self, encrypted_data, salt):
        # Derive a key from the salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(self.key)
        # Create a cipher instance
        cipher = Cipher(algorithms.AES(key), modes.CBC(salt))
        # Decrypt the data
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data



# Example usage
key = b'secret_key'
prf = TailoredPRF(key)

data = b'Hello, World!'
encrypted_data, salt = prf.encrypt(data)
print("Encrypted data:", encrypted_data)

decrypted_data = prf.decrypt(encrypted_data, salt)
print("Decrypted data:", decrypted_data.decode())