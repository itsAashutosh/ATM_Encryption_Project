"""
Secure ATM-Bank Communication Module

This module provides cryptographic functions for secure communication
between ATM and Bank systems using:
- AES-256 encryption/decryption (CBC mode)
- RSA-2048 key generation and encryption/decryption
- Hybrid encryption: RSA for session key exchange, AES for data encryption
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os


class ATMCryptoUtils:
    """
    Cryptographic utilities for ATM-Bank secure communication.
    
    This class provides methods for:
    - RSA key pair generation (2048 bits)
    - AES session key generation (256 bits)
    - Hybrid encryption: RSA encrypts AES session key, AES encrypts data
    - Decryption of both session keys and data
    """
    
    AES_KEY_SIZE = 32  # 256 bits = 32 bytes
    RSA_KEY_SIZE = 2048
    AES_BLOCK_SIZE = 16  # 128 bits = 16 bytes
    
    @staticmethod
    def generate_rsa_key_pair():
        """
        Generate an RSA-2048 key pair for public/private key encryption.
        
        Returns:
            tuple: (private_key, public_key) - RSA key objects
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=ATMCryptoUtils.RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def generate_aes_session_key():
        """
        Generate a random AES-256 session key.
        
        Returns:
            bytes: 32-byte (256-bit) random key
        """
        return os.urandom(ATMCryptoUtils.AES_KEY_SIZE)
    
    @staticmethod
    def encrypt_aes(data, key, iv=None):
        """
        Encrypt data using AES-256 in CBC mode.
        
        Args:
            data (bytes): Plaintext data to encrypt
            key (bytes): AES-256 key (32 bytes)
            iv (bytes, optional): Initialization vector (16 bytes). 
                                  If None, a random IV is generated.
        
        Returns:
            tuple: (encrypted_data, iv) - Encrypted ciphertext and IV
        """
        if len(key) != ATMCryptoUtils.AES_KEY_SIZE:
            raise ValueError(f"AES key must be {ATMCryptoUtils.AES_KEY_SIZE} bytes")
        
        if iv is None:
            iv = os.urandom(ATMCryptoUtils.AES_BLOCK_SIZE)
        elif len(iv) != ATMCryptoUtils.AES_BLOCK_SIZE:
            raise ValueError(f"IV must be {ATMCryptoUtils.AES_BLOCK_SIZE} bytes")
        
        # Pad the data to be a multiple of block size
        padder = padding.PKCS7(ATMCryptoUtils.AES_BLOCK_SIZE * 8).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Create cipher and encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return ciphertext, iv
    
    @staticmethod
    def decrypt_aes(encrypted_data, key, iv):
        """
        Decrypt data using AES-256 in CBC mode.
        
        Args:
            encrypted_data (bytes): Ciphertext to decrypt
            key (bytes): AES-256 key (32 bytes)
            iv (bytes): Initialization vector (16 bytes)
        
        Returns:
            bytes: Decrypted plaintext data
        """
        if len(key) != ATMCryptoUtils.AES_KEY_SIZE:
            raise ValueError(f"AES key must be {ATMCryptoUtils.AES_KEY_SIZE} bytes")
        
        if len(iv) != ATMCryptoUtils.AES_BLOCK_SIZE:
            raise ValueError(f"IV must be {ATMCryptoUtils.AES_BLOCK_SIZE} bytes")
        
        # Create cipher and decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(ATMCryptoUtils.AES_BLOCK_SIZE * 8).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    @staticmethod
    def encrypt_rsa(data, public_key):
        """
        Encrypt data using RSA-2048 public key.
        
        Typically used to encrypt AES session keys.
        
        Args:
            data (bytes): Data to encrypt (max ~245 bytes for RSA-2048)
            public_key: RSA public key object
        
        Returns:
            bytes: Encrypted ciphertext
        """
        ciphertext = public_key.encrypt(
            data,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    @staticmethod
    def decrypt_rsa(encrypted_data, private_key):
        """
        Decrypt data using RSA-2048 private key.
        
        Typically used to decrypt AES session keys.
        
        Args:
            encrypted_data (bytes): Encrypted ciphertext
            private_key: RSA private key object
        
        Returns:
            bytes: Decrypted plaintext
        """
        plaintext = private_key.decrypt(
            encrypted_data,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    @staticmethod
    def serialize_public_key(public_key):
        """
        Serialize RSA public key to PEM format for storage/transmission.
        
        Args:
            public_key: RSA public key object
        
        Returns:
            bytes: PEM-encoded public key
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def serialize_private_key(private_key, password=None):
        """
        Serialize RSA private key to PEM format for storage.
        
        Args:
            private_key: RSA private key object
            password (bytes, optional): Password for encryption. If None, key is unencrypted.
        
        Returns:
            bytes: PEM-encoded private key
        """
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    @staticmethod
    def deserialize_public_key(pem_data):
        """
        Deserialize RSA public key from PEM format.
        
        Args:
            pem_data (bytes): PEM-encoded public key
        
        Returns:
            RSA public key object
        """
        return serialization.load_pem_public_key(pem_data, backend=default_backend())
    
    @staticmethod
    def save_key_to_file(key, filename, is_private=False, password=None):
        """
        Save an RSA key to a file.
        
        Args:
            key: RSA key object (private or public)
            filename (str): Path to save the key
            is_private (bool): True if saving a private key
            password (bytes, optional): Password for private key encryption
        """
        if is_private:
            pem_data = ATMCryptoUtils.serialize_private_key(key, password)
        else:
            pem_data = ATMCryptoUtils.serialize_public_key(key)
            
        with open(filename, 'wb') as f:
            f.write(pem_data)
            
    @staticmethod
    def load_key_from_file(filename, is_private=False, password=None):
        """
        Load an RSA key from a file.
        
        Args:
            filename (str): Path to the key file
            is_private (bool): True if loading a private key
            password (bytes, optional): Password if private key is encrypted
            
        Returns:
            RSA key object or None if file doesn't exist
        """
        if not os.path.exists(filename):
            return None
            
        with open(filename, 'rb') as f:
            pem_data = f.read()
            
        if is_private:
            return ATMCryptoUtils.deserialize_private_key(pem_data, password)
        else:
            return ATMCryptoUtils.deserialize_public_key(pem_data)

    @staticmethod
    def deserialize_private_key(pem_data, password=None):
        """
        Deserialize RSA private key from PEM format.
        
        Args:
            pem_data (bytes): PEM-encoded private key
            password (bytes, optional): Password if key is encrypted
        
        Returns:
            RSA private key object
        """
        return serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )

    @staticmethod
    def sign_data(data, private_key):
        """
        Sign data using RSA-2048 private key (SHA-256).
        
        Args:
            data (bytes): Data to sign
            private_key: RSA private key object
            
        Returns:
            bytes: Digital signature
        """
        signature = private_key.sign(
            data,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(data, signature, public_key):
        """
        Verify a digital signature using RSA-2048 public key.
        
        Args:
            data (bytes): Original data
            signature (bytes): Signature to verify
            public_key: RSA public key object
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                data,
                rsa_padding.PSS(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    salt_length=rsa_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def hybrid_encrypt(data, bank_public_key):
        """
        Hybrid encryption: Generate AES session key, encrypt data with AES,
        and encrypt session key with RSA.
        
        This is the typical flow for ATM-Bank communication:
        1. Generate random AES session key
        2. Encrypt data with AES-256-CBC
        3. Encrypt AES session key with RSA-2048 (bank's public key)
        
        Args:
            data (bytes): Plaintext data to encrypt
            bank_public_key: Bank's RSA public key
        
        Returns:
            dict: {
                'encrypted_data': bytes,  # AES-encrypted data
                'encrypted_session_key': bytes,  # RSA-encrypted AES key
                'iv': bytes  # AES initialization vector
            }
        """
        # Generate AES session key
        session_key = ATMCryptoUtils.generate_aes_session_key()
        
        # Encrypt data with AES
        encrypted_data, iv = ATMCryptoUtils.encrypt_aes(data, session_key)
        
        # Encrypt session key with RSA
        encrypted_session_key = ATMCryptoUtils.encrypt_rsa(session_key, bank_public_key)
        
        return {
            'encrypted_data': encrypted_data,
            'encrypted_session_key': encrypted_session_key,
            'iv': iv
        }
    
    @staticmethod
    def hybrid_decrypt(encrypted_package, bank_private_key):
        """
        Hybrid decryption: Decrypt RSA-encrypted session key, then decrypt
        AES-encrypted data.
        
        This is used by the bank to decrypt ATM messages:
        1. Decrypt AES session key with RSA private key
        2. Decrypt data with AES-256-CBC using session key
        
        Args:
            encrypted_package (dict): {
                'encrypted_data': bytes,
                'encrypted_session_key': bytes,
                'iv': bytes
            }
            bank_private_key: Bank's RSA private key
        
        Returns:
            bytes: Decrypted plaintext data
        """
        # Decrypt session key with RSA
        session_key = ATMCryptoUtils.decrypt_rsa(
            encrypted_package['encrypted_session_key'],
            bank_private_key
        )
        
        # Decrypt data with AES
        plaintext = ATMCryptoUtils.decrypt_aes(
            encrypted_package['encrypted_data'],
            session_key,
            encrypted_package['iv']
        )
        
        return plaintext


# Example usage and testing
if __name__ == "__main__":
    # Example: ATM encrypting a message to send to Bank
    print("=== ATM-Bank Secure Communication Demo ===\n")
    
    # Bank generates RSA key pair
    print("1. Bank generating RSA-2048 key pair...")
    bank_private_key, bank_public_key = ATMCryptoUtils.generate_rsa_key_pair()
    print("   ✓ RSA key pair generated\n")
    
    # ATM prepares a message
    atm_message = b"ATM Transaction: Withdraw $100 from account 123456789"
    print(f"2. ATM message: {atm_message.decode()}\n")
    
    # ATM encrypts message using hybrid encryption
    print("3. ATM encrypting message (hybrid: RSA + AES-256-CBC)...")
    encrypted_package = ATMCryptoUtils.hybrid_encrypt(atm_message, bank_public_key)
    print(f"   ✓ Encrypted data length: {len(encrypted_package['encrypted_data'])} bytes")
    print(f"   ✓ Encrypted session key length: {len(encrypted_package['encrypted_session_key'])} bytes")
    print(f"   ✓ IV length: {len(encrypted_package['iv'])} bytes\n")
    
    # Bank decrypts the message
    print("4. Bank decrypting message...")
    decrypted_message = ATMCryptoUtils.hybrid_decrypt(encrypted_package, bank_private_key)
    print(f"   ✓ Decrypted message: {decrypted_message.decode()}\n")
    
    # Verify encryption/decryption worked correctly
    if atm_message == decrypted_message:
        print("✓ SUCCESS: Encryption and decryption verified!")
    else:
        print("✗ ERROR: Decrypted message does not match original!")
    
    # Demonstrate individual AES encryption/decryption
    print("\n=== Individual AES-256-CBC Demo ===\n")
    aes_key = ATMCryptoUtils.generate_aes_session_key()
    test_data = b"Test data for AES encryption"
    encrypted, iv = ATMCryptoUtils.encrypt_aes(test_data, aes_key)
    decrypted = ATMCryptoUtils.decrypt_aes(encrypted, aes_key, iv)
    print(f"Original: {test_data.decode()}")
    print(f"Decrypted: {decrypted.decode()}")
    print(f"Match: {test_data == decrypted}")

