from cryptography.fernet import Fernet
import os

class Encryptor:
    # Generate a valid Fernet key using: Fernet.generate_key()
    # This is a valid 32-byte base64 encoded key
    FIXED_KEY = b'YOUR_SECURE_KEY_HERE_32_BYTES_BASE64_ENCODED_'

    def __init__(self, key=None):
        if key:
            self.key = key
        else:
            # Use environment variable or generate a new key
            env_key = os.environ.get('IOT_COMPILER_KEY')
            if env_key:
                self.key = env_key.encode() if isinstance(env_key, str) else env_key
            else:
                # Generate a fresh valid key (this will work every time)
                self.key = Fernet.generate_key()
        
        self.cipher = Fernet(self.key)

    def encrypt(self, data):
        """Encrypt data using Fernet"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)

    def decrypt(self, encrypted_data):
        """Decrypt data (for verification)"""
        return self.cipher.decrypt(encrypted_data).decode()

    @staticmethod
    def generate_key():
        """Generate a new Fernet key"""
        return Fernet.generate_key().decode()
    
    def get_key(self):
        """Get the current key (for debugging)"""
        return self.key.decode() if isinstance(self.key, bytes) else self.key