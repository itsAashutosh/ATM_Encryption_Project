
import requests
import json
import base64
import os
import sys
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import ATMCryptoUtils

class ATMClient:
    def __init__(self, bank_url='http://127.0.0.1:5003'):
        self.bank_url = bank_url
        self.keys_dir = 'ATM_Encryption_Project/keys'
        os.makedirs(self.keys_dir, exist_ok=True)
        
        # Load or generate ATM keys
        self.private_key, self.public_key = self._load_or_generate_keys()
        
        # Fetch Bank's public key
        # self.bank_public_key = self._fetch_bank_public_key()
        self.bank_public_key = None

    def _load_or_generate_keys(self):
        private_path = os.path.join(self.keys_dir, 'atm_private.pem')
        public_path = os.path.join(self.keys_dir, 'atm_public.pem')
        
        if os.path.exists(private_path) and os.path.exists(public_path):
            private_key = ATMCryptoUtils.load_key_from_file(private_path, is_private=True)
            public_key = ATMCryptoUtils.load_key_from_file(public_path, is_private=False)
        else:
            private_key, public_key = ATMCryptoUtils.generate_rsa_key_pair()
            ATMCryptoUtils.save_key_to_file(private_key, private_path, is_private=True)
            ATMCryptoUtils.save_key_to_file(public_key, public_path, is_private=False)
            
        return private_key, public_key

    def _fetch_bank_public_key(self):
        try:
            response = requests.get(f"{self.bank_url}/public_key", timeout=5)
            if response.status_code == 200:
                pem_data = response.json()['public_key'].encode('utf-8')
                return ATMCryptoUtils.deserialize_public_key(pem_data)
            else:
                print(f"Failed to fetch bank key: {response.text}")
                return None
        except Exception as e:
            print(f"Error fetching bank key: {e}")
            return None

    def send_transaction(self, transaction_data):
        """
        Encrypts, signs, and sends transaction data to the bank.
        """
        if not self.bank_public_key:
            self.bank_public_key = self._fetch_bank_public_key()
            if not self.bank_public_key:
                raise Exception("Cannot communicate with Bank: Public Key unavailable. Ensure Bank Server is running on port 5003.")

        # 1. Sign the raw data (Integrity & Non-Repudiation)
        data_bytes = transaction_data.encode('utf-8')
        signature = ATMCryptoUtils.sign_data(data_bytes, self.private_key)
        
        # 2. Encrypt
        encrypted_pkg = ATMCryptoUtils.hybrid_encrypt(data_bytes, self.bank_public_key)
        
        payload = {
            'encrypted_data': base64.b64encode(encrypted_pkg['encrypted_data']).decode('utf-8'),
            'encrypted_session_key': base64.b64encode(encrypted_pkg['encrypted_session_key']).decode('utf-8'),
            'iv': base64.b64encode(encrypted_pkg['iv']).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8')
        }
        
        # 3. Send
        try:
            response = requests.post(f"{self.bank_url}/transaction/process", json=payload, timeout=10)
        except requests.exceptions.ConnectionError:
            raise Exception("Failed to connect to Bank Server. Is it running?")
        except requests.exceptions.Timeout:
            raise Exception("Connection to Bank Server timed out.")
        
        if response.status_code == 200:
            resp_json = response.json()
            return resp_json
        else:
            try:
                err_msg = response.json().get('error', 'Unknown Error')
            except:
                err_msg = response.text
            raise Exception(f'Bank Error: {err_msg}')

