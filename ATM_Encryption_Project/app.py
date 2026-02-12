"""
Flask Web Application for ATM-Bank Secure Communication Simulation

This application simulates:
- ATM encrypting transaction data using AES-256-CBC
- RSA public key encrypting the AES session key
- Bank decrypting the AES key and transaction data
"""

from flask import Flask, render_template, request, jsonify, session
from cryptography.hazmat.primitives import serialization
import json
import base64
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import ATMCryptoUtils

app = Flask(__name__)
app.secret_key = 'atm-bank-secure-session-key-change-in-production'

# In a real application, the bank's RSA key pair would be stored securely
# For this simulation, we generate it once and store it in session
def get_bank_keys():
    """Get or generate bank's RSA key pair"""
    if 'bank_private_key' not in session or 'bank_public_key' not in session:
        # Generate new key pair
        private_key, public_key = ATMCryptoUtils.generate_rsa_key_pair()
        
        # Serialize keys to bytes, then encode as base64 strings for session storage
        private_key_bytes = ATMCryptoUtils.serialize_private_key(private_key)
        public_key_bytes = ATMCryptoUtils.serialize_public_key(public_key)
        
        # Store as base64-encoded strings in session (Flask sessions need strings)
        session['bank_private_key'] = base64.b64encode(private_key_bytes).decode('utf-8')
        session['bank_public_key'] = base64.b64encode(public_key_bytes).decode('utf-8')
    
    # Decode from base64 and deserialize keys from session
    private_key_bytes = base64.b64decode(session['bank_private_key'].encode('utf-8'))
    public_key_bytes = base64.b64decode(session['bank_public_key'].encode('utf-8'))
    
    private_key = ATMCryptoUtils.deserialize_private_key(private_key_bytes)
    public_key = ATMCryptoUtils.deserialize_public_key(public_key_bytes)
    
    return private_key, public_key


@app.route('/')
def index():
    """Main page showing the encryption/decryption interface"""
    _, public_key = get_bank_keys()
    
    # Serialize public key for display
    public_key_pem = ATMCryptoUtils.serialize_public_key(public_key).decode('utf-8')
    
    return render_template('index.html', bank_public_key=public_key_pem)


@app.route('/encrypt', methods=['POST'])
def encrypt_transaction():
    """
    ATM side: Encrypt transaction data
    
    This endpoint simulates the ATM encrypting transaction data:
    1. Receives transaction data from the form
    2. Encrypts data with AES-256-CBC
    3. Encrypts AES session key with RSA public key
    4. Returns encrypted package
    """
    try:
        data = request.get_json()
        transaction_data = data.get('transaction_data', '').encode('utf-8')
        
        if not transaction_data:
            return jsonify({'error': 'Transaction data is required'}), 400
        
        # Get bank's public key
        _, public_key = get_bank_keys()
        
        # Encrypt using hybrid encryption (RSA + AES-256-CBC)
        encrypted_package = ATMCryptoUtils.hybrid_encrypt(transaction_data, public_key)
        
        # Encode binary data to base64 for JSON transmission
        result = {
            'success': True,
            'encrypted_data': base64.b64encode(encrypted_package['encrypted_data']).decode('utf-8'),
            'encrypted_session_key': base64.b64encode(encrypted_package['encrypted_session_key']).decode('utf-8'),
            'iv': base64.b64encode(encrypted_package['iv']).decode('utf-8'),
            'original_data': transaction_data.decode('utf-8'),
            'message': 'Transaction data encrypted successfully'
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/decrypt', methods=['POST'])
def decrypt_transaction():
    """
    Bank side: Decrypt transaction data
    
    This endpoint simulates the bank decrypting the transaction:
    1. Receives encrypted package (encrypted_data, encrypted_session_key, iv)
    2. Decrypts AES session key with RSA private key
    3. Decrypts transaction data with AES-256-CBC
    4. Returns decrypted transaction data
    """
    try:
        data = request.get_json()
        
        # Decode base64 strings back to bytes
        encrypted_data = base64.b64decode(data.get('encrypted_data', ''))
        encrypted_session_key = base64.b64decode(data.get('encrypted_session_key', ''))
        iv = base64.b64decode(data.get('iv', ''))
        
        if not all([encrypted_data, encrypted_session_key, iv]):
            return jsonify({'error': 'All encrypted components are required'}), 400
        
        # Get bank's private key
        private_key, _ = get_bank_keys()
        
        # Create encrypted package dictionary
        encrypted_package = {
            'encrypted_data': encrypted_data,
            'encrypted_session_key': encrypted_session_key,
            'iv': iv
        }
        
        # Decrypt using hybrid decryption
        decrypted_data = ATMCryptoUtils.hybrid_decrypt(encrypted_package, private_key)
        
        result = {
            'success': True,
            'decrypted_data': decrypted_data.decode('utf-8'),
            'message': 'Transaction data decrypted successfully'
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """Get bank's public key in PEM format"""
    _, public_key = get_bank_keys()
    
    public_key_pem = ATMCryptoUtils.serialize_public_key(public_key).decode('utf-8')
    
    return jsonify({
        'public_key': public_key_pem,
        'key_size': 'RSA-2048'
    })


if __name__ == '__main__':
    print("=" * 60)
    print("ATM-Bank Secure Communication Simulation")
    print("=" * 60)
    print("\nStarting Flask server...")
    print("Open your browser and navigate to: http://127.0.0.1:5002")
    print("\nFeatures:")
    print("  - AES-256-CBC encryption for transaction data")
    print("  - RSA-2048 encryption for AES session key")
    print("  - Hybrid encryption/decryption flow")
    print("=" * 60 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5002)

