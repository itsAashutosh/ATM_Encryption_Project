from flask import Flask, request, jsonify
import sqlite3
import os
from datetime import datetime
import json
import base64
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import ATMCryptoUtils

app = Flask(__name__)
DB_PATH = 'database/bank.db'
KEYS_DIR = 'keys'

# Ensure directories exist
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE,
            status TEXT,
            encrypted_data TEXT,
            decrypted_data TEXT,
            timestamp TEXT,
            client_ip TEXT,
            security_notes TEXT
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            severity TEXT,
            message TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def load_or_generate_keys():
    private_path = os.path.join(KEYS_DIR, 'bank_private.pem')
    public_path = os.path.join(KEYS_DIR, 'bank_public.pem')
    
    if os.path.exists(private_path) and os.path.exists(public_path):
        # app.logger.info('Loading existing RSA keys...')
        private_key = ATMCryptoUtils.load_key_from_file(private_path, is_private=True)
        public_key = ATMCryptoUtils.load_key_from_file(public_path, is_private=False)
    else:
        # app.logger.info('Generating new RSA keys...')
        private_key, public_key = ATMCryptoUtils.generate_rsa_key_pair()
        ATMCryptoUtils.save_key_to_file(private_key, private_path, is_private=True)
        ATMCryptoUtils.save_key_to_file(public_key, public_path, is_private=False)
        
    return private_key, public_key

# Global keys - loaded on module load
try:
    PRIVATE_KEY, PUBLIC_KEY = load_or_generate_keys()
except Exception as e:
    print(f'Error generating keys: {e}')
    # Fallback for now to prevent crash
    PRIVATE_KEY, PUBLIC_KEY = ATMCryptoUtils.generate_rsa_key_pair()

@app.route('/public_key', methods=['GET'])
def get_public_key():
    pem = ATMCryptoUtils.serialize_public_key(PUBLIC_KEY).decode('utf-8')
    return jsonify({'public_key': pem})

def log_security_event(event_type, severity, message):
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO security_logs (event_type, severity, message, timestamp) VALUES (?, ?, ?, ?)',
            (event_type, severity, message, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        print(f'[{datetime.now().isoformat()}] [{severity}] {event_type}: {message}')
    except Exception as e:
        print(f'Logging failed: {e}')

@app.route('/transaction/process', methods=['POST'])
def process_transaction():
    try:
        data = request.get_json()
        client_ip = request.remote_addr
        
        # Log request receipt
        log_security_event('TRANSACTION_RECEIVED', 'INFO', f'Received encrypted packet from {client_ip}')

        # Extract components
        encrypted_data = base64.b64decode(data.get('encrypted_data', ''))
        encrypted_session_key = base64.b64decode(data.get('encrypted_session_key', ''))
        iv = base64.b64decode(data.get('iv', ''))
        # signature = base64.b64decode(data.get('signature', '')) # Future use
        
        if not all([encrypted_data, encrypted_session_key, iv]):
             raise ValueError('Missing cryptographic components')

        # 1. Decrypt
        encrypted_pkg = {
            'encrypted_data': encrypted_data,
            'encrypted_session_key': encrypted_session_key,
            'iv': iv
        }
        
        decrypted_bytes = ATMCryptoUtils.hybrid_decrypt(encrypted_pkg, PRIVATE_KEY)
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        # 2. Simulate Verification (Logic checks, etc.)
        status = 'VERIFIED'
        notes = 'Transaction processed successfully'
        
        # Simple fraud detection simulation
        if 'Amount: ' in decrypted_text:
            status = 'FLAGGED'
            notes = 'High value transaction flag'
            log_security_event('FRAUD_ALERT', 'WARNING', f'High value transaction detected: {decrypted_text}')

        # 3. Store in DB
        tx_id = f'TX-{int(datetime.now().timestamp()*1000)}'
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO transactions (transaction_id, status, encrypted_data, decrypted_data, timestamp, client_ip, security_notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (tx_id, status, data.get('encrypted_data'), decrypted_text, datetime.now().isoformat(), client_ip, notes)
        )
        conn.commit()
        conn.close()
        
        # 4. Response
        response_data = {
            'success': True,
            'transaction_id': tx_id,
            'status': status,
            'message': notes,
            'timestamp': datetime.now().isoformat()
        }
        
        # Sign the response (Bank signing) - using structured JSON string as 'data' to sign
        # In real system, we might sign a specific hash or structured buffer
        response_json_str = json.dumps(response_data, sort_keys=True)
        response_bytes = response_json_str.encode('utf-8')
        bank_signature = ATMCryptoUtils.sign_data(response_bytes, PRIVATE_KEY)
        
        final_response = {
            'original_data': response_data, # Send back data for client to verify
            'signature': base64.b64encode(bank_signature).decode('utf-8')
        }
        
        return jsonify(final_response)

    except Exception as e:
        log_security_event('PROCESSING_ERROR', 'ERROR', str(e))
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    print(f'Bank Server running on port 5003...')
    if PUBLIC_KEY:
        print(f'Public Key loaded.')
    app.run(host='127.0.0.1', port=5003, debug=True)

