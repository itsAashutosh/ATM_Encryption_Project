
"""
Flask Web Application for ATM-Bank Secure Communication Simulation
Acts as the ATM Controller.
"""

from flask import Flask, render_template, request, jsonify
import sys
import os
import requests
import base64

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from atm_client import ATMClient
from crypto_utils import ATMCryptoUtils

app = Flask(__name__)
app.secret_key = "atm-client-session-key"

# Initialize ATM Client
atm_client = ATMClient()

@app.route("/")
def index():
    """Main page"""
    public_key_pem = "Connecting to Bank Server..."
    try:
        pk = atm_client._fetch_bank_public_key()
        if pk:
            public_key_pem = ATMCryptoUtils.serialize_public_key(pk).decode("utf-8")
        else:
            public_key_pem = "Error: Could not fetch Bank Public Key. Ensure Port 5003 is running."
    except Exception as e:
        public_key_pem = f"Connection Error: {str(e)}"
        
    return render_template("index.html", bank_public_key=public_key_pem)

@app.route("/encrypt", methods=["POST"])
def encrypt_transaction():
    try:
        data = request.get_json()
        transaction_data = data.get("transaction_data", "")
        
        if not transaction_data:
            return jsonify({"error": "Transaction data is required"}), 400
            
        # 1. Sign
        data_bytes = transaction_data.encode("utf-8")
        signature = ATMCryptoUtils.sign_data(data_bytes, atm_client.private_key)
        
        # 2. Encrypt
        if not atm_client.bank_public_key:
             atm_client.bank_public_key = atm_client._fetch_bank_public_key()
             
        if not atm_client.bank_public_key:
             return jsonify({"error": "Bank Server unavailable (Pre-check failed)"}), 503
             
        encrypted_pkg = ATMCryptoUtils.hybrid_encrypt(data_bytes, atm_client.bank_public_key)
        
        result = {
            "success": True,
            "encrypted_data": base64.b64encode(encrypted_pkg["encrypted_data"]).decode("utf-8"),
            "encrypted_session_key": base64.b64encode(encrypted_pkg["encrypted_session_key"]).decode("utf-8"),
            "iv": base64.b64encode(encrypted_pkg["iv"]).decode("utf-8"),
            "signature": base64.b64encode(signature).decode("utf-8"),
            "message": "Data Encrypted & Signed by ATM"
        }
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/decrypt", methods=["POST"])
def proxy_to_bank():
    """
    Proxies the encrypted packet to the Bank Server.
    The frontend calls this "decrypt", but backend-wise it is "Process Transaction".
    """
    try:
        data = request.get_json()
        
        # Construct payload for Bank
        payload = {
            "encrypted_data": data.get("encrypted_data"),
            "encrypted_session_key": data.get("encrypted_session_key"),
            "iv": data.get("iv"),
            "signature": data.get("signature", "")
        }
        
        # Send to Bank
        try:
             response = requests.post(f"{atm_client.bank_url}/transaction/process", json=payload)
        except Exception as e:
             return jsonify({"error": f"Connection to Bank failed: {str(e)}"}), 503
        
        if response.status_code != 200:
             try:
                 err = response.json().get("error", response.text)
             except:
                 err = response.text
             return jsonify({"error": f"Bank Error: {err}"}), response.status_code
             
        bank_resp = response.json()
        
        # Extract confirmation from Bank Response
        if "data" in bank_resp:
             final_data = bank_resp["data"]
             display_text = (
                 f"Transaction ID: {final_data.get('transaction_id')}\\n"
                 f"Status: {final_data.get('status')}\\n"
                 f"Bank Message: {final_data.get('message')}\\n"
                 f"Timestamp: {final_data.get('timestamp')}"
             )
                            
             return jsonify({
                 "success": True, 
                 "decrypted_data": display_text 
             })
        else:
             return jsonify({"success": False, "error": "Invalid Bank Response format"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("=" * 60)
    print("ATM Client (Frontend Controller)")
    print("=" * 60)
    print(f"Running on http://127.0.0.1:5002")
    print(f"Target Bank Server: http://127.0.0.1:5003")
    
    app.run(debug=True, host="127.0.0.1", port=5002)

