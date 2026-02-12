cat > README.md << 'EOF'
# ATM–Bank Secure Communication System 🔐

A distributed security simulation demonstrating how real banking networks protect ATM transactions using **Hybrid Encryption, Digital Signatures, and Secure Service Communication**.

This project models a real-world banking architecture where an ATM client communicates with a Bank server over an untrusted network while guaranteeing:

* Confidentiality
* Integrity
* Authentication
* Tamper detection
* Fraud monitoring

---

## 🧠 System Overview

The project evolved from a single-process demo into a **two-service secure distributed system**:

| Component   | Role                                    | Port |
| ----------- | --------------------------------------- | ---- |
| ATM Client  | Encrypts, signs, and sends transactions | 5002 |
| Bank Server | Verifies, decrypts, stores, audits      | 5003 |

Communication happens over HTTP while maintaining real cryptographic guarantees.

---

## 🏗️ Architecture

### ATM Client
* Generates its own RSA key pair
* Fetches Bank public key
* Encrypts transaction using AES-256
* Encrypts AES key using RSA-2048
* Digitally signs the request
* Sends secure payload to Bank server

### Bank Server
* Stores persistent RSA private key
* Verifies ATM signature (authenticity)
* Decrypts AES session key
* Decrypts transaction payload
* Stores transaction in database
* Logs security events & fraud alerts
* Sends signed confirmation response

---

## 🔐 Security Features

### Hybrid Encryption
* AES-256-CBC → encrypts transaction data
* RSA-2048 → encrypts session key

### Digital Signatures
ATM signs every transaction → Bank verifies integrity

### Tampering Detection
Any modification to payload or signature results in rejection

### Fraud Detection
Transactions > $10,000 automatically flagged

### Audit Logging
All events recorded in SQLite security logs

---

## 🗂️ Project Structure

ATM_Encryption_Project/
│
├── atm_app.py
├── bank_server.py
├── crypto_utils.py
│
├── keys/
│   ├── atm_private.pem
│   └── bank_private.pem
│
├── database/
│   └── bank.db
│
├── templates/
│   └── index.html
│
└── README.md

---

## ▶️ How To Run

### 1. Create Environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

### 2. Start Bank Server
venv/bin/python bank_server.py
Runs on http://127.0.0.1:5003

### 3. Start ATM Client
venv/bin/python atm_app.py
Runs on http://127.0.0.1:5002

### 4. Use the System
Open browser:
http://127.0.0.1:5002

Submit a transaction →
ATM signs & encrypts →
Bank verifies & decrypts →
Response returned securely.

---

## 📊 Observability

Transactions:
database/bank.db → transactions table

Security Logs:
database/bank.db → security_logs table

Includes:
Authentication failures
Fraud alerts
Key generation events
Tampering detection

---

## 🧪 Troubleshooting

Port already in use:
lsof -i :5003
kill <PID>

Reset Database:
rm database/bank.db

Regenerate Keys:
rm -rf keys/

Stop Servers:
pkill -f "python.*ATM_Encryption_Project"

---

## 🎯 Learning Objectives
Hybrid Encryption Systems  
Digital Signatures & Authentication  
Secure Key Exchange  
Distributed Service Communication  
Fraud Monitoring Systems  
Security Audit Logging  

---

## ⚠️ Disclaimer
Educational simulation only — not production banking software.

---

## 👨‍💻 Author
Aashutosh Pandey

EOF
