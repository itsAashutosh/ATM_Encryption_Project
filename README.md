cat << 'EOF' > README.md
# ATM–Bank Secure Communication Simulator 🔐

A Flask-based web application that demonstrates secure communication between an ATM and a Bank server using **Hybrid Encryption (AES-256 + RSA-2048)**.

The project simulates how sensitive financial transaction data can be securely transmitted over an untrusted network.

---

## 📌 Overview

In real banking systems, ATMs never send transaction data in plain text.
Instead, they use a hybrid encryption model:

1. The ATM encrypts transaction data using **AES-256-CBC**
2. The AES session key is encrypted using the **Bank's RSA-2048 public key**
3. The Bank decrypts the AES key using its private key
4. The Bank decrypts the original transaction securely

This project demonstrates that complete workflow visually in a web interface.

---

## 🧠 Security Concepts Demonstrated

* Symmetric Encryption (AES-256-CBC)
* Asymmetric Encryption (RSA-2048)
* Hybrid Encryption Scheme
* Secure Key Exchange
* Initialization Vector (IV) handling
* Base64 encoding for safe transmission
* Secure session storage in Flask

---

## 🏗️ Tech Stack

* Python
* Flask
* Cryptography Library (PyCA)
* HTML / CSS / JavaScript

---

## 🔄 Application Flow

### ATM Side

1. User enters transaction details
2. Data encrypted using AES-256-CBC
3. AES session key encrypted using Bank RSA public key
4. Encrypted package sent to bank

### Bank Side

1. Bank decrypts AES session key using private key
2. Bank decrypts transaction data using AES
3. Original transaction is recovered securely

---

## 📁 Project Structure

\`\`\`
ATM_Encryption_Project/
│── app.py
│── crypto_utils.py
│── templates/
│     └── index.html
│── requirements.txt
│── README.md
\`\`\`

---

## ▶️ How to Run Locally

### 1. Clone Repository
\`\`\`
git clone https://github.com/YOUR_USERNAME/atm-bank-secure-communication.git
cd atm-bank-secure-communication
\`\`\`

### 2. Create Virtual Environment
\`\`\`
python3 -m venv venv
source venv/bin/activate
\`\`\`

### 3. Install Dependencies
\`\`\`
pip install -r requirements.txt
\`\`\`

### 4. Run Application
\`\`\`
python app.py
\`\`\`

Open browser:
http://127.0.0.1:5002

---

## 🎯 Purpose
This project demonstrates secure transaction handling used in banking systems and payment gateways.

---

## 📚 Learning Outcomes
* Implemented hybrid encryption
* Understood secure key exchange
* Built client-server simulation
* Applied cryptography in a real application

---

## ⚠️ Disclaimer
This project is for educational purposes only.

---

## 👨‍💻 Author
Aashutosh Pandey
EOF
