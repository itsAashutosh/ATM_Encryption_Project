# Create / overwrite README.md
cat << 'EOF' > README.md
# ATM–Bank Secure Communication Simulator 🔐

A Flask-based web application that demonstrates secure communication between an ATM and a Bank server using Hybrid Encryption (AES-256 + RSA-2048).

## Overview
This project simulates how ATMs securely transmit financial transaction data to banks.

Flow:
1. ATM encrypts transaction data using AES-256-CBC
2. AES session key encrypted using Bank RSA public key
3. Bank decrypts session key using private key
4. Bank decrypts original transaction data

## Security Concepts
- AES-256-CBC Symmetric Encryption
- RSA-2048 Asymmetric Encryption
- Hybrid Encryption
- Secure Key Exchange
- Base64 transmission encoding

## Tech Stack
Python, Flask, Cryptography Library

## Run Locally
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py

Open browser:
http://127.0.0.1:5002

## Purpose
Educational demonstration of secure banking communication.
EOF
