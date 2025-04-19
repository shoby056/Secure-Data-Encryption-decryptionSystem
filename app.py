import streamlit as st
import json
import base64
import hashlib
from cryptography.fernet import Fernet
import os

st.title("🔐 Secure Data Encryption System Using Streamlit")

# Create Fernet key from passkey
def generate_key(passkey):
    return base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())

# JSON file patha
FILE_PATH = "data.json"

# Save encrypted data to JSON file
def save_to_json(encrypted_data):
    with open(FILE_PATH, "w") as file:
        json.dump({"encrypted_data": encrypted_data.decode()}, file)

# Load encrypted data from JSON file
def load_from_json():
    if os.path.exists(FILE_PATH):
        with open(FILE_PATH, "r") as file:
            return json.load(file).get("encrypted_data")
    return None

# Inputs
passkey = st.text_input("🔑 Enter your passkey", type="password")
new_message = st.text_area("✍️ Enter message to encrypt and save")

# Encrypt and save (without showing hexacode)
if st.button("🔐 Encrypt & Save to JSON"):
    if passkey and new_message:
        key = generate_key(passkey)
        f = Fernet(key)
        encrypted_data = f.encrypt(new_message.encode())
        save_to_json(encrypted_data)
        st.success("✅ Data encrypted and saved to JSON.")
        st.write("Your data is now securely saved and encrypted. (No hexacode shown)")

# Decrypt by just using passkey
if st.button("🔓 Decrypt from JSON"):
    if passkey:
        encrypted_data = load_from_json()
        if encrypted_data:
            try:
                key = generate_key(passkey)
                f = Fernet(key)
                decrypted = f.decrypt(encrypted_data.encode()).decode()
                st.success("✅ Decrypted Message:")
                st.write(decrypted)
            except:
                st.error("❌ Incorrect passkey! Decryption failed.")
        else:
            st.warning("⚠️ No data found in JSON.")
    else:
        st.warning("⚠️ Please enter your passkey.")
