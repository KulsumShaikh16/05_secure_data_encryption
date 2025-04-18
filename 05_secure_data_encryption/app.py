import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --------------------- Security Key Setup ---------------------
# Secret Key (In production, store securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --------------------- In-Memory Data Store ---------------------
stored_data = {}  # {"encrypted_text": {"encrypted_text": ..., "passkey": ...}}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# --------------------- Hash Function ---------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --------------------- Encryption ---------------------
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# --------------------- Decryption ---------------------
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for entry in stored_data.values():
        if entry["encrypted_text"] == encrypted_text and entry["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# --------------------- Streamlit UI ---------------------
st.set_page_config(page_title="🔐 Secure Data Vault", layout="centered")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# --------------------- Home ---------------------
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.markdown("""
        This app allows you to:
        - 🔐 Store sensitive data with encryption.
        - 🔓 Retrieve data using your unique passkey.
        - 🚫 Auto-lock on multiple failed attempts.
    """)

# --------------------- Store Data ---------------------
elif choice == "Store Data":
    st.subheader("📁 Store Your Data")
    user_data = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language='text')
        else:
            st.error("❌ Both fields are required!")

# --------------------- Retrieve Data ---------------------
elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Your Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("🚫 Too many failed attempts. Please reauthorize.")
        st.switch_page("Login")  # Requires streamlit >=1.22
    else:
        encrypted_input = st.text_area("Paste Encrypted Text:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_input and passkey:
                decrypted = decrypt_data(encrypted_input, passkey)
                if decrypted:
                    st.success("✅ Data decrypted successfully!")
                    st.text_area("Decrypted Text:", decrypted, height=150)
                else:
                    st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ Please fill in both fields.")

# --------------------- Login ---------------------
elif choice == "Login":
    st.subheader("🔐 Reauthorization")
    login_input = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_input == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in successfully! You may now return to 'Retrieve Data'.")
        else:
            st.error("❌ Incorrect master password!")
