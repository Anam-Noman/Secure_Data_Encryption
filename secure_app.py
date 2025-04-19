import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# 🔐 Key & Encryption Setup

if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
fernet = Fernet(st.session_state.fernet_key)
# Data Persistence (JSON File)

data_file = 'encrypted_data.json'

def load_data():
    """Load encrypted data from a JSON file."""
    try:
        with open(data_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_data(data):
    """Save encrypted data to a JSON file."""
    with open(data_file, 'w') as f:
        json.dump(data, f)

# 🔑 Utility Functions
def hash_passkey(passkey):
    """Hash passkey using PBKDF2 HMAC."""
    salt = b"some_salt_value"  # Always use a constant salt for simplicity
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passkey.encode()).hex()

def encrypt_text(text):
    """Encrypt the plain text."""
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(cipher):
    """Decrypt the cipher text."""
    return fernet.decrypt(cipher.encode()).decode()

# 🔁 Login & Security Attempts

if "login_passed" not in st.session_state:
    st.session_state.login_passed = True

if "attempts" not in st.session_state:
    st.session_state.attempts = 3

if "lock_time" not in st.session_state:
    st.session_state.lock_time = None

# 🧭 Navigation

menu = ["🏠 Home", "📝 Encrypt Data", "🔓 Retrieve Data", "🔐 Login Page"]
choice = st.sidebar.selectbox("📂 Navigate", menu)

# 🏠 Home Page

if choice == "🏠 Home":
    st.title("🔐 Secure Data Encryption System")
    st.markdown("""
    - Store and retrieve encrypted messages with a secure passkey.
    - System auto-locks after 3 failed attempts.
    - Admin login required to reset failed attempts.
    """)
# 📝 Insert Data Page
elif choice == "📝 Encrypt Data":
    st.subheader("🔒 Encrypt & Store Your Data")

    user_id = st.text_input("👤 Enter a unique ID:")
    plain_text = st.text_area("📨 Enter message:")
    passkey = st.text_input("🔑 Create your passkey:", type="password")

    if st.button("🚀 Encrypt & Save"):
        if user_id and plain_text and passkey:
            encrypted = encrypt_text(plain_text)
            hashed = hash_passkey(passkey)
            
            # Load stored data
            stored_data = load_data()
            stored_data[user_id] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }

            # Save updated data back to JSON file
            save_data(stored_data)

            st.success("✅ Data encrypted and saved successfully!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please fill all fields.")

# 🔓 Retrieve Data Page

elif choice == "🔓 Retrieve Data":
    st.subheader("🔍 Retrieve Your Encrypted Data")

    if not st.session_state.login_passed:
        st.warning("🚫 Too many failed attempts. Please login.")
        st.stop()

    # Lock-out logic
    if st.session_state.lock_time and time.time() < st.session_state.lock_time:
        st.warning("🚫 You are locked out due to multiple failed attempts. Try again later.")
        st.stop()

    user_id = st.text_input("👤 Enter your ID:")
    passkey = st.text_input("🔑 Enter your passkey:", type="password")

    if st.button("🔐 Decrypt"):
        # Load stored data
        stored_data = load_data()
        
        if user_id in stored_data:
            data_entry = stored_data[user_id]
            hashed_input = hash_passkey(passkey)

            if hashed_input == data_entry["passkey"]:
                decrypted = decrypt_text(data_entry["encrypted_text"])
                st.success("✅ Decryption successful!")
                st.code(decrypted, language="text")
                st.session_state.attempts = 3  # Reset attempts
            else:
                st.session_state.attempts -= 1
                st.error(f"❌ Incorrect passkey. Attempts left: {st.session_state.attempts}")

                # Lockout after 3 failed attempts
                if st.session_state.attempts <= 0:
                    st.session_state.lock_time = time.time() + 300  # 5-minute lockout
                    st.session_state.login_passed = False
                    st.warning("🔐 Too many failed attempts. Redirecting to Login Page...")
        else:
            st.error("⚠️ User ID not found.")

# 🔐 Login Page

elif choice == "🔐 Login Page":
    st.subheader("🔐 Admin Login (to reset attempts)")
    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    if st.button("🔓 Login"):
        if username == "Welcome_admin" and password == "0000":
            st.session_state.attempts = 3
            st.session_state.login_passed = True
            st.session_state.lock_time = None
            st.success("✅ Access Restored! Attempts Reset.")
        else:
            st.error("❌ Invalid credentials!")
