import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# The encrypted domain
ciphertext_b64 = "whQkhfaCW4dvBnzTCDW5rW6KLTU9RiSTcNwWFR/1gNP8rRfd9nuzy53BXr26J/7peazAVzWXDeL02U5ZiAQ1xbh9hBpgXzGf0/ukSaW+9mwFRwVGOnaRwSgyJpJ7KAOK"

# The password
password_b64 = "QWdYdDZUc2R3bTE4Y3p5Y2UycXpwN3RoTDhIbmc2eHc="
password_bytes = base64.b64decode(password_b64)

# The hardcoded salt found in FetchRemoteProfile
salt_bytes = bytes([
    191, 235, 30, 86, 251, 205, 151, 59, 178, 25, 2, 36, 48, 165, 120, 67, 
    0, 61, 86, 68, 210, 30, 98, 185, 212, 241, 128, 231, 230, 195, 57, 65
])

# --- Key Derivation ---
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA1(),
    length=32 + 64, # 32 bytes for Key, 64 for HMAC
    salt=salt_bytes,
    iterations=50000,
    backend=default_backend()
)
key_material = kdf.derive(password_bytes)
aes_key = key_material[:32]

# --- Decryption ---
full_payload = base64.b64decode(ciphertext_b64)

# Extract IV (Skip first 32 bytes used for HMAC)
iv = full_payload[32:48]
encrypted_content = full_payload[48:]

# Decrypt using AES-CBC
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
padded_plaintext = decryptor.update(encrypted_content) + decryptor.finalize()

# Unpad (PKCS7)
unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

print(f"Recovered Domain: {plaintext.decode('utf-8')}")
