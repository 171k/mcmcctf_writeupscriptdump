#!/usr/bin/env python3
"""
AES/ECB/PKCS5Padding Decryption Script
Decrypts base64-encoded ciphertext using base64-encoded key
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import hashlib

def decrypt_aes_ecb(ciphertext_b64, key_b64):
    """
    Decrypt AES/ECB encrypted data

    Args:
        ciphertext_b64: Base64 encoded ciphertext
        key_b64: Base64 encoded key

    Returns:
        Decrypted plaintext string
    """
    try:
        # Fix base64 padding if needed
        def fix_base64_padding(data):
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            return data

        # Decode base64 ciphertext and key
        ciphertext = base64.b64decode(fix_base64_padding(ciphertext_b64))
        key = base64.b64decode(fix_base64_padding(key_b64))

        print(f"\n[DEBUG] Key length: {len(key)} bytes")
        print(f"[DEBUG] Key (hex): {key.hex()}")
        print(f"[DEBUG] Key (text): {key.decode('utf-8', errors='ignore')}")
        print(f"[DEBUG] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[DEBUG] Ciphertext (hex): {ciphertext.hex()}")

        # Create AES cipher in ECB mode
        cipher = AES.new(key, AES.MODE_ECB)

        # Decrypt
        decrypted_padded = cipher.decrypt(ciphertext)
        print(f"[DEBUG] Decrypted (hex): {decrypted_padded.hex()}")
        print(f"[DEBUG] Decrypted (raw): {decrypted_padded}")

        # Try to remove PKCS5 padding
        try:
            decrypted = unpad(decrypted_padded, AES.block_size)
            return decrypted.decode('utf-8', errors='replace')
        except ValueError as pad_error:
            # Padding might be incorrect, return raw decrypted data
            print(f"[WARNING] Padding error: {pad_error}")
            print("[INFO] Returning raw decrypted data without unpadding...")
            return decrypted_padded.decode('utf-8', errors='replace')

    except Exception as e:
        import traceback
        return f"Decryption failed: {str(e)}\n{traceback.format_exc()}"


def main():
    # ========== FILL THESE VALUES ==========

    # Paste your base64 ciphertext here
    CIPHERTEXT = "bBJNkA2kvfETMiuzUh3PYUQMstHcXPdMZNj2c20oiZwFAWuoq7ll2umX8eNUqhFj"

    # Enter your base64-encoded key here
    KEY_B64 = "NXVwNDUzY3UyNGszeVlvX2p1NTdmMDIxaDRjazIwMjQ"

    # ========================================

    # Clean up ciphertext (remove whitespace/newlines)
    ciphertext_clean = ''.join(CIPHERTEXT.split())

    print("=" * 60)
    print("AES/ECB/PKCS5Padding Decryption")
    print("=" * 60)
    print(f"Key (base64): {KEY_B64}")
    print(f"Ciphertext length: {len(ciphertext_clean)} characters")
    print("=" * 60)

    # Decrypt
    result = decrypt_aes_ecb(ciphertext_clean, KEY_B64)

    print("\nDecrypted Result:")
    print("-" * 60)
    print(result)
    print("-" * 60)


if __name__ == "__main__":
    main()
