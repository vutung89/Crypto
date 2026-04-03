
# ============================================================
# DEMO THÊM: GCM MODE — Authenticated Encryption cho UAV
# ============================================================
from Crypto.Cipher import AES as AES_LIB
import os
import struct


def demo_aes256_gcm_uav(key = None, nonce = None, payload = None):
    """
    AES-256-GCM: CTR + GHASH authentication.
    Phù hợp hơn cho UAV nếu cần integrity + confidentiality trong 1 bước.
    """
    from Crypto.Cipher import AES as AES_LIB

    print("\n" + "=" * 65)
    print("  BONUS: AES-256-GCM (Authenticated Encryption)")
    print("  → CTR mode + 128-bit authentication tag")
    print("  → Phát hiện packet tampering tự động")
    print("=" * 65)
    
    # KEY, Nonce
    print(f"\nKEY   = {key.hex()}")
    print(f"NONCE = {nonce.hex()}")
    print(f"\n[PLAINTEXT]  {plaintext.hex()}")



    # Additional Authenticated Data: header MAVLink (không mã hóa, chỉ xác thực)
    aad = struct.pack('>BBBB', 0xFE, 0x09, 1, 1)  # magic, len, sys_id, comp_id

    # Encrypt + authenticate
    cipher_enc = AES_LIB.new(key, AES_LIB.MODE_GCM, nonce=nonce)
    cipher_enc.update(aad)  # AAD không mã hóa nhưng được bảo vệ
    ciphertext, tag = cipher_enc.encrypt_and_digest(payload)

    print(f"[AAD]        {aad.hex()}  (header, không mã hóa)")
    print(f"[CIPHERTEXT] {ciphertext.hex()}")
    print(f"[AUTH TAG]   {tag.hex()}  (16 bytes, phát hiện tamper)")

    # Decrypt + verify
    cipher_dec = AES_LIB.new(key, AES_LIB.MODE_GCM, nonce=nonce)
    cipher_dec.update(aad)
    try:
        plaintext = cipher_dec.decrypt_and_verify(ciphertext, tag)
        print(f"[DECRYPTED]  {plaintext.hex()}")
        print(f"[VERIFY]     ✅ Authentication OK — packet chưa bị tamper")
    except ValueError:
        print(f"[VERIFY]     ❌ Authentication FAIL — packet đã bị tamper!")

def demo_aes256_ctr_uav(key=None, nonce=None, plaintext=None):
    """
    AES-256-CTR: CTR mode for encryption.
    Phù hợp hơn cho UAV nếu chỉ cần confidentiality.
    """
    print("\n" + "=" * 65)
    print("  DEMO: AES-256-CTR (Confidentiality-only Encryption)")
    print("  → CTR mode for encryption")
    print("  → Chỉ cung cấp tính bảo mật, không có xác thực")
    print("=" * 65)

    # KEY, Nonce
    print(f"\nKEY   = {key.hex()}")
    print(f"NONCE = {nonce.hex()}")
    print(f"\n[PLAINTEXT]  {plaintext.hex()}")

    # Encrypt
    cipher_enc = AES_LIB.new(key, AES_LIB.MODE_CTR, nonce=nonce)
    ciphertext = cipher_enc.encrypt(plaintext)
    print(f"[CIPHERTEXT] {ciphertext.hex()}")

    # Decrypt
    cipher_dec = AES_LIB.new(key, AES_LIB.MODE_CTR, nonce=nonce)
    decrypted = cipher_dec.decrypt(ciphertext)
    print(f"[DECRYPTED]  {decrypted.hex()}")
    print(f"[VERIFY]     {'✅ OK' if decrypted == plaintext else '❌ FAIL'}")



if __name__ == "__main__":
    # # Demo GCM
    # demo_aes256_gcm_uav()

    # Demo CTR
    key = bytes.fromhex("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F")
    nonce = bytes.fromhex("DE AD BE EF 01 02 03 04 00 00 00 00")  # 12 bytes
    plaintext = bytes.fromhex("FE 09 2A 01 01")

    demo_aes256_ctr_uav(key=key, nonce=nonce, plaintext=plaintext)