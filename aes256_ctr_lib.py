"""
AES-256-CTR — Dùng pycryptodome để đối chiếu kết quả với pure Python.

Cài đặt: pip install pycryptodome

Chạy sau khi đã chạy aes256_ctr_pure.py để lấy KEY, NONCE, PLAINTEXT, EXPECTED.
"""

import os
import struct
import time
from Crypto.Cipher import AES


# ============================================================
# WRAPPER: AES-256-CTR dùng pycryptodome
# ============================================================

def aes256_ctr_encrypt_lib(plaintext: bytes, key: bytes, nonce: bytes,
                             initial_counter: int = 0) -> bytes:
    """
    Mã hóa AES-256-CTR dùng pycryptodome.
    nonce_prefix (8 bytes) + counter (8 bytes) theo format pycryptodome.

    Lưu ý: pycryptodome.AES CTR mode dùng nonce (8 bytes) + counter (8 bytes)
    hoặc prefix (12 bytes) + counter (4 bytes) tùy cấu hình.
    Ở đây ta dùng nonce_prefix=12 bytes, counter_len=4 bytes để khớp với
    implementation pure Python (NIST 96+32 bit format).
    """
    assert len(key) == 32
    assert len(nonce) == 12

    cipher = AES.new(
        key,
        AES.MODE_CTR,
        nonce=nonce,              # 12-byte prefix
        initial_value=initial_counter  # 4-byte counter bắt đầu
    )
    return cipher.encrypt(plaintext)


def aes256_ctr_decrypt_lib(ciphertext: bytes, key: bytes, nonce: bytes,
                             initial_counter: int = 0) -> bytes:
    """
    Giải mã AES-256-CTR dùng pycryptodome.
    CTR mode: decrypt = encrypt (dùng cùng hàm cipher.decrypt).
    """
    assert len(key) == 32
    assert len(nonce) == 12

    cipher = AES.new(
        key,
        AES.MODE_CTR,
        nonce=nonce,
        initial_value=initial_counter
    )
    return cipher.decrypt(ciphertext)


# ============================================================
# ĐỐI CHIẾU: Import pure Python implementation
# ============================================================

def cross_check_with_pure_python():
    """
    Chạy cả hai implementation với cùng key/nonce/data,
    so sánh kết quả byte-by-byte.
    """
    # Import pure Python version
    from aes256_ctr_pure import aes256_ctr_xcrypt

    print("=" * 65)
    print("  CROSS-CHECK: Pure Python vs pycryptodome (AES-256-CTR)")
    print("=" * 65)

    # Test cases: từ ngắn đến dài
    test_vectors = [
        ("1 block (16B)",  b"UAV-MAVLINK-HELO"),
        ("1.5 blocks (24B)", b"HEARTBEAT_PAYLOAD_MSG0"),
        ("3 blocks (48B)", os.urandom(48)),
        ("Arbitrary (37B)", os.urandom(37)),
        ("Large (1024B)",  os.urandom(1024)),
    ]

    key   = os.urandom(32)
    nonce = os.urandom(12)

    print(f"\nKEY   = {key.hex()}")
    print(f"NONCE = {nonce.hex()}\n")

    all_pass = True
    for name, plaintext in test_vectors:
        # Pure Python
        t0 = time.perf_counter()
        ct_pure = aes256_ctr_xcrypt(plaintext, key, nonce)
        t_pure = (time.perf_counter() - t0) * 1e6

        # pycryptodome
        t0 = time.perf_counter()
        ct_lib = aes256_ctr_encrypt_lib(plaintext, key, nonce)
        t_lib = (time.perf_counter() - t0) * 1e6

        # Decrypt bằng cả hai
        pt_pure = aes256_ctr_xcrypt(ct_pure, key, nonce)
        pt_lib  = aes256_ctr_decrypt_lib(ct_lib, key, nonce)

        enc_match = ct_pure == ct_lib
        dec_match_pure = pt_pure == plaintext
        dec_match_lib  = pt_lib  == plaintext
        ok = enc_match and dec_match_pure and dec_match_lib
        all_pass = all_pass and ok

        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"[{status}] {name:<20} | pure={t_pure:6.1f}µs | lib={t_lib:5.1f}µs"
              f" | enc_match={enc_match} | dec_ok_pure={dec_match_pure} | dec_ok_lib={dec_match_lib}")

        if not enc_match:
            print(f"         Pure: {ct_pure.hex()[:64]}...")
            print(f"         Lib:  {ct_lib.hex()[:64]}...")

    print(f"\n{'✅ TẤT CẢ TEST PASS' if all_pass else '❌ CÓ TEST FAIL'}")
    return all_pass


# ============================================================
# DEMO THÊM: GCM MODE — Authenticated Encryption cho UAV
# ============================================================

def demo_aes256_gcm_uav():
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

    # key   = os.urandom(32)
    # nonce = os.urandom(12)  # GCM dùng 12-byte nonce (96-bit)
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    nonce = bytes.fromhex("DEADBEEF0102030400000000")  # 12 bytes

    # Additional Authenticated Data: header MAVLink (không mã hóa, chỉ xác thực)
    aad = struct.pack('>BBBB', 0xFE, 0x09, 1, 1)  # magic, len, sys_id, comp_id

    payload = b'\x00\x00\x00\x01\x06\x08\xC1\x00\x03'  # HEARTBEAT payload

    # Encrypt + authenticate
    cipher_enc = AES_LIB.new(key, AES_LIB.MODE_GCM, nonce=nonce)
    cipher_enc.update(aad)  # AAD không mã hóa nhưng được bảo vệ
    ciphertext, tag = cipher_enc.encrypt_and_digest(payload)

    print(f"\n[PAYLOAD]    {payload.hex()}")
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

    # Giả lập attacker flip 1 bit
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    cipher_dec2 = AES_LIB.new(key, AES_LIB.MODE_GCM, nonce=nonce)
    cipher_dec2.update(aad)
    try:
        cipher_dec2.decrypt_and_verify(bytes(tampered), tag)
        print("[TAMPER]     ❌ FAIL — không phát hiện tamper")
    except ValueError:
        print("[TAMPER]     ✅ PASS — phát hiện tamper thành công!")

def demo_aes256_ctr_uav(key=None, nonce=None, plaintext=None):
    """
    AES-256-CTR: CTR mode for encryption.
    Phù hợp hơn cho UAV nếu chỉ cần confidentiality.
    """
    from Crypto.Cipher import AES as AES_LIB
    print("\n" + "=" * 65)
    print("  DEMO: AES-256-CTR (Confidentiality-only Encryption)")
    print("  → CTR mode for encryption")
    print("  → Chỉ cung cấp tính bảo mật, không có xác thực")
    print("=" * 65)

    # KEY, Nonce
    print(f"\nKEY   = {key.hex()}")
    print(f"NONCE = {nonce.hex()}")
    # Encrypt
    cipher_enc = AES_LIB.new(key, AES_LIB.MODE_CTR, nonce=nonce)
    ciphertext = cipher_enc.encrypt(plaintext)
    print(f"\n[PLAINTEXT]  {plaintext.hex()}")
    print(f"[CIPHERTEXT] {ciphertext.hex()}")

    # Decrypt
    cipher_dec = AES_LIB.new(key, AES_LIB.MODE_CTR, nonce=nonce)
    decrypted = cipher_dec.decrypt(ciphertext)
    print(f"[DECRYPTED]  {decrypted.hex()}")
    print(f"[VERIFY]     {'✅ OK' if decrypted == plaintext else '❌ FAIL'}")



if __name__ == "__main__":
    # Chạy cross-check
    cross_check_with_pure_python()

    # # Demo GCM
    # demo_aes256_gcm_uav()

    # Demo CTR
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    nonce = bytes.fromhex("DEADBEEF0102030400000000")  # 12 bytes
    # plaintext = b'\x00\x00\x00\x01\x06\x08\xC1\x00\x03'  # HEARTBEAT payload
    
    plaintext = bytes.fromhex("FE 09 2A 01 01")

    demo_aes256_ctr_uav(key=key, nonce=nonce, plaintext=plaintext)
