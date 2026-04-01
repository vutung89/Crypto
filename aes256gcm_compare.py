"""
=============================================================================
AES-256-GCM — Dùng thư viện chuẩn `cryptography` để đối chiếu kết quả
=============================================================================
Cài đặt: pip install cryptography
=============================================================================
"""

import os
import sys
import struct

# ─────────────────────────────────────────────────────────────────────────────
# REFERENCE IMPLEMENTATION — dùng cryptography.hazmat (AEAD chuẩn)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False
    print("⚠️  Chưa cài thư viện `cryptography`. Chạy: pip install cryptography")


def ref_aes_256_gcm_encrypt(key: bytes,
                              iv:  bytes,
                              plaintext: bytes,
                              aad: bytes = b'') -> tuple:
    """
    Mã hoá AES-256-GCM dùng thư viện `cryptography`.

    Trả về (ciphertext, tag) — tách ra từ output dạng CT||TAG 16-byte.
    """
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("Cần `pip install cryptography`")
    aesgcm = AESGCM(key)
    ct_tag = aesgcm.encrypt(nonce=iv,
                             data=plaintext,
                             associated_data=aad if aad else None)
    # cryptography nối TAG 16-byte vào cuối ciphertext
    return ct_tag[:-16], ct_tag[-16:]


def ref_aes_256_gcm_decrypt(key:        bytes,
                              iv:         bytes,
                              ciphertext: bytes,
                              tag:        bytes,
                              aad:        bytes = b'') -> bytes:
    """
    Giải mã AES-256-GCM dùng thư viện `cryptography`.
    Ném InvalidTag nếu xác thực thất bại.
    """
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("Cần `pip install cryptography`")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce=iv,
                           data=ciphertext + tag,
                           associated_data=aad if aad else None)


# ─────────────────────────────────────────────────────────────────────────────
# SO SÁNH: Pure Python vs cryptography
# ─────────────────────────────────────────────────────────────────────────────

def run_comparison():
    # Import pure implementation
    sys.path.insert(0, '.')
    from aes256gcm_pure import aes_256_gcm_encrypt, aes_256_gcm_decrypt

    SEP  = "─" * 60
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"

    print("=" * 60)
    print("  AES-256-GCM — So sánh Pure Python vs cryptography lib")
    print("=" * 60)

    # ── Test 1: NIST SP 800-38D Test Case 13 ─────────────────────────────
    print(f"\n{SEP}")
    print("Test 1 : NIST TC-13  (empty plaintext, empty AAD)")
    print(SEP)
    key = bytes(32)
    iv  = bytes(12)
    ct_pure, tag_pure = aes_256_gcm_encrypt(key, iv, b'', b'')
    ct_ref,  tag_ref  = ref_aes_256_gcm_encrypt(key, iv, b'', b'')
    print(f"  CT   pure={ct_pure.hex() or '(empty)'} | ref={ct_ref.hex() or '(empty)'}")
    print(f"  Tag  pure={tag_pure.hex()}")
    print(f"  Tag   ref={tag_ref.hex()}")
    print(f"  Match: {PASS if (ct_pure==ct_ref and tag_pure==tag_ref) else FAIL}")

    # ── Test 2: UAV telemetry payload ────────────────────────────────────
    print(f"\n{SEP}")
    print("Test 2 : UAV telemetry payload + AAD (mission header)")
    print(SEP)
    key       = os.urandom(32)
    iv        = os.urandom(12)
    plaintext = b"lat=21.0285,lon=105.8542,alt=120m,spd=18m/s,hdg=045,batt=87%"
    aad       = b"MISSION:UAV-ALPHA-01|SEQ:0042|PROTO:v3"

    ct_pure, tag_pure = aes_256_gcm_encrypt(key, iv, plaintext, aad)
    ct_ref,  tag_ref  = ref_aes_256_gcm_encrypt(key, iv, plaintext, aad)

    print(f"  Plaintext : {plaintext.decode()}")
    print(f"  AAD       : {aad.decode()}")
    print(f"  Key       : {key.hex()}")
    print(f"  IV        : {iv.hex()}")
    print(f"  CT  pure  : {ct_pure.hex()}")
    print(f"  CT  ref   : {ct_ref.hex()}")
    print(f"  Tag pure  : {tag_pure.hex()}")
    print(f"  Tag ref   : {tag_ref.hex()}")
    match_ct  = ct_pure  == ct_ref
    match_tag = tag_pure == tag_ref
    print(f"  CT  match : {PASS if match_ct  else FAIL}")
    print(f"  Tag match : {PASS if match_tag else FAIL}")

    # ── Test 3: Decrypt cross-check ──────────────────────────────────────
    print(f"\n{SEP}")
    print("Test 3 : Decrypt cross-check")
    print("         Pure encrypt → Ref decrypt  (và ngược lại)")
    print(SEP)

    # Pure encrypt → Ref decrypt
    ct_p, tag_p = aes_256_gcm_encrypt(key, iv, plaintext, aad)
    pt_ref = ref_aes_256_gcm_decrypt(key, iv, ct_p, tag_p, aad)
    ok_a = pt_ref == plaintext
    print(f"  Pure→Ref : {PASS if ok_a else FAIL}  '{pt_ref.decode()}'")

    # Ref encrypt → Pure decrypt
    ct_r, tag_r = ref_aes_256_gcm_encrypt(key, iv, plaintext, aad)
    pt_pure = aes_256_gcm_decrypt(key, iv, ct_r, tag_r, aad)
    ok_b = pt_pure == plaintext
    print(f"  Ref→Pure : {PASS if ok_b else FAIL}  '{pt_pure.decode()}'")

    # ── Test 4: Tamper detection ──────────────────────────────────────────
    print(f"\n{SEP}")
    print("Test 4 : Giả mạo 1 byte → phải bị phát hiện (auth fail)")
    print(SEP)
    ct_tampered = bytearray(ct_pure)
    ct_tampered[3] ^= 0xFF                # lật bit byte thứ 4
    try:
        aes_256_gcm_decrypt(key, iv, bytes(ct_tampered), tag_pure, aad)
        print(f"  {FAIL} — Không phát hiện giả mạo!")
    except ValueError as e:
        print(f"  {PASS} — Phát hiện giả mạo: {e}")

    # ── Test 5: Sai AAD → phải bị phát hiện ─────────────────────────────
    print(f"\n{SEP}")
    print("Test 5 : Sai AAD → phải bị phát hiện")
    print(SEP)
    bad_aad = b"MISSION:UAV-ALPHA-01|SEQ:0043|PROTO:v3"   # SEQ bị thay đổi
    try:
        aes_256_gcm_decrypt(key, iv, ct_pure, tag_pure, bad_aad)
        print(f"  {FAIL} — Không phát hiện AAD bị sửa!")
    except ValueError as e:
        print(f"  {PASS} — Phát hiện AAD thay đổi: {e}")

    # ── Test 6: Nhiều block (dữ liệu > 16 bytes) ─────────────────────────
    print(f"\n{SEP}")
    print("Test 6 : Multi-block payload (256 bytes)")
    print(SEP)
    key2 = os.urandom(32)
    iv2  = os.urandom(12)
    pt2  = os.urandom(256)
    aad2 = b"DATALINK-FRAME-HDR"

    ct2_pure, tag2_pure = aes_256_gcm_encrypt(key2, iv2, pt2, aad2)
    ct2_ref,  tag2_ref  = ref_aes_256_gcm_encrypt(key2, iv2, pt2, aad2)
    ok6 = (ct2_pure == ct2_ref) and (tag2_pure == tag2_ref)
    print(f"  CT  match  : {PASS if ct2_pure  == ct2_ref  else FAIL}")
    print(f"  Tag match  : {PASS if tag2_pure == tag2_ref else FAIL}")
    pt2_dec = aes_256_gcm_decrypt(key2, iv2, ct2_pure, tag2_pure, aad2)
    print(f"  Decrypt ok : {PASS if pt2_dec == pt2 else FAIL}")

    # ── Kết luận ─────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    all_ok = (
        match_ct and match_tag and ok_a and ok_b and ok6
    )
    if all_ok:
        print("  ✅  Tất cả test PASS — Pure Python = cryptography lib")
    else:
        print("  ❌  Có test FAIL — kiểm tra lại implementation")
    print("=" * 60)


if __name__ == '__main__':
    run_comparison()
