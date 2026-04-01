"""
=============================================================================
AES-256-GCM — Thuần Python, không dùng thư viện ngoài
=============================================================================

Các bước:
  1. AES-256 key expansion  (Nk=8, Nr=14 rounds)
  2. AES block encrypt      (SubBytes, ShiftRows, MixColumns, AddRoundKey)
  3. GF(2^128) multiply     (phép nhân đa thức trên trường GF(2^128))
  4. GHASH                  (xác thực toàn vẹn dữ liệu)
  5. CTR mode + Tag         (mã hoá + sinh tag 128-bit)

Tham khảo chuẩn: NIST SP 800-38D (GCM), FIPS 197 (AES)
=============================================================================
"""

import struct
import os

# ─────────────────────────────────────────────────────────────────────────────
# 1. AES LOOKUP TABLES
# ─────────────────────────────────────────────────────────────────────────────

# AES S-Box (Substitution Box) — 256 giá trị thay thế phi tuyến
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# Round Constants cho Key Expansion (AES-256 cần tối đa Rcon[6])
RCON = [
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,
]

# ─────────────────────────────────────────────────────────────────────────────
# 2. PHÉP NHÂN TRONG GF(2^8) — dùng cho MixColumns
# ─────────────────────────────────────────────────────────────────────────────

def gmul8(a: int, b: int) -> int:
    """
    Nhân a và b trong GF(2^8) với đa thức tối giản 0x11b
    (x^8 + x^4 + x^3 + x + 1).

    Thuật toán: Russian Peasant Multiplication — mỗi vòng:
      - Nếu LSB của b = 1: XOR kết quả với a
      - Nhân a với x (shift trái + giảm modulo)
      - Shift phải b
    """
    p = 0
    for _ in range(8):
        if b & 1:          # nếu bit thấp của b = 1
            p ^= a
        msb = a & 0x80     # lưu MSB của a trước khi shift
        a = (a << 1) & 0xff
        if msb:            # nếu bị tràn → XOR với đa thức tối giản (trừ x^8)
            a ^= 0x1b
        b >>= 1
    return p

# ─────────────────────────────────────────────────────────────────────────────
# 3. AES-256 KEY EXPANSION
# ─────────────────────────────────────────────────────────────────────────────

def _sub_word(w: int) -> int:
    """Áp dụng SBOX lên từng byte của một 32-bit word."""
    return (SBOX[(w >> 24) & 0xff] << 24 |
            SBOX[(w >> 16) & 0xff] << 16 |
            SBOX[(w >>  8) & 0xff] <<  8 |
            SBOX[ w        & 0xff])

def _rot_word(w: int) -> int:
    """Xoay vòng trái 8 bit của một 32-bit word: [a,b,c,d] → [b,c,d,a]."""
    return ((w << 8) | (w >> 24)) & 0xffffffff

def key_expansion(key: bytes) -> list:
    """
    AES-256 Key Expansion.

    Đầu vào : 32-byte key (256-bit)
    Đầu ra  : 15 round keys (mỗi cái 16 byte) → danh sách 15 phần tử

    AES-256: Nk=8 (8 words/key), Nr=14 (14 rounds), 4*(Nr+1)=60 words cần.

    Lịch trình mở rộng:
      W[i] = W[i-Nk] XOR temp
      temp tính từ W[i-1]:
        - Nếu i % Nk == 0 : SubWord(RotWord(W[i-1])) XOR Rcon[i/Nk]
        - Nếu i % Nk == 4 : SubWord(W[i-1])          (đặc trưng AES-256)
        - Còn lại          : W[i-1]
    """
    assert len(key) == 32, "AES-256 cần key 32 bytes"
    Nk, Nr = 8, 14
    W = list(struct.unpack('>8I', key))          # 8 word đầu từ key

    for i in range(Nk, 4 * (Nr + 1)):
        temp = W[i - 1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[i // Nk - 1] << 24)
        elif i % Nk == 4:
            temp = _sub_word(temp)
        W.append(W[i - Nk] ^ temp)

    # Gộp thành 15 round keys (mỗi cái = 4 word = 16 byte)
    round_keys = []
    for r in range(Nr + 1):
        rk = struct.pack('>4I', W[4*r], W[4*r+1], W[4*r+2], W[4*r+3])
        round_keys.append(rk)
    return round_keys

# ─────────────────────────────────────────────────────────────────────────────
# 4. AES STATE — 4×4 ma trận byte (column-major)
# ─────────────────────────────────────────────────────────────────────────────

def _bytes_to_state(b: bytes) -> list:
    """16 bytes → state[r][c] = b[r + 4*c]  (column-major theo AES FIPS 197)."""
    return [[b[r + 4*c] for c in range(4)] for r in range(4)]

def _state_to_bytes(s: list) -> bytes:
    """State → 16 bytes (column-major)."""
    return bytes(s[r][c] for c in range(4) for r in range(4))

def _add_round_key(state: list, rk: bytes) -> list:
    """XOR từng byte của state với round key tương ứng."""
    k = _bytes_to_state(rk)
    return [[state[r][c] ^ k[r][c] for c in range(4)] for r in range(4)]

def _sub_bytes(state: list) -> list:
    """Thay thế phi tuyến: mỗi byte → SBOX[byte]."""
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def _shift_rows(state: list) -> list:
    """
    Dịch vòng trái hàng i một khoảng i vị trí:
      Hàng 0: không dịch
      Hàng 1: dịch trái 1
      Hàng 2: dịch trái 2
      Hàng 3: dịch trái 3
    """
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][1], state[1][2], state[1][3], state[1][0]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][3], state[3][0], state[3][1], state[3][2]],
    ]

def _mix_columns(state: list) -> list:
    """
    Nhân từng cột của state với ma trận cố định trong GF(2^8):
        | 2 3 1 1 |
        | 1 2 3 1 |
        | 1 1 2 3 |
        | 3 1 1 2 |
    Mục đích: khuếch tán (diffusion) giữa các byte trong một cột.
    """
    def mix_col(col):
        s0, s1, s2, s3 = col
        return [
            gmul8(2,s0) ^ gmul8(3,s1) ^        s2  ^        s3,
                   s0  ^ gmul8(2,s1) ^ gmul8(3,s2) ^        s3,
                   s0  ^        s1   ^ gmul8(2,s2) ^ gmul8(3,s3),
            gmul8(3,s0) ^       s1   ^        s2  ^ gmul8(2,s3),
        ]
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = mix_col(col)
        for r in range(4):
            result[r][c] = mixed[r]
    return result

# ─────────────────────────────────────────────────────────────────────────────
# 5. AES-256 BLOCK ENCRYPT
# ─────────────────────────────────────────────────────────────────────────────

def aes_encrypt_block(plaintext: bytes, round_keys: list) -> bytes:
    """
    Mã hoá một block 16 byte bằng AES-256 (14 rounds).

    Cấu trúc mỗi round (1..13):
        SubBytes → ShiftRows → MixColumns → AddRoundKey

    Round cuối (14): không có MixColumns.
    """
    assert len(plaintext) == 16
    state = _bytes_to_state(plaintext)

    # Round 0: chỉ AddRoundKey
    state = _add_round_key(state, round_keys[0])

    # Rounds 1..13
    for rnd in range(1, 14):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])

    # Round 14: không MixColumns
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[14])

    return _state_to_bytes(state)

# ─────────────────────────────────────────────────────────────────────────────
# 6. GF(2^128) MULTIPLICATION — dùng cho GHASH
# ─────────────────────────────────────────────────────────────────────────────

_GCM_R = 0xE1 << 120  # = 1110_0001 || 0^120, đa thức tối giản GCM

def _gf128_mul(X: int, Y: int) -> int:
    """
    Nhân X và Y trong GF(2^128) với đa thức tối giản của GCM:
        x^128 + x^7 + x^2 + x + 1
    Biểu diễn dưới dạng số nguyên 128-bit (big-endian, bit 0 = MSB).

    Thuật toán: Double-and-add phải (right-to-left) trên Y:
      Z = 0, V = X
      for bit i từ 0 đến 127 (bit 0 = MSB của Y):
          if bit i của Y = 1: Z ^= V
          if LSB của V = 1:   V = (V >> 1) ^ R
          else:               V >>= 1
    """
    Z = 0
    V = X
    for i in range(128):
        if (Y >> (127 - i)) & 1:    # bit thứ i của Y (MSB trước)
            Z ^= V
        if V & 1:                    # nếu bit thấp nhất (= hệ số x^127) = 1
            V = (V >> 1) ^ _GCM_R
        else:
            V >>= 1
    return Z

# ─────────────────────────────────────────────────────────────────────────────
# 7. GHASH — xác thực toàn vẹn
# ─────────────────────────────────────────────────────────────────────────────

def _ghash(H_bytes: bytes, data: bytes) -> bytes:
    """
    GHASH_H(data):
        Y_0 = 0
        Y_i = (Y_{i-1} XOR X_i) · H   (nhân trong GF(2^128))
    data đã được pad thành bội số của 16 byte.
    Trả về 16 byte.
    """
    H = int.from_bytes(H_bytes, 'big')
    Y = 0
    for i in range(0, len(data), 16):
        block = int.from_bytes(data[i:i+16], 'big')
        Y = _gf128_mul(Y ^ block, H)
    return Y.to_bytes(16, 'big')

def _gcm_pad(data: bytes) -> bytes:
    """Thêm zero-padding cho đến khi len là bội số của 16."""
    rem = len(data) % 16
    return data + (b'\x00' * (16 - rem) if rem else b'')

def _inc32(ctr: bytes) -> bytes:
    """Tăng 4 byte cuối (big-endian) của counter 16-byte lên 1."""
    n = struct.unpack('>I', ctr[12:])[0]
    return ctr[:12] + struct.pack('>I', (n + 1) & 0xffffffff)

# ─────────────────────────────────────────────────────────────────────────────
# 8. CTR MODE ENCRYPT/DECRYPT
# ─────────────────────────────────────────────────────────────────────────────

def _ctr_crypt(data: bytes, J0: bytes, round_keys: list) -> bytes:
    """
    CTR (Counter) mode bắt đầu từ inc32(J0).
    Sinh keystream = AES(ctr_i) rồi XOR với data.
    Dùng được cho cả encrypt lẫn decrypt (CTR là đối xứng).
    """
    ctr = _inc32(J0)
    out = bytearray()
    for i in range(0, len(data), 16):
        keystream = aes_encrypt_block(ctr, round_keys)
        chunk = data[i:i+16]
        out += bytes(a ^ b for a, b in zip(keystream, chunk))
        ctr = _inc32(ctr)
    return bytes(out)

# ─────────────────────────────────────────────────────────────────────────────
# 9. AES-256-GCM ENCRYPT
# ─────────────────────────────────────────────────────────────────────────────

def aes_256_gcm_encrypt(key: bytes,
                         iv:  bytes,
                         plaintext: bytes,
                         aad: bytes = b'') -> tuple:
    """
    AES-256-GCM Encryption.

    Tham số:
        key       : 32 bytes (256-bit)
        iv        : 12 bytes nonce (96-bit, khuyến nghị của NIST)
        plaintext : dữ liệu cần mã hoá
        aad       : Additional Authenticated Data (xác thực nhưng không mã hoá)

    Trả về:
        (ciphertext: bytes, tag: bytes)  — tag luôn dài 16 bytes

    Các bước GCM:
        B1. H   = AES_K(0^128)              — hash subkey
        B2. J0  = IV || 0x00000001          — counter gốc (96-bit IV)
        B3. CT  = CTR_K(J0+1, PT)           — mã hoá bằng CTR
        B4. S   = GHASH_H(pad(AAD) || pad(CT) || len64(AAD) || len64(CT))
        B5. Tag = AES_K(J0) XOR S
    """
    assert len(key) == 32, "Key phải đúng 32 bytes cho AES-256"
    assert len(iv)  == 12, "IV phải đúng 12 bytes (96-bit nonce)"

    rk   = key_expansion(key)
    H    = aes_encrypt_block(b'\x00' * 16, rk)          # B1
    J0   = iv + b'\x00\x00\x00\x01'                     # B2

    ct   = _ctr_crypt(plaintext, J0, rk)                 # B3

    # B4: GHASH input = pad(AAD) || pad(CT) || len(AAD)*8 (64-bit) || len(CT)*8 (64-bit)
    ghash_in = (_gcm_pad(aad) + _gcm_pad(ct)
                + struct.pack('>QQ', len(aad) * 8, len(ct) * 8))
    S   = _ghash(H, ghash_in)

    # B5
    E_J0 = aes_encrypt_block(J0, rk)
    tag  = bytes(a ^ b for a, b in zip(E_J0, S))        # B5

    return ct, tag

# ─────────────────────────────────────────────────────────────────────────────
# 10. AES-256-GCM DECRYPT
# ─────────────────────────────────────────────────────────────────────────────

def _ct_compare(a: bytes, b: bytes) -> bool:
    """
    So sánh hằng thời gian (constant-time) để tránh timing attack.
    Luôn chạy đủ vòng lặp dù tìm thấy khác biệt từ sớm.
    """
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0

def aes_256_gcm_decrypt(key:        bytes,
                         iv:         bytes,
                         ciphertext: bytes,
                         tag:        bytes,
                         aad:        bytes = b'') -> bytes:
    """
    AES-256-GCM Decryption + Authentication.

    Xác thực tag TRƯỚC khi giải mã (fail-fast, tránh oracle attacks).
    Ném ValueError nếu tag không khớp (dữ liệu có thể bị giả mạo).

    Trả về: plaintext (bytes)
    """
    assert len(key) == 32
    assert len(iv)  == 12

    rk   = key_expansion(key)
    H    = aes_encrypt_block(b'\x00' * 16, rk)
    J0   = iv + b'\x00\x00\x00\x01'

    # Tái tính tag từ ciphertext nhận được
    ghash_in = (_gcm_pad(aad) + _gcm_pad(ciphertext)
                + struct.pack('>QQ', len(aad) * 8, len(ciphertext) * 8))
    S    = _ghash(H, ghash_in)
    E_J0 = aes_encrypt_block(J0, rk)
    expected_tag = bytes(a ^ b for a, b in zip(E_J0, S))

    # Xác thực tag (constant-time)
    if not _ct_compare(tag, expected_tag):
        raise ValueError(
            "❌ GCM Authentication FAILED — tag không khớp!\n"
            "   Dữ liệu có thể bị giả mạo hoặc key/IV sai."
        )

    # Giải mã CTR (giống hệt encrypt)
    plaintext = _ctr_crypt(ciphertext, J0, rk)
    return plaintext


# ─────────────────────────────────────────────────────────────────────────────
# QUICK SELF-TEST với NIST test vector
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # NIST SP 800-38D — Test Case 13 (AES-256, empty P, empty AAD)
    key_tv = bytes(32)                   # 32 bytes 0x00
    iv_tv  = bytes(12)                   # 12 bytes 0x00
    ct_tv, tag_tv = aes_256_gcm_encrypt(key_tv, iv_tv, b'', b'')

    expected_tag = bytes.fromhex('530f8afbc74536b9a963b4f1c4cb738b')
    ok = tag_tv == expected_tag
    print(f"[NIST TC-13] Tag match: {'✅ PASS' if ok else '❌ FAIL'}")
    print(f"  Got      : {tag_tv.hex()}")
    print(f"  Expected : {expected_tag.hex()}")
