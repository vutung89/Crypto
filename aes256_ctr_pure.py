"""
AES-256-CTR (XCRYPT) — Pure Python Implementation
===================================================
Không dùng bất kỳ thư viện ngoài nào.
Mục đích: hiểu từng bước bên trong AES block cipher + CTR mode.

Chuẩn tham chiếu: FIPS PUB 197 (AES), NIST SP 800-38A (CTR mode)

Ứng dụng UAV Datalink:
  - Mã hóa MAVLink payload trước khi truyền qua RF link
  - Nonce = timestamp (4B) + system_id (1B) + component_id (1B) + sequence (2B)
  - Counter tăng theo từng 16-byte block
"""

import os
import struct
import time

# ============================================================
# PHẦN 1: AES CORE — S-BOX, KEY SCHEDULE, CIPHER
# ============================================================

# AES SubBytes S-Box (256 entries, GF(2^8) inverse + affine transform)
_SBOX = [
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

# Round constants dùng trong Key Schedule (x^(i-1) mod GF(2^8))
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def _xtime(a: int) -> int:
    """Nhân a với x (= 0x02) trong GF(2^8) với polynomial x^8+x^4+x^3+x+1."""
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff


def _gmul(a: int, b: int) -> int:
    """Nhân hai phần tử trong GF(2^8) — dùng cho MixColumns."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return result


def _sub_word(word: int) -> int:
    """Áp dụng S-Box cho từng byte của một 32-bit word."""
    return ((_SBOX[(word >> 24) & 0xff] << 24) |
            (_SBOX[(word >> 16) & 0xff] << 16) |
            (_SBOX[(word >>  8) & 0xff] <<  8) |
            (_SBOX[ word        & 0xff]))


def _rot_word(word: int) -> int:
    """Xoay trái 8-bit: [a0,a1,a2,a3] -> [a1,a2,a3,a0]."""
    return ((word << 8) | (word >> 24)) & 0xffffffff


# ============================================================
# PHẦN 2: KEY EXPANSION (AES-256 = Nk=8, Nr=14, 60 words)
# ============================================================

def _key_expansion(key: bytes) -> list[int]:
    """
    Sinh 60 round-key words từ 32-byte key.
    AES-256: Nk=8, Nr=14 -> cần (Nr+1)*Nb = 15*4 = 60 words.

    Quy tắc:
      W[i] = W[i-Nk] XOR temp
      với temp = SubWord(RotWord(W[i-1]))  XOR Rcon  nếu i % Nk == 0
               = SubWord(W[i-1])                    nếu i % Nk == 4
               = W[i-1]                             còn lại
    """
    assert len(key) == 32, "AES-256 yêu cầu key 32 bytes"
    Nk = 8   # số words trong key
    Nr = 14  # số rounds
    total = (Nr + 1) * 4  # = 60 words

    # Khởi tạo W[0..7] từ key
    W = [int.from_bytes(key[i*4:(i+1)*4], 'big') for i in range(Nk)]

    for i in range(Nk, total):
        temp = W[i - 1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ (_RCON[i // Nk - 1] << 24)
        elif i % Nk == 4:
            temp = _sub_word(temp)
        W.append(W[i - Nk] ^ temp)

    return W


def _get_round_key(W: list[int], round_num: int) -> list[list[int]]:
    """Lấy round key thứ round_num, trả về ma trận 4x4."""
    words = W[round_num * 4 : round_num * 4 + 4]
    # Ma trận state: state[col][row]
    return [[(w >> (24 - 8*r)) & 0xff for r in range(4)] for w in words]


# ============================================================
# PHẦN 3: AES BLOCK CIPHER — 4 PHÉP BIẾN ĐỔI
# ============================================================

def _bytes_to_state(block: bytes) -> list[list[int]]:
    """16 bytes -> ma trận state 4x4 (column-major theo chuẩn AES)."""
    state = [[0]*4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = block[i]
    return state


def _state_to_bytes(state: list[list[int]]) -> bytes:
    """Ma trận state 4x4 -> 16 bytes."""
    return bytes(state[i % 4][i // 4] for i in range(16))


def _add_round_key(state: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
    """
    AddRoundKey: XOR từng byte của state với round key.
    Đây là bước duy nhất liên quan trực tiếp đến key.
    """
    for col in range(4):
        for row in range(4):
            state[row][col] ^= round_key[col][row]
    return state


def _sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """
    SubBytes: thay thế phi tuyến từng byte qua S-Box.
    S-Box được xây từ: inverse trong GF(2^8) + affine transform.
    Đây là nguồn gốc tính phi tuyến (confusion) của AES.
    """
    for row in range(4):
        for col in range(4):
            state[row][col] = _SBOX[state[row][col]]
    return state


def _shift_rows(state: list[list[int]]) -> list[list[int]]:
    """
    ShiftRows: xoay trái từng hàng i một lượng i bytes.
      Row 0: không dịch
      Row 1: dịch trái 1
      Row 2: dịch trái 2
      Row 3: dịch trái 3
    Mục đích: diffusion theo chiều hàng.
    """
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]
    return state


def _mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    MixColumns: nhân mỗi cột với ma trận cố định trong GF(2^8):
    [2 3 1 1]
    [1 2 3 1]
    [1 1 2 3]
    [3 1 1 2]
    Mục đích: diffusion mạnh theo chiều cột.
    """
    for col in range(4):
        s = [state[row][col] for row in range(4)]
        state[0][col] = _gmul(s[0],2) ^ _gmul(s[1],3) ^ s[2]         ^ s[3]
        state[1][col] = s[0]          ^ _gmul(s[1],2) ^ _gmul(s[2],3) ^ s[3]
        state[2][col] = s[0]          ^ s[1]           ^ _gmul(s[2],2) ^ _gmul(s[3],3)
        state[3][col] = _gmul(s[0],3) ^ s[1]           ^ s[2]          ^ _gmul(s[3],2)
    return state


def aes256_encrypt_block(plaintext_block: bytes, round_keys: list[int]) -> bytes:
    """
    Mã hóa 1 block 16 bytes với AES-256 (14 rounds).

    Cấu trúc:
      InitialRound: AddRoundKey(W[0..3])
      Round 1-13:   SubBytes → ShiftRows → MixColumns → AddRoundKey
      FinalRound:   SubBytes → ShiftRows → AddRoundKey (không MixColumns)
    """
    assert len(plaintext_block) == 16
    state = _bytes_to_state(plaintext_block)

    # Initial round key addition
    rk = _get_round_key(round_keys, 0)
    state = _add_round_key(state, rk)

    # 13 vòng đầy đủ
    for rnd in range(1, 14):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        rk = _get_round_key(round_keys, rnd)
        state = _add_round_key(state, rk)

    # Vòng cuối (không có MixColumns)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    rk = _get_round_key(round_keys, 14)
    state = _add_round_key(state, rk)

    return _state_to_bytes(state)


# ============================================================
# PHẦN 4: CTR MODE — XCRYPT (encrypt = decrypt)
# ============================================================

def _build_counter_block(nonce: bytes, counter: int) -> bytes:
    """
    Tạo counter block 16 bytes theo chuẩn NIST SP 800-38A:
      [  nonce (12 bytes)  |  counter (4 bytes, big-endian)  ]

    Trong UAV datalink:
      nonce = timestamp_ms(4B) + sys_id(1B) + comp_id(1B) + msg_seq(2B) + padding(4B)
    """
    assert len(nonce) == 12, "Nonce phải 12 bytes (96-bit)"
    assert 0 <= counter < 2**32, "Counter 32-bit: tối đa 2^32 blocks = 64GB data"
    return nonce + struct.pack('>I', counter)


def aes256_ctr_xcrypt(data: bytes, key: bytes, nonce: bytes,
                       initial_counter: int = 0) -> bytes:
    """
    AES-256-CTR encrypt/decrypt (XCRYPT — cùng một hàm cho cả hai chiều).

    Tham số:
      data            : plaintext (encrypt) hoặc ciphertext (decrypt)
      key             : 32 bytes (256-bit)
      nonce           : 12 bytes (96-bit) — KHÔNG BAO GIỜ tái dùng với cùng key!
      initial_counter : giá trị counter bắt đầu (mặc định 0)

    Thuật toán:
      Với mỗi block i (16 bytes):
        counter_block = nonce ‖ (initial_counter + i)
        keystream     = AES_Encrypt(counter_block, key)
        output_block  = input_block XOR keystream
    """
    assert len(key) == 32, "Cần key 32 bytes cho AES-256"
    assert len(nonce) == 12, "Cần nonce 12 bytes"

    # Key expansion — thực hiện 1 lần cho toàn bộ message
    round_keys = _key_expansion(key)

    result = bytearray()
    offset = 0
    block_idx = 0

    while offset < len(data):
        # Bước 1: Xây counter block
        counter_block = _build_counter_block(nonce, initial_counter + block_idx)

        # Bước 2: Mã hóa counter block bằng AES-256 -> keystream
        keystream = aes256_encrypt_block(counter_block, round_keys)

        # Bước 3: XOR data với keystream (XCRYPT)
        chunk = data[offset : offset + 16]
        for i, byte in enumerate(chunk):
            result.append(byte ^ keystream[i])  # XOR từng byte

        offset += 16
        block_idx += 1

    return bytes(result)


# ============================================================
# PHẦN 5: DEMO — UAV DATALINK SIMULATION
# ============================================================

def demo_uav_datalink():
    print("=" * 60)
    print("  AES-256-CTR (XCRYPT) — Pure Python Implementation")
    print("  Ứng dụng: UAV MAVLink Datalink Encryption")
    print("=" * 60)

    # --- Sinh key & nonce ---
    # Trong thực tế: key trao đổi qua ECDH hoặc pre-shared
    key = os.urandom(32)  # 256-bit session key
    # Nonce: timestamp (4B) + sys_id (1B) + comp_id (1B) + seq (2B) + padding (4B)
    timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
    sys_id, comp_id, seq = 1, 1, 42
    nonce = struct.pack('>IBBH', timestamp_ms, sys_id, comp_id, seq) + b'\x00' * 4

    print(f"\n[KEY]   {key.hex()}")
    print(f"[NONCE] {nonce.hex()}  (timestamp={timestamp_ms}, sys={sys_id}, seq={seq})")

    # --- Simulate MAVLink payload ---
    # HEARTBEAT message (6 bytes payload) + header giả lập
    mavlink_payload = bytes([
        0xFE,          # Magic
        0x09,          # Payload length = 9
        seq & 0xFF,    # Sequence
        sys_id,        # System ID
        comp_id,       # Component ID
        0x00,          # Message ID: HEARTBEAT
        # Payload data
        0x00, 0x00, 0x00, 0x01,  # custom_mode
        0x06,                    # type = MAV_TYPE_GCS
        0x08,                    # autopilot = MAV_AUTOPILOT_ARDUPILOTMEGA
        0xC1,                    # base_mode
        0x00,                    # system_status
        0x03,                    # mavlink_version
    ])

    print(f"\n[PLAINTEXT]  ({len(mavlink_payload)} bytes)")
    print(f"  Hex: {mavlink_payload.hex()}")
    print(f"  Str: {mavlink_payload}")

    # --- ENCRYPT ---
    t0 = time.perf_counter()
    ciphertext = aes256_ctr_xcrypt(mavlink_payload, key, nonce, initial_counter=0)
    t_enc = (time.perf_counter() - t0) * 1e6

    print(f"\n[CIPHERTEXT] ({len(ciphertext)} bytes) — encrypted in {t_enc:.1f} µs")
    print(f"  Hex: {ciphertext.hex()}")

    # --- DECRYPT (cùng hàm, cùng params) ---
    t0 = time.perf_counter()
    decrypted = aes256_ctr_xcrypt(ciphertext, key, nonce, initial_counter=0)
    t_dec = (time.perf_counter() - t0) * 1e6

    print(f"\n[DECRYPTED]  ({len(decrypted)} bytes) — decrypted in {t_dec:.1f} µs")
    print(f"  Hex: {decrypted.hex()}")

    # --- Verify ---
    ok = decrypted == mavlink_payload
    print(f"\n[VERIFY] Plaintext == Decrypted: {'✅ PASS' if ok else '❌ FAIL'}")

    # --- Test: wrong nonce -> data corrupt (như mong đợi) ---
    wrong_nonce = bytes([n ^ 0xFF for n in nonce])
    decrypted_wrong = aes256_ctr_xcrypt(ciphertext, key, wrong_nonce)
    corrupt = decrypted_wrong != mavlink_payload
    print(f"[VERIFY] Wrong nonce -> corrupt:  {'✅ PASS (data garbled)' if corrupt else '❌ FAIL'}")

    return key, nonce, mavlink_payload, ciphertext


if __name__ == "__main__":
    key, nonce, plaintext, ciphertext = demo_uav_datalink()

    print("\n" + "=" * 60)
    print("  Xuất kết quả để đối chiếu với thư viện chuẩn:")
    print("=" * 60)
    print(f"KEY       = bytes.fromhex('{key.hex()}')")
    print(f"NONCE     = bytes.fromhex('{nonce.hex()}')")
    print(f"PLAINTEXT = bytes.fromhex('{plaintext.hex()}')")
    print(f"EXPECTED  = bytes.fromhex('{ciphertext.hex()}')")
