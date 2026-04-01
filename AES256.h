#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifndef FUNC_H
#define FUNC_H
/**
 * PURE C AES-256 IMPLEMENTATION FOR UAV DATALINK ENCRYPTION
 * --------------------------------------------------------
 * Ưu điểm: Không phụ thuộc thư viện ngoài (No OpenSSL), 
 *          Thích hợp cho vi điều khiển (STM32, ESP32, v.v.)
 * 
// --- ỨNG DỤNG TRONG UAV DATALINK (CTR MODE) ---
/** 
 * Ghi chú: Với UAV datalink, chế độ CTR (Counter) thường được dùng vì:
 * 1. Không cần Padding (dữ liệu dài bao nhiêu cũng mã hóa được bấy nhiêu byte).
 * 2. Có thể mã hóa/giải mã song song.
 * 3. Thuật toán Encrypt và Decrypt hoàn toàn GIỐNG NHAU.
 */

// S-box cho AES
static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Round Constant
static const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// Cấu trúc lưu trữ round keys (256-bit = 14 rounds = 15 keys * 16 bytes = 240 bytes)
typedef struct {
	uint8_t round_keys[240];
} aes256_ctx;

// --- HÀM BỔ TRỢ ---
static void key_expansion(const uint8_t *key, uint8_t *round_keys) {
	int i, j;
	uint8_t temp[4];

	memcpy(round_keys, key, 32);

	for (i = 8; i < 60; i++) {
		memcpy(temp, &round_keys[(i - 1) * 4], 4);
		if (i % 8 == 0) {
			// RotWord
			uint8_t t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
			// SubWord
			temp[0] = sbox[temp[0]]; temp[1] = sbox[temp[1]]; temp[2] = sbox[temp[2]]; temp[3] = sbox[temp[3]];
			temp[0] ^= rcon[i / 8 - 1];
		}
		else if (i % 8 == 4) {
			temp[0] = sbox[temp[0]]; temp[1] = sbox[temp[1]]; temp[2] = sbox[temp[2]]; temp[3] = sbox[temp[3]];
		}
		for (j = 0; j < 4; j++) round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j];
	}
}

static uint8_t gmul(uint8_t a, uint8_t b) {
	uint8_t p = 0;
	for (int i = 0; i < 8; i++) {
		if (b & 1) p ^= a;
		uint8_t hi_bit = a & 0x80;
		a <<= 1;
		if (hi_bit) a ^= 0x1b;
		b >>= 1;
	}
	return p;
}

// --- CORE AES ENCRYPT BLOCK (16 bytes) ---
void aes256_encrypt_block(const aes256_ctx *ctx, const uint8_t *in, uint8_t *out) {
	uint8_t state[16];
	int r, i;

	memcpy(state, in, 16);

	// AddRoundKey 0
	for (i = 0; i < 16; i++) state[i] ^= ctx->round_keys[i];

	for (r = 1; r < 14; r++) {
		// SubBytes
		for (i = 0; i < 16; i++) state[i] = sbox[state[i]];

		// ShiftRows
		uint8_t t;
		t = state[1];
		state[1] = state[5];
		state[5] = state[9];
		state[9] = state[13];
		state[13] = t;

		// Row 2: shift left 2
		uint8_t t1 = state[2];
		uint8_t t2 = state[6];
		state[2]  = state[10];
		state[6]  = state[14];
		state[10] = t1;
		state[14] = t2;

		// Row 3: shift left 3
		t = state[3];
		state[3] = state[15];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = t;

		// MixColumns
		for (i = 0; i < 4; i++) {
			uint8_t *c = &state[i * 4];
			uint8_t a = c[0], b = c[1], d = c[2], e = c[3];
			c[0] = gmul(a, 2) ^ gmul(b, 3) ^ d ^ e;
			c[1] = a ^ gmul(b, 2) ^ gmul(d, 3) ^ e;
			c[2] = a ^ b ^ gmul(d, 2) ^ gmul(e, 3);
			c[3] = gmul(a, 3) ^ b ^ d ^ gmul(e, 2);
		}

		// AddRoundKey
		for (i = 0; i < 16; i++) state[i] ^= ctx->round_keys[r * 16 + i];
	}

	// Final Round (No MixColumns)
	for (i = 0; i < 16; i++) state[i] = sbox[state[i]];
	// ShiftRows final
	uint8_t t;
	t = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = t;

	// Row 2: shift left 2
	uint8_t t1 = state[2];
	uint8_t t2 = state[6];
	state[2]  = state[10];
	state[6]  = state[14];
	state[10] = t1;
	state[14] = t2;

	// Row 3: shift left 3
	t = state[3];
	state[3] = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = t;
	
	// AddRoundKey final
	for (i = 0; i < 16; i++) state[i] ^= ctx->round_keys[14 * 16 + i];
	memcpy(out, state, 16);
}

void aes256_ctr_xcrypt(const aes256_ctx *ctx, uint8_t *nonce, uint8_t *data, size_t len) {
	uint8_t stream[16];
	uint8_t counter[16];
	memcpy(counter, nonce, 16);

	for (size_t i = 0; i < len; i++) {
		if (i % 16 == 0) {
			aes256_encrypt_block(ctx, counter, stream);
			// Tăng counter
			for (int j = 15; j >= 0; j--) {
				if (++counter[j]) break;
			}
		}
		data[i] ^= stream[i % 16];
	}
}

//
// // --- DEMO TRONG MAIN ---
// int main() {
// 	aes256_ctx ctx;
// 	// 256-bit Key (32 bytes)
// 	uint8_t key[32] = {
// 		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
// 		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
// 		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
// 		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
// 	};
//
// 	// Nonce/IV cho CTR mode (16 bytes)
// 	uint8_t nonce[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
//
// 	// Gói tin UAV giả định (Telemetry)
// 	char telemetry_data[] = "UAV_ID:001; LAT:10.76; LON:106.66; ALT:250m; SPD:15m/s; BATT:85%";
// 	size_t len = strlen(telemetry_data);
//
// 	printf("--- UAV DATALINK ENCRYPTION (AES-256 CTR) ---\n");
// 	printf("Plaintext: \n\r");
// 	printf("%s", telemetry_data);
// 	printf("\n");
//
// 	// 0. Hien thi thông tin gói tin trước khi mã hóa
// 	printf("Data (Hex): \n\r");
// 	for(size_t i=0; i<len; i++) printf("%02X ", telemetry_data[i]);
// 	printf("\n");
//
// 	// 1. Khởi tạo Key
// 	key_expansion(key, ctx.round_keys);
//
// 	// 2. Encryption (Sử dụng CTR mode)
// 	uint8_t buffer[128];
// 	memcpy(buffer, telemetry_data, len);
//
// 	uint8_t nonce_enc[16], nonce_dec[16];
// 	memcpy(nonce_enc, nonce, 16);
// 	memcpy(nonce_dec, nonce, 16);
//
// 	aes256_ctr_xcrypt(&ctx, nonce_enc, buffer, len);
//
// 	printf("Encrypted (Hex): \n\r");
// 	for(size_t i=0; i<len; i++) printf("%02X ", buffer[i]);
// 	printf("\n");
//
// 	// 3. Decryption (Dùng lại chính hàm đó với CTR)
// 	aes256_ctr_xcrypt(&ctx, nonce_dec, buffer, len);
// 	buffer[len] = '\0';
//
// 	printf("Decrypted: \n\r");
// 	printf("%s", buffer);
// 	printf("\n");
//
// 	return 0;
// }

#endif