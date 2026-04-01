#include "AES256.h"

// --- DEMO TRONG MAIN ---
int main() {
	aes256_ctx ctx;
	// 256-bit Key (32 bytes)
	const uint8_t key[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};

	// Nonce/IV cho CTR mode (16 bytes)
	const uint8_t nonce[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

	// Gói tin UAV giả định (Telemetry)
	const uint8_t sys_id = 1;
	const uint8_t comp_id = 1;
	const uint8_t seq = 42;
	uint8_t telemetry_data[] = {
        0xFE,          // Magic
        0x09,          // Payload length = 9
        seq & 0xFF,    // Sequence
        sys_id,        // System ID
        comp_id,       // Component ID
        0x00,          // Message ID: HEARTBEAT
        // Payload data
        0x00, 0x00, 0x00, 0x01,  // custom_mode
        0x06,                    // type = MAV_TYPE_GCS
        0x08,                    // autopilot = MAV_AUTOPILOT_ARDUPILOTMEGA
        0xC1,                    // base_mode
        0x00,                    // system_status
        0x03,                    // mavlink_version
    };
	size_t len = strlen(telemetry_data);

	printf("--- UAV DATALINK ENCRYPTION (AES-256 CTR) ---\n");

	// 0. Hien thi thông tin gói tin trước khi mã hóa
	printf("key (Hex): \n\r");
	for(size_t i=0; i<32; i++) printf("%02X ", key[i]);
	printf("\n");	
	printf("nonce (Hex): \n\r");
	for(size_t i=0; i<16; i++) printf("%02X ", nonce[i]);
	printf("\n");

	printf("Data (Hex): \n\r");
	for(size_t i=0; i<len; i++) printf("%02X ", telemetry_data[i]);
	printf("\n");

	// 1. Khởi tạo Key
	key_expansion(key, ctx.round_keys);

	// 2. Encryption (Sử dụng CTR mode)
	uint8_t buffer[128];
	memcpy(buffer, telemetry_data, len);

	uint8_t nonce_enc[16], nonce_dec[16];
	memcpy(nonce_enc, nonce, 16);
	memcpy(nonce_dec, nonce, 16);

	aes256_ctr_xcrypt(&ctx, nonce_enc, buffer, len);

	printf("Encrypted (Hex): \n\r");
	for(size_t i=0; i<len; i++) printf("%02X ", buffer[i]);
	printf("\n");

	// 3. Decryption (Dùng lại chính hàm đó với CTR)
	aes256_ctr_xcrypt(&ctx, nonce_dec, buffer, len);
	buffer[len] = '\0';

	printf("Decrypted (Hex): \n\r");
	for(size_t i=0; i<len; i++) printf("%02X ", buffer[i]);
	printf("\n");

	return 0;
}
