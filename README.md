# Tóm tắt nội dung

## BUILD SRC
```bash
gcc --version
gcc main.c -std=c11 -O2 -o main.exe; .\main.exe
```

## Y nghia cua AES_CTR_XCRYPT


## Ý nghĩa của các biến `key[32]` và `nonce[16]`:
1. **`key[32]`**:
   - Là khóa bí mật dùng cho thuật toán mã hóa AES-256.
   - Kích thước: 32 bytes (256 bits).
   - Vai trò:
     - Dùng để tạo các round keys thông qua hàm `key_expansion()`.
     - Round keys được sử dụng trong từng vòng mã hóa/giải mã của AES.
   - Lưu ý: Phải được giữ bí mật tuyệt đối để đảm bảo an toàn dữ liệu.

2. **`nonce[16]`**:
   - Là giá trị khởi tạo (Initialization Vector - IV) hoặc nonce (number used once) trong chế độ CTR.
   - Kích thước: 16 bytes (128 bits).
   - Vai trò:
     - Tạo các counter blocks trong chế độ CTR.
     - Đảm bảo tính ngẫu nhiên và duy nhất cho mỗi lần mã hóa.
   - Lưu ý: Không cần bí mật nhưng phải duy nhất để tránh lặp lại đầu ra mã hóa.

---

## Độ dài của `len` trong chế độ CTR:
- **Chế độ CTR cho phép `len` có độ dài bất kỳ** (không cần bội số của 16 bytes).
- **Giải thích**:
  - Dữ liệu được chia thành các khối 16 bytes.
  - Nếu khối cuối cùng không đủ 16 bytes, chỉ các byte cần thiết sẽ được xử lý.
  - Hàm `aes256_ctr_xcrypt` sử dụng bộ đếm (`counter`) để tạo keystream 16 bytes và XOR với dữ liệu.
  - Bộ đếm tăng sau mỗi khối, đảm bảo mã hóa chính xác cho toàn bộ dữ liệu.
- **Kết luận**:
  - Chế độ CTR không yêu cầu padding, nên dữ liệu có thể dài bao nhiêu cũng được xử lý chính xác.