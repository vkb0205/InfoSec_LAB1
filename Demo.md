# Quy Trình Demo Mini Vault CLI

Dựa vào mã nguồn `main.py` và yêu cầu, dưới đây là quy trình chi tiết từng bước để bạn thực hiện quay video demo (3-5 phút) qua giao diện dòng lệnh (CLI).

## Chuẩn bị (Trước khi quay video)
Để tiết kiệm thời gian quay, hãy đảm bảo Vault đã được khởi tạo và tạo sẵn 2 tài khoản người dùng:
1. **Khởi tạo Vault:** `python main.py init` *(Lưu lại Master Passphrase)*
2. **Đăng ký User 1:** `python main.py register` *(vd: `user1@test.com`)*
3. **Đăng ký User 2:** `python main.py register` *(vd: `user2@test.com`)*

---

## Các bước thực hiện quay video Demo

*Lưu ý: Thay thế `$TOKEN_1`, `$TOKEN_2`, `$CIPHERTEXT`, và `$SIGNATURE` bằng các giá trị thực tế sinh ra trên màn hình.*

### 1. Mở khóa Vault (Unlock)
Chạy lệnh unlock và nhập Master Passphrase:
```bash
python main.py unlock
```
*(Kết quả mong đợi: In ra `unlocked`)*

**Lấy Token cho 2 User (để dùng cho các bước sau):**
```bash
python main.py login
# Nhập email: user1@test.com và mật khẩu -> Copy Token nhận được (Gọi là TOKEN_1)

python main.py login
# Nhập email: user2@test.com và mật khẩu -> Copy Token nhận được (Gọi là TOKEN_2)
```

### 2. Ghi và Đọc một Secret (write/read a secret)
Dùng `TOKEN_1` để ghi một secret vào đường dẫn của User 1:
```bash
python main.py kv write --token <TOKEN_1> --path secret/user1/data --secret "Day la bi mat cua User 1"
```

Đọc lại secret vừa ghi:
```bash
python main.py kv read --token <TOKEN_1> --path secret/user1/data
```
*(Kết quả mong đợi: In ra "Day la bi mat cua User 1")*

### 3. Thử truy cập Secret của người khác (bị từ chối)
Dùng `TOKEN_2` (của User 2) để cố gắng đọc secret của User 1:
```bash
python main.py kv read --token <TOKEN_2> --path secret/user1/data
```
*(Kết quả mong đợi: Bị từ chối truy cập, in ra lỗi quyền hạn `PermissionError` hoặc `PERMISSION_DENIED`)*

### 4. Tạo Named Key, Mã hóa và Giải mã
Tạo một Transit key cho User 1:
```bash
python main.py transit create-key --token <TOKEN_1> --key-name key-cua-user1
```

Mã hóa một đoạn văn bản (Plaintext):
```bash
python main.py transit encrypt --token <TOKEN_1> --key-name key-cua-user1 --plaintext "Hello Vault"
```
*(Kết quả mong đợi: Trả về một chuỗi mã hóa CIPHERTEXT, hãy copy chuỗi này)*

Giải mã chuỗi Ciphertext vừa nhận được:
```bash
python main.py transit decrypt --token <TOKEN_1> --ciphertext <CIPHERTEXT>
```
*(Kết quả mong đợi: Trả về "Hello Vault" hoặc phiên bản base64 của nó)*

### 5. Thử dùng Key của người khác (bị từ chối)
Dùng `TOKEN_2` (của User 2) để cố gắng dùng key của User 1 mã hóa dữ liệu:
```bash
python main.py transit encrypt --token <TOKEN_2> --key-name key-cua-user1 --plaintext "Hacker"
```
*(Kết quả mong đợi: Bị từ chối truy cập)*

### 6. Ký một thông điệp (sign a message)
Tạo một Signing Key cho User 1:
```bash
python main.py transit create-signing-key --token <TOKEN_1> --key-name sign-key-1
```

Ký một thông điệp:
```bash
python main.py transit sign --token <TOKEN_1> --key-name sign-key-1 --message "Van ban quan trong"
```
*(Kết quả mong đợi: Trả về một chuỗi chữ ký SIGNATURE, hãy copy chuỗi này)*

### 7. Xác minh thông điệp hợp lệ (verify it - valid)
Sử dụng chính chữ ký và thông điệp ban đầu để xác minh:
```bash
python main.py transit verify --token <TOKEN_1> --key-name sign-key-1 --message "Van ban quan trong" --signature <SIGNATURE>
```
*(Kết quả mong đợi: In ra `True` hoặc phản hồi xác nhận hợp lệ)*

### 8. Xác minh thông điệp bị thay đổi (verify a tampered message - invalid)
Cố tình thay đổi nội dung của thông điệp so với lúc ký để xem hệ thống có phát hiện ra không:
```bash
python main.py transit verify --token <TOKEN_1> --key-name sign-key-1 --message "Van ban quan trong DA BI SUA" --signature <SIGNATURE>
```
*(Kết quả mong đợi: In ra `False` hoặc thông báo lỗi không hợp lệ)*

---
*Mẹo: Bạn cũng có thể thực hiện toàn bộ quá trình này bằng chế độ Tương tác (Interactive Mode) bằng cách chạy lệnh `python main.py interactive` và chọn các số từ Menu, quy trình và logic vẫn tương tự như các bước ở trên.*
