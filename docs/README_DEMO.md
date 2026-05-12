# Kịch bản Demo: IAM Key Management System (End-to-End)

Tài liệu này hướng dẫn chạy kịch bản thử nghiệm toàn diện (End-to-End) để minh họa các tính năng của hệ thống bao gồm: Quản lý Danh tính, Quản lý Khóa, Phân quyền (RBAC), PKI/Chứng chỉ số, và Chat Mã hóa E2E.

## 🚀 Bước 1: Khởi tạo và Dọn dẹp môi trường

Đầu tiên, chạy script khởi tạo để dọn dẹp dữ liệu cũ (nếu có) và tạo dữ liệu mẫu:

```bash
python init_demo_env.py
```
> **Kết quả:** Hệ thống sẽ tạo ra `demo_identity`, `demo_keys`, `demo_audit`, `data` (chứa chứng chỉ Root CA).  
> Nó sẽ tạo 2 tài khoản mẫu: `admin` (Role: ADMIN) và `alice` (Role: USER).

## 🚀 Bước 2: Khởi động Server (API Backend & Relay)

Mở **Terminal số 1**, khởi động IAM Server:

```bash
python server.py
```
> Server sẽ lắng nghe các kết nối TCP từ Client, xử lý Authentication, phân phối Certificate, quản trị Khóa và đóng vai trò Relay cho các tin nhắn E2E.

## 🚀 Bước 3: Đăng nhập Người dùng thông thường (Alice)

Mở **Terminal số 2**, chạy Client App:

```bash
python client.py
```

Khi Menu hiện lên, thực hiện:
1. Chọn `1` để Đăng nhập.
2. Nhập Username: `alice`
3. Nhập Password: `Alice@123`

### 3.1. Thử nghiệm Quản lý Khóa
Tại **Menu chính**, thao tác:
- Chọn `1` (Quản lý khóa) → Chọn `1` (Sinh khóa mới).
  - Chọn thuật toán: `1` (AES-256).
  - Tên khóa: `alice_secret_doc_key`
  - Mục đích: `Encrypt Document`
- Quay lại menu Quản lý khóa, chọn `2` (Liệt kê khóa). Bạn sẽ thấy khóa mặc định và khóa vừa tạo.

### 3.2. Thử nghiệm Phân quyền (RBAC) - Cố tình truy cập trái phép
Tại **Menu chính**, thao tác:
- Chọn `3` (Xem audit log)
- Hệ thống sẽ chặn lại với lỗi **Ngăn chặn truy cập** bởi Alice (vai trò `USER`) không có quyền `audit:read`.

## 🚀 Bước 4: Đăng nhập Quản trị viên (Admin)

Mở **Terminal số 3**, chạy một Client App mới:

```bash
python client.py
```

Khi Menu hiện lên, thực hiện:
1. Chọn `1` để Đăng nhập.
2. Nhập Username: `admin`
3. Nhập Password: `Admin@123`

### 4.1. Thử nghiệm Truy vấn Hệ thống (Audit Log & Users)
Tại **Menu chính**, thao tác:
- Chọn `4` (Xem danh sách users). Admin có thể nhìn thấy danh sách Alice và Admin.
- Chọn `3` (Xem audit log). Bạn sẽ thấy toàn bộ lịch sử hệ thống, **bao gồm cả sự kiện Alice vừa bị từ chối truy cập (PERMISSION_DENIED)** ở bước 3.2!

## 🚀 Bước 5: Chat Mã hóa End-to-End (Alice <--> Admin)

1. Tại **Terminal 2 (Alice)**, chọn Menu số `5` (Chế độ chat E2E).
2. Tại **Terminal 3 (Admin)**, chọn Menu số `5` (Chế độ chat E2E).
3. **Trao đổi tin nhắn:**
   - Tại Terminal Alice gõ: `Chào sếp, dự án tuyệt mật tới đâu rồi?`
   - Tại Terminal Admin gõ: `Mọi thứ đang được mã hóa an toàn.`
4. **Quan sát Màn hình Server (Terminal 1):**
   - Server chỉ nhìn thấy [ENCRYPTED PAYLOAD], không thể đọc được nội dung thực sự nhờ trao đổi khóa RSA và mã hóa AES-GCM.

Gõ `back` trên terminal của Client để thoát chế độ Chat và trở lại Menu chính.

## 🚀 Bước 6: Phân phối Động (Đăng ký tài khoản mới)

Tại **Trang chủ Client** (không cần đăng nhập, hoặc mở Terminal 4 chạy `python client.py`):
1. Chọn `2` (Đăng ký).
2. Nhập thông tin: `bob` / `bob@company.com` / `Bob@123`.
3. Đăng ký thành công, tự động cấp quyền `USER`. Bob có thể login vào chat ngay lập tức!
