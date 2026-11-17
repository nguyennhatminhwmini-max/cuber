# URL Safety Checker – Tiếng Việt

Dự án học tập về phân tích dấu hiệu rủi ro trong đường dẫn website.

## Chức năng
- Phân tích cấu trúc URL, giao thức và tên miền.
- Kiểm tra một số dấu hiệu thường gặp như HTTP, địa chỉ IP, ký tự Punycode, tên miền dài, nhiều cấp phụ, liên kết rút gọn và từ khóa đáng ngờ.
- Chấm điểm rủi ro theo quy tắc minh họa.
- Lưu và xem lịch sử bằng SQLite.
- Giao diện tiếng Việt, tương thích máy tính và điện thoại.

## Cài đặt trên Windows

Mở Terminal tại thư mục dự án:

```powershell
py -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Nếu không muốn kích hoạt môi trường ảo, có thể gọi Python trong venv trực tiếp:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe app.py
```

## Chạy
```powershell
python app.py
```

Mở trình duyệt tại http://127.0.0.1:5000

## Lưu ý an toàn
- Công cụ chỉ phân tích chuỗi URL, không truy cập hoặc tải nội dung website.
- Điểm số là heuristic phục vụ học tập, không phải kết luận website độc hại hay an toàn.
- Không nhập mật khẩu, mã OTP hoặc thông tin cá nhân vào các website chưa xác minh.
- Máy chủ mặc định chỉ lắng nghe trên 127.0.0.1 và tắt chế độ debug.
- Không triển khai trực tiếp lên Internet khi chưa bổ sung các biện pháp bảo vệ phù hợp.
