from flask import Flask, render_template, request, jsonify
from urllib.parse import urlsplit
from pathlib import Path
from datetime import datetime
import sqlite3
import ipaddress
import json
import re

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # Giới hạn dữ liệu gửi lên: 16 KB

DB_DIR = Path(app.instance_path)
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "lich_su_kiem_tra.db"

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy"
}
SUSPICIOUS_WORDS = {
    "login", "verify", "account", "password", "secure",
    "update", "banking", "wallet", "signin", "confirm"
}


def get_db():
    """Mở kết nối SQLite và trả về hàng dữ liệu dạng từ điển."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                scheme TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                reasons TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.commit()


def analyze_url(raw_url):
    """Phân tích dấu hiệu rủi ro từ URL; không truy cập URL đó."""
    if not isinstance(raw_url, str):
        return {"error": "Dữ liệu đường dẫn không hợp lệ."}

    raw_url = raw_url.strip()

    if not raw_url:
        return {"error": "Bạn chưa nhập đường dẫn website."}
    if len(raw_url) > 2048:
        return {"error": "Đường dẫn quá dài (tối đa 2.048 ký tự)."}
    if any(ord(char) < 32 or char.isspace() for char in raw_url):
        return {"error": "Đường dẫn chứa khoảng trắng hoặc ký tự điều khiển."}

    # Chỉ chấp nhận URL đầy đủ có http:// hoặc https://.
    try:
        parsed = urlsplit(raw_url)
        if parsed.scheme.lower() not in ("http", "https"):
            return {"error": "Đường dẫn phải bắt đầu bằng http:// hoặc https://."}
        if not parsed.hostname:
            return {"error": "Không tìm thấy tên miền trong đường dẫn."}

        # Truy cập thuộc tính port để phát hiện cổng không hợp lệ.
        _ = parsed.port
        host = parsed.hostname.rstrip(".").lower()
        if not host:
            return {"error": "Tên miền không hợp lệ."}

        # Chuẩn hóa tên miền quốc tế về dạng IDNA để phân tích.
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return {"error": "Không thể đọc tên miền này."}

    except ValueError:
        return {"error": "Cấu trúc đường dẫn hoặc số cổng không hợp lệ."}

    score = 0
    reasons = []
    scheme = parsed.scheme.lower()

    def add(points, message):
        nonlocal score
        score += points
        reasons.append(message)

    if scheme == "http":
        add(15, "Website không sử dụng HTTPS.")

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        add(25, "Đường dẫn có thông tin trước ký tự @; hãy kiểm tra kỹ tên miền thật.")

    try:
        ipaddress.ip_address(ascii_host)
        add(25, "Đường dẫn sử dụng địa chỉ IP thay cho tên miền thông thường.")
    except ValueError:
        pass

    if "xn--" in ascii_host:
        add(20, "Tên miền dùng mã Punycode; có thể cần kiểm tra ký tự giả mạo.")

    if len(ascii_host) > 45:
        add(10, "Tên miền khá dài.")
    if ascii_host.count(".") >= 4:
        add(10, "Tên miền có nhiều cấp phụ.")
    if ascii_host.count("-") >= 3:
        add(10, "Tên miền chứa nhiều dấu gạch ngang.")

    if ascii_host in SHORTENERS:
        add(15, "Đây là dịch vụ rút gọn liên kết; đích đến thật chưa được xác định.")

    lowered = (ascii_host + parsed.path + parsed.query).lower()
    matched_words = sorted(word for word in SUSPICIOUS_WORDS if word in lowered)
    if matched_words:
        add(10, "Có từ khóa thường xuất hiện trong trang đăng nhập hoặc xác minh: "
            + ", ".join(matched_words[:5]) + ".")

    if len(parsed.query) > 300:
        add(5, "Phần tham số của đường dẫn dài bất thường.")

    score = min(score, 100)

    if score >= 50:
        level = "Cao"
        advice = "Không nhập mật khẩu, mã OTP hoặc thông tin cá nhân nếu bạn chưa xác minh được nguồn gửi."
    elif score >= 20:
        level = "Trung bình"
        advice = "Hãy kiểm tra kỹ tên miền và nguồn gửi đường dẫn trước khi tiếp tục."
    else:
        level = "Thấp"
        advice = "Chưa phát hiện nhiều dấu hiệu đáng ngờ theo các quy tắc cơ bản. Điều này không chứng minh website an toàn."

    if not reasons:
        reasons.append("Chưa phát hiện dấu hiệu rủi ro nổi bật theo các quy tắc hiện có.")

    return {
        "url": raw_url,
        "domain": ascii_host,
        "scheme": scheme.upper(),
        "https": scheme == "https",
        "score": score,
        "level": level,
        "reasons": reasons,
        "advice": advice,
        "checked_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    }


def save_scan(result):
    with get_db() as db:
        cursor = db.execute("""
            INSERT INTO scans (url, domain, scheme, score, level, reasons, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result["url"],
            result["domain"],
            result["scheme"],
            result["score"],
            result["level"],
            json.dumps(result["reasons"], ensure_ascii=False),
            datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        ))
        db.commit()
        return cursor.lastrowid


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )
    return response


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    result = analyze_url(data.get("url", ""))

    if "error" in result:
        return jsonify(result), 400

    result["id"] = save_scan(result)
    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def history():
    with get_db() as db:
        rows = db.execute("""
            SELECT id, url, domain, scheme, score, level, created_at
            FROM scans ORDER BY id DESC LIMIT 100
        """).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def history_detail(scan_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()

    if row is None:
        return jsonify({"error": "Không tìm thấy lần kiểm tra này."}), 404

    item = dict(row)
    item["reasons"] = json.loads(item["reasons"])
    return jsonify(item)


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    with get_db() as db:
        db.execute("DELETE FROM scans")
        db.commit()
    return jsonify({"message": "Đã xóa toàn bộ lịch sử kiểm tra."})


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Dữ liệu gửi lên quá lớn."}), 413


@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Không tìm thấy chức năng được yêu cầu."}), 404
    return "Không tìm thấy trang.", 404


if __name__ == "__main__":
    init_db()
    print("URL Safety Checker đang chạy tại: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
