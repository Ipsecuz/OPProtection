# 🛡️ OPProtection - Bảo Vệ Toàn Diện Cho Server Minecraft Của Bạn 🔐  

![Version](https://img.shields.io/badge/version-2.5.3Folia-blue.svg)
![Java](https://img.shields.io/badge/java-17%2B-orange.svg)
![Platform](https://img.shields.io/badge/platform-PaperMC%20%7C%20Folia-lightgrey.svg)

---

**OPProtection** là một plugin bảo mật mạnh mẽ được thiết kế để **bảo vệ server Minecraft** của bạn khỏi việc lạm dụng quyền *Operator (OP)* và các mối đe dọa bảo mật khác.  
Với các tính năng như **xác minh đa tầng**, **chặn IP/GeoIP**, và **chế độ khẩn cấp**, đây là **lớp phòng thủ đầu tiên và quan trọng nhất** cho máy chủ của bạn.

---

## ✨ Tính Năng Nổi Bật

| 🔰 | Tính năng | Mô tả |
|----|-----------|-------|
| 🔐 | **Xác Minh OP Đa Tầng** | Yêu cầu xác minh bằng mật khẩu OPProtection và/hoặc Discord 2FA |
| 🔒 | **Mật Khẩu OP Dạng Hash** | Không lưu mật khẩu thô trong config, sử dụng hash bảo mật PBKDF2 |
| 🕶️ | **Ẩn `/oppass <pass>` Khỏi Console Log** | Ngăn việc lộ mật khẩu khi người chơi nhập `/oppass <password>` |
| 🌐 | **Domain Whitelist** | Chỉ cho phép người chơi join bằng domain hợp lệ |
| 🛡️ | **Strict Proxy IP** | Chặn fake proxy bằng cách chỉ cho backend nhận kết nối từ IP proxy chính thức |
| 👑 | **Premium Auth Cho OP Whitelist** | Kiểm tra acc premium/cracked cho những người nằm trong `op-whitelist` |
| 🧾 | **Exact Name Case Check** | Bắt buộc đúng chữ hoa/thường theo tên Minecraft premium chính thức |
| 🌍 | **Chặn GeoIP / Anti-VPN** | Tự động chặn người chơi từ quốc gia không được phép |
| 🚨 | **Chế Độ Khẩn Cấp** | Khóa toàn bộ server ngay khi có sự cố bảo mật |
| 📢 | **Tích Hợp Discord** | Gửi thông báo và xác minh 2FA qua Discord |
| 🛑 | **Chống Lệnh Nguy Hiểm** | Chặn các lệnh nhạy cảm như `/op`, `/plugins`, `/stop`, `/reload` |
| 🚫 | **Chặn Tab-Complete** | Ngăn hiển thị lệnh bị cấm khi người chơi gõ tab |
| 🕵️ | **Chống IP/UUID Spoofing** | Phát hiện và ngăn nỗ lực giả mạo danh tính |
| 🔄 | **Tự Động Hành Động Khi Logout** | Tự động gỡ OP hoặc permission khi admin logout |
| 🔗 | **DiscordSync** | Bắt buộc liên kết Discord + Minecraft trước khi sử dụng hot reload command |
| ✅ | **Tương Thích Folia** | Hỗ trợ PaperMC và Folia |

---

## 📥 Cài Đặt

1. Tải bản mới nhất tại [**Releases**](https://github.com/Ipsecuz/OPProtection/releases/).
2. Hoặc tải phiên bản cũ hoàn chỉnh nhưng không hỗ trợ Folia tại [**Old Version**](https://www.mediafire.com/file/rcbnb0ack1wsnxg/OPProtection-2.3.3.jar/file).
3. Đặt file `.jar` vào thư mục `plugins/`.
4. Khởi động lại server.
5. Cấu hình các file `config.yml`, `messages.yml`, `embed_discord.yml` theo nhu cầu.
6. Thêm tên admin của bạn vào danh sách `op-whitelist` trong `config.yml`.
7. Sau khi plugin load thành công, tạo mật khẩu OPProtection bằng lệnh console: oppass createpass <mật-khẩu-bạn-tự-nhập>

## Dependencies (Phụ thuộc)
1. Packetenvents(bắt buộc)
---

## ⚙️ Cấu Hình

### `config.yml`
```yaml
# Whitelist các người chơi được phép có OP
op-whitelist:
  - YourName
  - AnotherAdmin

# Mật khẩu để xác minh OP
op-password: "mat_khau_bao_mat"
# Thời gian (giây) để người chơi nhập mật khẩu
pass-timeout: 50

# Cấu hình Discord Bot
discord:
  enabled: false
  token: "YOUR_BOT_TOKEN"
  channel-id: "YOUR_CHANNEL_ID"
  use-2fa: false

# Cấu hình chống VPN (GeoIP)
geoip:
  enabled: true
  allowed-countries:
    - "VN"
  block-message: "&cQuốc gia của bạn không được phép truy cập server!"

# Chế độ khẩn cấp
emergency-mode:
  enabled: false
  blocked-commands:
    - "op"
    - "stop"
    - "reload"
  kick-message: "&cServer đang trong chế độ khẩn cấp!"

# Các lệnh bị chặn với tất cả người chơi
disable-commands:
  - op
  - pl
  - plugins
  - ver
  - luckperms

# Các lệnh được phép khi chưa xác minh OP
allowed-commands:
  - login
  - register
  - oppass

# Hành động tự động khi người chơi trong whitelist logout
logout-actions:
  - "deop %player%"
  - "lp user %player% permission unset *"
```

🤖 Hướng Dẫn Cấu Hình Discord 2FA

Truy cập Discord Developer Portal

Tạo ứng dụng mới và thêm Bot.

Bật quyền MESSAGE CONTENT INTENT.

Mời bot vào server của bạn bằng OAuth2 → URL Generator.

Lấy Channel ID (chuột phải → Copy Channel ID).

Điền token và channel-id vào file config.yml.

Đặt enabled: true và use-2fa: true.

📜 Lệnh & Quyền
Lệnh	Mô tả	Quyền

/oppass <mật khẩu>	Xác minh quyền OP của chính bạn	-> Player

/oppass confirm <tên>	Xác minh OP cho người chơi khác ->	Console

/oppass resetip <tên>	Reset IP của người chơi về unknown ->	Console

/opreload	Tải lại toàn bộ cấu hình plugin	-> Console

/verify - trước để nhận được mã xác minh hãy lên trên discord nhận mã từ bot

/opverify <mã> - nhập để xác minh liên kết tài khoản thành công MC với discord

🤝 Đóng Góp

Chúng tôi luôn hoan nghênh mọi đóng góp từ cộng đồng!
Nếu bạn muốn báo lỗi, đề xuất tính năng hoặc gửi pull request — hãy làm điều đó trên GitHub
.

📄 Báo lỗi:

Discord: habitat_

Báo cho tui nếu plugin có lỗi gì đó:)

👥 Tác Giả

👤 Ipsecuz_
🏢 Fox Studio

Cảm ơn bạn đã sử dụng OPProtection — lá chắn đầu tiên cho server của bạn 🔰
