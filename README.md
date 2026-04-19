# 🛡️ OPProtection - Bảo Vệ Toàn Diện Cho Server Minecraft Của Bạn 🔐  

![Version](https://img.shields.io/badge/version-2.5-blue.svg)
![Java](https://img.shields.io/badge/java-17%2B-orange.svg)
![Platform](https://img.shields.io/badge/platform-PaperMC%20%7C%20Folia-lightgrey.svg)

---

**OPProtection** là một plugin bảo mật mạnh mẽ được thiết kế để **bảo vệ server Minecraft** của bạn khỏi việc lạm dụng quyền *Operator (OP)* và các mối đe dọa bảo mật khác.  
Với các tính năng như **xác minh đa tầng**, **chặn IP/GeoIP**, và **chế độ khẩn cấp**, đây là **lớp phòng thủ đầu tiên và quan trọng nhất** cho máy chủ của bạn.

---

## ✨ Tính Năng Nổi Bật

| 🔰 | Tính năng | Mô tả |
|----|------------|--------|
| 🔐 | **Xác Minh OP Đa Tầng** | Yêu cầu xác minh qua mật khẩu hoặc 2FA qua Discord |
| 🌍 | **Chặn GeoIP (Anti-VPN)** | Tự động chặn người chơi từ quốc gia không được phép |
| 🚨 | **Chế Độ Khẩn Cấp (Emergency Mode)** | Khóa toàn bộ server ngay khi có sự cố |
| 📢 | **Tích Hợp Discord** | Gửi thông báo và xác minh 2FA qua Discord |
| 🛡️ | **Chống Lệnh Nguy Hiểm** | Chặn các lệnh nhạy cảm như `/op`, `/plugins`, `/stop` |
| 🚫 | **Chặn Tab-Complete** | Ngăn hiển thị lệnh bị cấm khi người chơi gõ tab |
| 🕵️ | **Chống IP/UUID Spoofing** | Phát hiện và ngăn nỗ lực giả mạo danh tính |
| ✅ | **Tương Thích Folia** | Hỗ trợ hoàn toàn PaperMC và Folia mới nhất |
| 🔄 | **Tự Động Hành Động** | Gỡ OP và un-permission khi người chơi logout |
| 🔗 | **DiscordSync** | Bắt buộc liên kết Discord + Minecraft trước khi sử dụng hot reload command |

---

## 📥 Cài Đặt

1. Tải bản mới nhất tại [**Releases**](https://github.com/Ipsecuz/OPProtection/releases/tag/minecraft)) 
2. Hoặc phiên bản cũ hoàn chỉnh không support folia [**Old Version**](https://www.mediafire.com/file/rcbnb0ack1wsnxg/OPProtection-2.3.3.jar/file)
3. Đặt file `.jar` vào thư mục `plugins/`.  
4. Khởi động lại server hoặc chạy lệnh `/reload`.  
5. Cấu hình file `config.yml`, `messages.yml`, `embed_discord.yml` theo nhu cầu.  
6. Thêm tên admin của bạn vào danh sách `op-whitelist` trong `config.yml`.  

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
