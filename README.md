OPProtection - Bảo Vệ Toàn Diện Cho Server Minecraft Của Bạn 🔐
Version
License
Java
Platform

OPProtection là một plugin bảo mật mạnh mẽ được thiết kế để bảo vệ server Minecraft của bạn khỏi việc lạm dụng quyền Operator (OP) và các mối đe dọa bảo mật khác. Với các tính năng như xác minh đa tầng, chặn IP/GeoIP, và chế độ khẩn cấp, OPProtection là lớp phòng thủ đầu tiên và quan trọng nhất cho server của bạn.

✨ Tính Năng Nổi Bật
🔐 Xác Minh OP Đa Tầng: Yêu cầu xác minh qua mật khẩu hoặc 2FA qua Discord.
🌍 Chặn GeoIP (Anti-VPN): Tự động chặn người chơi từ các quốc gia không được phép.
🚨 Chế Độ Khẩn Cấp (Emergency Mode): Kích hoạt ngay lập tức để khóa server khi có sự cố.
📢 Tích Hợp Discord: Gửi thông báo, yêu cầu xác minh và quản lý 2FA ngay trên Discord.
🛡️ Chống Lệnh Nguy Hiểm: Chặn các lệnh nhạy cảm như /op, /plugins, /stop.
🚫 Chặn Tab-Complete: Ngăn chặn việc hiển thị các lệnh bị cấm khi người chơi gõ tab.
🕵️ Chống IP/UUID Spoofing: Phát hiện và ngăn chặn các nỗ lực giả mạo IP/UUID.
✅ Tương Thích Folia: Hoạt động ổn định trên cả server PaperMC và Folia mới nhất.
🔄 Tự Động Hành Động: Tự động gỡ OP và thực thi các lệnh khi người chơi logout.
📥 Cài Đặt
Tải phiên bản mới nhất của OPProtection từ releases.
Đặt file .jar vào thư mục plugins/ trên server của bạn.
Khởi động lại server hoặc chạy lệnh /reload.
Cấu hình các file config.yml, messages.yml và embed_discord.yml theo nhu cầu.
Thêm tên admin của bạn vào danh sách op-whitelist trong config.yml.
⚙️ Cấu Hình
config.yml
Đây là file cấu hình chính của plugin.

yaml

Line Wrapping

Collapse
Copy
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
⌄
⌄
⌄
⌄
⌄
⌄
⌄
⌄
⌄
⌄
⌄
⌄
⌄
⌄
# Whitelist các người chơi được phép có OP
op-whitelist:
  - YourName
  - AnotherAdmin

# Mật khẩu để xác minh OP
op-password: "mat_khau_bao_mat"
# Thời gian (giây) để người chơi nhập mật khẩu
pass-timeout: 50

# Cấu hình Discord Bot (Xem hướng dẫn bên dưới)
discord:
  enabled: false
  token: "YOUR_BOT_TOKEN"
  channel-id: "YOUR_CHANNEL_ID"
  use-2fa: false

# Cấu hình chống VPN (GeoIP)
geoip:
  enabled: true
  allowed-countries:
    - "VN"  # Mã quốc gia (ví dụ: VN, US, SG)
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

# Các lệnh được phép khi người chơi chưa xác minh OP
allowed-commands:
  - login
  - register
  - oppass

# Hành động tự động khi người chơi trong whitelist logout
logout-actions:
  - "deop %player%"
  - "lp user %player% permission unset *"
messages.yml
File này cho phép bạn tùy chỉnh mọi thông báo trong game. Bạn có thể thay đổi màu sắc, văn bản và thêm các biến như %player%, %time%, %ip%.

embed_discord.yml
Tùy chỉnh giao diện của các thông báo được gửi đến Discord (màu sắc, tiêu đề, nội dung các trường).

🤖 Hướng Dẫn Cấu Hình Discord 2FA
Tạo một ứng dụng Bot trên Discord Developer Portal.
Tạo một Bot cho ứng dụng đó và lấy Token.
Bật Privileged Gateway Intents -> MESSAGE CONTENT INTENT.
Mời Bot vào server của bạn thông qua link OAuth2 -> URL Generator.
Lấy ID của kênh mà bạn muốn bot gửi thông báo (kích chuột phải vào kênh -> Copy Channel ID).
Điền token và channel-id vào file config.yml và đặt enabled: true, use-2fa: true.
📜 Lệnh & Quyền
Lệnh
Mô tả
Quyền
/oppass <mật khẩu>	Xác minh quyền OP của chính bạn.	Không cần
/oppass confirm <tên_người_chơi>	Xác minh OP cho người chơi khác (chỉ Console).	Console
/oppass resetip <tên_người_chơi>	Reset IP của một người chơi về 'unknown'.	Console
/opreload	Tải lại tất cả các file cấu hình.	Console
/opemergency	Bật hoặc tắt chế độ khẩn cấp.	Console

Quyền
Mô tả
opprotection.bypass.disabled-commands	Cho phép sử dụng tất cả các lệnh bị chặn.
opprotection.emergency	Cho phép sử dụng các lệnh ngay cả khi trong chế độ khẩn cấp.

❓ Hỏi Đáp & Gỡ Rối
Hỏi: Discord bot không kết nối được, log báo lỗi UnknownHostException?
Đáp: Đây là lỗi do máy chủ của bạn không thể kết nối đến Discord. Hãy thử các bước sau:

Thay đổi DNS của máy chủ sang 8.8.8.8 (Google) và 1.1.1.1 (Cloudflare).
Kiểm tra firewall của máy chủ hoặc nhà cung cấp hosting có chặn cổng 443 không.
Liên hệ nhà cung cấp hosting để hỏi về việc chặn kết nối đến Discord.
Hỏi: Tính năng GeoIP không chặn được người chơi từ quốc gia bị cấm?
Đáp: Lỗi này đã được khắc phục trong các phiên bản mới. Hãy đảm bảo bạn đang sử dụng phiên bản mới nhất của plugin. Logic kiểm tra đã được thay đổi thành đồng bộ để đảm bảo chặn chính xác.

Hỏi: Tôi cần thêm hỗ trợ ở đâu?
Đáp: Hãy tạo một issue mới trên trang GitHub Issues của dự án và cung cấp chi tiết lỗi từ file logs/latest.log.

🤝 Đóng Góp
Chúng tôi chào đón mọi đóng góp từ cộng đồng! Nếu bạn muốn báo lỗi, đề xuất tính năng hoặc gửi pull request, hãy làm điều đó trên GitHub.

📄 Giấy Phép
Dự án này được phân phối dưới giấy phép MIT.

👥 Tác Giả
Ipsecuz_
Kazami Studio
Cảm ơn bạn đã sử dụng OPProtection
