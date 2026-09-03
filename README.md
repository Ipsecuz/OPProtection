# 🛡️ OPProtection

![Version](https://img.shields.io/badge/version-2.6-blue.svg)
![Java](https://img.shields.io/badge/java-21%2B-orange.svg)
![Platform](https://img.shields.io/badge/platform-PaperMC%20%7C%20Folia-lightgrey.svg)
![PacketEvents](https://img.shields.io/badge/dependency-PacketEvents-red.svg)

**OPProtection** là plugin bảo mật dành cho server Minecraft, tập trung vào việc bảo vệ tài khoản quản trị, quyền **OP**, quyền LuckPerms wildcard `*`, xác minh nhiều lớp, chống spoof và giảm nguy cơ lộ thông tin server.

> **Lưu ý về phiên bản:** Source hiện tại được build với **Java 21** và Paper API **1.21.11**. Plugin khai báo `folia-supported: true` và có scheduler riêng để hỗ trợ Folia. Không nên quảng cáo Java 17+ cho bản source 2.6 này nếu chưa build/test lại bằng Java 17.

---

## ✨ Tính năng

| Tính năng | Mô tả |
|---|---|
| 🔐 OP Verification | Tài khoản quản trị phải xác minh bằng mật khẩu OPProtection trước khi sử dụng quyền cao. |
| 🔑 PBKDF2 Password Hash | Mật khẩu global không lưu plaintext; tạo/reset bằng console. |
| 🕶️ Secure `/oppass` | PacketEvents được dùng để hạn chế việc mật khẩu xuất hiện trong command log thông thường. |
| ⏱️ Verification Timeout | Tài khoản chưa xác minh sẽ bị khóa và có thể bị kick/ban khi hết thời gian. |
| 👑 OP Whitelist | Chỉ các tài khoản được chỉ định mới được coi là tài khoản quản trị hợp lệ. |
| 🛡️ LuckPerms Wildcard Protection | Theo dõi tài khoản có quyền cao, bao gồm wildcard `*`. |
| 🌐 GeoIP | Cho phép/chặn quốc gia theo mã ISO, ví dụ `VN`. |
| 🚪 Domain Whitelist | Chỉ cho phép kết nối bằng hostname/domain đã cấu hình. |
| 🔒 Strict Proxy IP | Chỉ cho phép backend nhận kết nối từ proxy IP/CIDR đã whitelist. |
| 🕵️ Anti Spoof | Kiểm tra socket IP, forwarded IP và UUID trong môi trường proxy. |
| 👑 Premium PreAuth | Xác minh tài khoản Premium cho các tài khoản trong `op-whitelist`. |
| 🔠 Exact Name Case | Có thể yêu cầu chữ hoa/thường trùng với tên Premium chính thức. |
| 🚨 Discord 2FA | Có thể yêu cầu mã 2FA Discord sau bước mật khẩu. |
| 🔗 Discord-Sync | Yêu cầu phiên Discord được phê duyệt trước các command nhạy cảm. |
| 🛑 Command Protection | Chặn các command nguy hiểm hoặc command làm lộ thông tin server. |
| 🚫 Tab-Complete Protection | Ẩn command nhạy cảm khỏi tab-complete. |
| 🕵️ F3 Brand Spoof | Thay đổi brand packet hiển thị trong F3. |
| 🧾 Security Audit Log | Ghi lại các sự kiện bảo mật và tự rotate log. |
| 🧬 Plugin Integrity | Theo dõi SHA-256 của các plugin JAR để phát hiện thay đổi. |
| 🔄 Logout Protection | Tự thu hồi OP/wildcard khi tài khoản quản trị logout. |
| 🌿 Folia Support | Hỗ trợ Paper/Folia với scheduler tương thích. |

---

# 📥 Cài đặt

## 1. Yêu cầu

- **Java 21 trở lên**
- **Paper 1.21.11** hoặc môi trường tương thích API hiện tại
- **Folia** được hỗ trợ
- **PacketEvents 2.12.1** — bắt buộc
- LuckPerms — tùy chọn, dùng cho tích hợp wildcard/permission
- Discord Bot — tùy chọn, chỉ cần nếu sử dụng Discord 2FA hoặc Discord-Sync

> OPProtection sẽ **tự disable** nếu PacketEvents chưa được bật.

## 2. Cài plugin

1. Tải `OPProtection-2.6.jar`.
2. Tải và cài **PacketEvents** vào thư mục `plugins/`.
3. Nếu sử dụng LuckPerms, cài LuckPerms.
4. Đặt `OPProtection-2.6.jar` vào `plugins/`.
5. Khởi động server.
6. Sau lần chạy đầu tiên, plugin sẽ tạo:
   - `plugins/OPProtection/config.yml`
   - `plugins/OPProtection/messages.yml`
   - `plugins/OPProtection/embed_discord.yml`
   - `plugins/OPProtection/config/`
7. Cấu hình `config.yml` và các file module trong `config/`.
8. Khởi động lại server hoặc dùng `/opreload` từ console.

---

# ⚙️ Cấu hình

Từ bản 2.6, cấu hình được chia thành **module** để dễ quản lý.

```text
plugins/
└── OPProtection/
    ├── config.yml
    ├── messages.yml
    ├── embed_discord.yml
    └── config/
        ├── core.yml
        ├── commands.yml
        ├── security.yml
        ├── geoip.yml
        ├── domain.yml
        ├── discord.yml
        ├── discord-sync.yml
        ├── premium.yml
        └── brand.yml
```

### Quan trọng

Các file trong `config/` được merge vào cấu hình chính khi plugin load.

**Ưu tiên cấu hình:**

```text
config/*.yml  >  config.yml
```

Nếu cùng một key xuất hiện ở cả hai nơi, giá trị trong module sẽ được ưu tiên.

> Sau khi chỉnh config, dùng `/opreload` từ **console**. Không reload bằng `/reload` của Bukkit/Paper.

---

# 🔐 1. `config/core.yml` — Cấu hình bảo vệ OP

Đây là file quan trọng nhất.

### `op-whitelist`

```yaml
op-whitelist:
  - "YourName"
  - "AnotherAdmin"
```

Danh sách tài khoản được phép nhận quyền quản trị.

Nên chỉ thêm tài khoản admin thật sự.

### `op-password`

```yaml
op-password: ""
```

**Không nhập mật khẩu plaintext vào đây.**

Hãy tạo mật khẩu bằng console:

```text
oppass createpass <mật-khẩu>
```

Ví dụ:

```text
oppass createpass MyVeryStrongPassword123!
```

Sau đó plugin sẽ lưu hash PBKDF2.

### `pass-timeout`

```yaml
pass-timeout: 60
```

Thời gian tối đa để hoàn thành bước xác minh.

Đơn vị: **giây**.

Khuyến nghị:

```yaml
pass-timeout: 60
```

### `op-verification-reset-time`

```yaml
op-verification-reset-time: 20
```

Số phút một phiên quyền cao được giữ trước khi phải xác minh lại.

Khuyến nghị:

- Server nhỏ: `20`
- Server có nhiều admin: `15`
- Server yêu cầu bảo mật cao: `5-10`

### `verification-timeout-action`

```yaml
verification-timeout-action: "ban"
```

Có 2 lựa chọn:

```yaml
verification-timeout-action: "ban"
```

hoặc:

```yaml
verification-timeout-action: "kick"
```

- `ban`: bảo mật nghiêm ngặt hơn.
- `kick`: ít mạnh tay hơn, phù hợp khi test.

### `logout-actions`

```yaml
logout-actions:
  - "deop %player%"
  - "lp user %player% permission unset *"
  - "gamemode survival %player%"
```

Các command console được chạy khi admin logout.

`%player%` sẽ được thay bằng tên người chơi.

Khuyến nghị giữ ít nhất:

```yaml
logout-actions:
  - "deop %player%"
  - "lp user %player% permission unset *"
```

---

# 🛑 2. `config/commands.yml` — Chặn command

## `disabled-commands`

```yaml
disabled-commands:
  - "op"
  - "pl"
  - "plugins"
  - "ver"
  - "version"
  - "luckperms"
  - "lp"
```

Các command bị khóa.

**Không cần thêm `/` ở đầu.**

Đúng:

```yaml
- "op"
```

Không cần:

```yaml
- "/op"
```

Plugin có normalize command, nhưng nên dùng format không có `/` để config dễ đọc.

Có thể chặn namespace:

```yaml
- "bukkit:version"
- "luckperms:lp"
```

## `allowed-commands`

```yaml
allowed-commands:
  - "login"
  - "l"
  - "register"
```

Các command được phép sử dụng khi tài khoản đang trong trạng thái khóa/chờ xác minh.

Nếu server dùng plugin login khác, hãy thêm command login của plugin đó.

## Console command protection

```yaml
console-blocked-cmd:
  enabled: false
  commands:
    - "about"
    - "stop"
```

Mặc định nên để:

```yaml
enabled: false
```

Nếu bật, console cũng sẽ bị áp dụng danh sách command này.

---

# 🔒 3. `config/security.yml` — Bảo mật nâng cao

## Password policy

```yaml
password-security:
  min-length: 10
  generated-length: 24
  max-attempts: 5
  attempt-window-seconds: 60
  lockout-seconds: 180
```

Ý nghĩa:

| Key | Ý nghĩa |
|---|---|
| `min-length` | Độ dài tối thiểu password |
| `generated-length` | Độ dài password tự sinh |
| `max-attempts` | Số lần nhập sai tối đa |
| `attempt-window-seconds` | Cửa sổ tính số lần sai |
| `lockout-seconds` | Thời gian khóa |
| `max-2fa-attempts` | Số lần nhập sai 2FA |
| `2fa-lockout-seconds` | Thời gian khóa sau khi sai 2FA |

Khuyến nghị giữ mặc định.

## Ẩn `/oppass`

```yaml
secure-command-input:
  hide-oppass-from-console-log: true
```

Nên luôn để:

```yaml
true
```

Mục đích là hạn chế việc password xuất hiện trong command logging thông thường.

## Anti-spam

```yaml
anti-spam:
  enabled: false
  delay-seconds: 1
```

Nếu server có vấn đề spam command:

```yaml
enabled: true
```

## Tab-complete

```yaml
tab-complete-block:
  enabled: true
  debug: false
```

Production nên:

```yaml
enabled: true
debug: false
```

Không nên bật `debug: true` trên server thật nếu không cần debug.

## Plugin Integrity

```yaml
integrity-check:
  enabled: true
  interval-minutes: 30
```

Plugin sẽ theo dõi SHA-256 của các JAR trong thư mục `plugins/`.

Đây là **cơ chế cảnh báo**, không phải antivirus.

### Tạo baseline

Từ console:

```text
/opreload hashaccept
```

Kiểm tra:

```text
/opreload hashcheck
```

> Chỉ chạy `hashaccept` sau khi chắc chắn toàn bộ plugin JAR hiện tại là bản bạn tin tưởng.

---

# 🌍 4. `config/geoip.yml` — Chặn quốc gia / GeoIP

Ví dụ chỉ cho Việt Nam:

```yaml
geoip:
  enabled: true

  allowed-countries:
    - "VN"

  timeout-ms: 3000
  cache-seconds: 1800
  fail-closed: true
```

Mã quốc gia dùng ISO-3166-1 alpha-2.

Ví dụ:

```text
VN = Việt Nam
US = Hoa Kỳ
SG = Singapore
JP = Nhật Bản
KR = Hàn Quốc
```

### `fail-closed`

```yaml
fail-closed: true
```

Nếu API GeoIP timeout/lỗi, kết nối sẽ bị chặn.

Bảo mật cao:

```yaml
fail-closed: true
```

Ít gây ảnh hưởng khi API lỗi:

```yaml
fail-closed: false
```

OPProtection hiện sử dụng HTTPS tới dịch vụ `ipwho.is`.

---

# 🌐 5. `config/domain.yml` — Domain Whitelist

Nếu server chạy qua domain:

```yaml
domain-whitelist:
  enabled: true

  allowed-domains:
    - "play.example.com"
    - "mc.example.com"

  allow-subdomains: false
```

### Cho phép subdomain

```yaml
allow-subdomains: true
```

Ví dụ domain:

```text
play.example.com
```

sẽ có thể cho phép:

```text
asia.play.example.com
```

nếu plugin xử lý domain theo cấu hình này.

---

# 🔒 Strict Proxy IP

Nếu backend nằm sau Velocity/Bungee:

```yaml
strict-proxy-ip:
  enabled: true

  allowed-proxy-ips:
    - "127.0.0.1"
    - "::1"

  block-when-empty: true
```

Nếu proxy nằm trên máy khác, thay bằng IP proxy thật:

```yaml
allowed-proxy-ips:
  - "10.0.0.10"
```

Có thể dùng CIDR/wildcard theo cấu hình hỗ trợ của module.

### ⚠️ Cực kỳ quan trọng

Nếu backend chạy sau proxy, **không chỉ dựa vào domain whitelist**.

Nên:

1. Firewall chặn port backend từ Internet.
2. Chỉ proxy được phép kết nối backend.
3. Bật `strict-proxy-ip`.
4. Cấu hình forwarding UUID/IP đúng ở proxy.

Ví dụ kiến trúc:

```text
Player
   │
   ▼
play.example.com
   │
   ▼
Velocity/Bungee
   │
   │ only trusted proxy IP
   ▼
Paper/Folia backend
   │
   ▼
OPProtection
```

---

# 🤖 6. `config/discord.yml` — Discord Bot / 2FA

## Bật Discord

```yaml
discord:
  enabled: true
  token: "YOUR_BOT_TOKEN"
  channel-id: "123456789012345678"
  use-2fa: true
```

### Không chia sẻ Bot Token

Token Discord là secret.

Không commit token vào GitHub và không gửi token cho người khác.

---

## 🧩 Tạo Discord Bot

### Bước 1 — Discord Developer Portal

Vào Discord Developer Portal và:

1. Create Application.
2. Chọn **Bot**.
3. Add Bot.
4. Copy Bot Token.
5. Bật **MESSAGE CONTENT INTENT** nếu bot của bạn cần quyền đọc message content.
6. Invite bot vào Discord server.

### Bước 2 — Lấy Channel ID

Bật Developer Mode trong Discord:

```text
User Settings
→ Advanced
→ Developer Mode
```

Sau đó:

```text
Right Click Channel
→ Copy Channel ID
```

Điền:

```yaml
channel-id: "ID_KENH_DISCORD"
```

### Bước 3 — Bật 2FA

```yaml
discord:
  enabled: true
  use-2fa: true
```

Khi admin xác minh password, OPProtection có thể gửi mã 2FA một lần vào Discord.

Mã có thời gian hết hạn:

```yaml
two-fa-code-timeout-seconds: 60
```

---

# 🔗 7. `config/discord-sync.yml` — Discord-Sync

Discord-Sync khác Discord 2FA.

- **Discord 2FA:** mã một lần để xác minh quyền cao.
- **Discord-Sync:** tạo một phiên liên kết/xác minh Discord để bảo vệ các command nhạy cảm.

Bật:

```yaml
discord-sync:
  enabled: true
```

## Người được phép phê duyệt

Có thể dùng Discord User ID:

```yaml
allowed-discord-user-ids:
  - "123456789012345678"
```

Hoặc Role ID:

```yaml
allowed-discord-role-ids:
  - "987654321098765432"
```

Nên cấu hình **ít nhất một User ID hoặc Role ID**.

Nếu cả hai danh sách đều trống, không ai có quyền phê duyệt.

## Thời gian xác minh

```yaml
verification-timeout-seconds: 300
request-timeout-seconds: 120
```

- `verification-timeout-seconds`: thời gian phiên đã xác minh còn hiệu lực.
- `request-timeout-seconds`: thời gian yêu cầu phê duyệt còn hiệu lực.

## Command cần Discord-Sync

```yaml
commands:
  - "/reload"
  - "/stop"
  - "/restart"
  - "/op"
  - "/deop"
  - "/ban"
  - "/kick"
  - "/save-all"
```

Có thể thêm/bớt command theo nhu cầu.

### ⚠️ Lưu ý về `/stop`

OPProtection không cho phép cơ chế Discord-Sync biến một hành động chưa xác minh thành shutdown server.

Không nên thiết kế security system theo hướng admin chưa verify có thể làm server tắt chỉ bằng một command.

---

# 👑 8. `config/premium.yml` — Premium Authentication

Bật:

```yaml
premium-auth:
  enabled: true
```

OPProtection có thể xác minh tài khoản Premium qua Minecraft Services.

## Server online-mode

Nếu:

```text
online-mode=true
```

UUID Premium được server xác minh.

## Backend sau proxy

Nếu backend sau Velocity/Bungee:

```yaml
ip-forwarding: true
```

Proxy phải forwarding UUID/IP đúng cách.

Đồng thời nên bật strict proxy IP.

## Server cracked

Nếu server:

```text
online-mode=false
```

OPProtection có thể tra cứu tên Premium, nhưng:

> Trên server cracked, việc tên tồn tại trên Mojang **không chứng minh người đang kết nối sở hữu tài khoản đó**.

Vì vậy không nên bật bypass bảo mật chỉ dựa vào tên Premium.

Khuyến nghị:

```yaml
op-whitelist-premium-auto-bypass-2fa: false
```

Đây là cấu hình an toàn hơn.

---

# 🔠 Exact Name Case

```yaml
require-exact-name-case: true
```

Nếu bật, chữ hoa/thường của username phải khớp với tên Premium chính thức.

Ví dụ tài khoản Premium:

```text
Ipsecuz_
```

thì:

```text
Ipsecuz_
```

được chấp nhận.

Còn:

```text
ipsecuz_
```

có thể bị từ chối.

---

# 🧾 Premium Registry

Admin có thể xác minh thủ công từ console.

Đăng ký:

```text
/oppass premium-register <player>
```

Gỡ:

```text
/oppass premium-unregister <player>
```

Xem danh sách:

```text
/oppass premium-list
```

---

# 🎨 9. `config/brand.yml` — F3 Brand

```yaml
f3-brand-spoof:
  enabled: true
  fake-brand: "&bOP&fProtection"
  debug: false
```

Khi bật, plugin thay đổi brand packet hiển thị trong F3.

Production nên:

```yaml
debug: false
```

---

# 💬 10. `messages.yml`

File này chứa toàn bộ message hiển thị cho người chơi.

Ví dụ:

```yaml
prefix: "&8[&b&lOP&fProtection&8] &7"
```

Có thể thay đổi message mà không cần sửa source.

Plugin hỗ trợ màu legacy và một số mã hex theo format:

```text
&#42D4F4
```

Ví dụ:

```yaml
login_success: "&#6EE7A8Xác minh OP thành công."
```

---

# 📢 11. `embed_discord.yml`

File này điều khiển nội dung Discord Embed.

Các nhóm embed chính gồm:

```text
request
verified
2fa-code
suspicious
spoof-alert
discord-sync-alert
discord-sync-verified
discord-sync-request
ip-change-alert
```

Có thể thay đổi:

- title
- color
- fields
- footer
- placeholder

Ví dụ:

```yaml
request:
  title: "🔐 OPProtection • Yêu cầu xác minh"
  color: 4379892
```

---

# 🔑 Lệnh

## `/oppass`

### Player

Xác minh:

```text
/oppass <mật-khẩu>
```

Nếu Discord 2FA được bật:

```text
/oppass <mã-2FA>
```

### Đổi password cá nhân

```text
/oppass change <mật-khẩu-cũ> <mật-khẩu-mới>
```

### Console

Tạo password:

```text
/oppass createpass <mật-khẩu>
```

Reset password:

```text
/oppass resetpass <mật-khẩu-mới>
```

Hoặc để plugin tự sinh password:

```text
/oppass resetpass
```

Password tự sinh chỉ hiển thị một lần.

### Console xác nhận player

```text
/oppass confirm <player>
```

Dùng khi quy trình yêu cầu console phê duyệt sau bước password.

### Reset IP

```text
/oppass resetip <player>
```

Lệnh này xóa IP fingerprint đã lưu của player.

Nếu player đang online, plugin sẽ ngắt kết nối để bắt đăng nhập/xác minh lại.

---

# 🔗 Discord-Sync Commands

Player tạo yêu cầu:

```text
/verify
```

Admin/console phê duyệt:

```text
/opverify <player> <mã-một-lần>
```

Một player đã xác minh không thể tự dùng `/opverify` để tự phê duyệt chính mình.

---

# 🔄 Reload

```text
/opreload
```

**Chỉ chạy từ console.**

Không dùng:

```text
/reload
```

để reload OPProtection.

### Kiểm tra integrity

```text
/opreload hashcheck
```

### Chấp nhận baseline mới

```text
/opreload hashaccept
```

Chỉ dùng `hashaccept` khi bạn chắc chắn các plugin hiện tại an toàn.

---

# 🧑‍💼 Quyền

| Permission | Mặc định | Chức năng |
|---|---:|---|
| `opprotection.oppass` | OP | Sử dụng `/oppass` |
| `opprotection.opreload` | OP | Reload / integrity |
| `opprotection.verify` | OP | Tạo Discord-Sync request |
| `opprotection.opverify` | OP | Phê duyệt Discord-Sync |
| `opprotection.bypass.blacklist` | false | Bypass blacklist |
| `opprotection.emergency` | false | Quyền emergency cho thao tác OP/deop an toàn |
| `opprotection.temp` | false | Permission tạm thời |

---

# 🔐 Cấu hình khuyến nghị cho server Production

Nếu server của bạn là server thật và ưu tiên bảo mật, có thể bắt đầu với:

### `config/core.yml`

```yaml
metric: true

ip-forwarding: false

op-verification-reset-time: 15

op-whitelist:
  - "YourAdminName"

op-password: ""

pass-timeout: 60

verification-timeout-action: "kick"

logout-actions:
  - "deop %player%"
  - "lp user %player% permission unset *"
```

Sau đó tạo password bằng console:

```text
/oppass createpass <password-mạnh>
```

### `config/security.yml`

```yaml
password-security:
  min-length: 12
  generated-length: 24
  max-attempts: 5
  attempt-window-seconds: 60
  lockout-seconds: 180
  max-2fa-attempts: 5
  2fa-lockout-seconds: 300

secure-command-input:
  hide-oppass-from-console-log: true

tab-complete-block:
  enabled: true
  debug: false

integrity-check:
  enabled: true
  interval-minutes: 30
```

### `config/geoip.yml`

Nếu chỉ cho Việt Nam:

```yaml
geoip:
  enabled: true
  allowed-countries:
    - "VN"
  timeout-ms: 3000
  cache-seconds: 1800
  fail-closed: true
```

### `config/premium.yml`

```yaml
premium-auth:
  enabled: true
  fail-closed: true
  require-exact-name-case: true
  op-whitelist-premium-auto-bypass-2fa: false

  cracked-mode:
    enabled: true
```

### Discord

Nếu muốn bảo mật nhiều lớp:

```yaml
discord:
  enabled: true
  use-2fa: true
```

và:

```yaml
discord-sync:
  enabled: true
```

Sau đó bắt buộc cấu hình:

```yaml
allowed-discord-user-ids:
  - "YOUR_DISCORD_USER_ID"
```

hoặc:

```yaml
allowed-discord-role-ids:
  - "YOUR_DISCORD_ROLE_ID"
```

---

# ⚠️ Những điều KHÔNG nên làm

### ❌ Không lưu password plaintext

Không làm:

```yaml
op-password: "123456"
```

Hãy dùng:

```text
/oppass createpass 123456
```

Tất nhiên, password thực tế nên mạnh hơn rất nhiều.

### ❌ Không public Discord Bot Token

Không upload:

```yaml
token: "REAL_BOT_TOKEN"
```

lên GitHub.

### ❌ Không mở trực tiếp backend

Nếu dùng Velocity/Bungee:

```text
Internet → Backend
```

là cấu hình rất nguy hiểm.

Nên:

```text
Internet → Proxy → Backend
```

và firewall backend chỉ cho phép proxy.

### ❌ Không bật Premium auto-bypass 2FA trên cracked server nếu không hiểu rủi ro

```yaml
op-whitelist-premium-auto-bypass-2fa: false
```

là lựa chọn an toàn hơn.

### ❌ Không dùng `/reload` để reload plugin

Dùng:

```text
/opreload
```

từ console.

---

# 🧪 Quy trình cài đặt lần đầu

Sau khi cài plugin:

### Bước 1

Cài PacketEvents và restart server.

### Bước 2

Thêm admin:

```yaml
op-whitelist:
  - "YourName"
```

### Bước 3

Tạo password:

```text
/oppass createpass <password-mạnh>
```

### Bước 4

OP admin join server.

### Bước 5

Xác minh:

```text
/oppass <password>
```

### Bước 6

Nếu bật Discord 2FA, nhập:

```text
/oppass <mã-2FA>
```

### Bước 7

Nếu dùng Discord-Sync:

```text
/verify
```

Sau đó chờ người có quyền phê duyệt trên Discord.

### Bước 8

Kiểm tra integrity:

```text
/opreload hashaccept
```

Chỉ chạy sau khi xác nhận plugin JAR hiện tại an toàn.

---

# 🆘 Xử lý sự cố

## Plugin tự tắt khi startup

Kiểm tra console có:

```text
PacketEvents chưa được bật
```

Nếu có:

1. Cài PacketEvents.
2. Đảm bảo PacketEvents load trước OPProtection.
3. Restart server.

## Discord không hoạt động

Kiểm tra:

```yaml
discord:
  enabled: true
  token: "BOT_TOKEN"
  channel-id: "CHANNEL_ID"
```

Kiểm tra bot đã được invite vào server và có quyền gửi message/embed ở channel.

## Discord-Sync không ai phê duyệt được

Kiểm tra:

```yaml
allowed-discord-user-ids:
  - "USER_ID"
```

hoặc:

```yaml
allowed-discord-role-ids:
  - "ROLE_ID"
```

Không được để cả hai danh sách trống.

## GeoIP chặn tất cả

Kiểm tra:

```yaml
allowed-countries:
  - "VN"
```

và:

```yaml
fail-closed: true
```

Nếu API GeoIP đang lỗi, `fail-closed: true` sẽ ưu tiên bảo mật và chặn.

## Backend sau Velocity/Bungee bị chặn

Kiểm tra:

```yaml
ip-forwarding: true
```

và:

```yaml
domain-whitelist:
  strict-proxy-ip:
    enabled: true
    allowed-proxy-ips:
      - "IP_PROXY"
```

Đồng thời kiểm tra forwarding và firewall.

---

# 📁 Dữ liệu plugin

OPProtection có thể tạo dữ liệu bảo mật trong thư mục plugin để lưu:

- IP fingerprint
- trạng thái xác minh
- Premium Registry
- audit log
- integrity baseline
- dữ liệu phiên bảo mật

**Không nên xóa toàn bộ thư mục plugin khi server đang production** nếu chưa backup.

---

# 🤝 Đóng góp & Báo lỗi

Nếu phát hiện lỗi hoặc muốn đề xuất tính năng, hãy cung cấp:

1. Phiên bản Minecraft.
2. Paper/Folia + build.
3. Phiên bản OPProtection.
4. Phiên bản PacketEvents.
5. Các plugin liên quan.
6. Log lỗi đầy đủ từ console.
7. Config liên quan đã che token/password.

**Không gửi:**

- Discord Bot Token
- Password OPProtection
- API key
- IP/private credential không cần thiết

---

# 👤 Tác giả

**Ipsecuz_**

**Fox Studio**

Discord hỗ trợ: `habitat_`

---

## ❤️ Cảm ơn

Cảm ơn bạn đã sử dụng **OPProtection**.

Plugin được thiết kế với mục tiêu biến quyền `OP` và các quyền quản trị cao thành một **quy trình xác minh nhiều lớp**, thay vì chỉ dựa vào việc tài khoản có OP hay không.

> 🔐 **OP không nên là lớp bảo mật cuối cùng. Hãy biến nó thành lớp được bảo vệ.**
