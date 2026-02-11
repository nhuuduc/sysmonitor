# 🔐 Cấu hình Auth0 cho SysMonitor

## Bước 1: Đăng ký Auth0 (5 phút)

1. Vào https://auth0.com/signup
2. Đăng ký bằng email hoặc Google/GitHub
3. Chọn region: **US** hoặc **EU**

## Bước 2: Tạo Application

1. Dashboard → **Applications** → **Create Application**
2. **Name**: `SysMonitor VPS`
3. **Type**: Regular Web Application
4. Click **Create**

## Bước 3: Cấu hình Application

Vào tab **Settings**:

```
Allowed Callback URLs:
https://dns.nhangiaz.com/callback

Allowed Logout URLs:
https://dns.nhangiaz.com/login

Allowed Web Origins:
https://dns.nhangiaz.com
```

Click **Save Changes**

## Bước 4: Copy thông tin

Copy các giá trị này:

- **Domain**: `your-tenant.us.auth0.com`
- **Client ID**: `abc123xyz...`
- **Client Secret**: Click "Reveal" để copy

## Bước 5: Cập nhật SysMonitor

```bash
# Edit service file
nano /etc/systemd/system/sysmonitor.service
```

Thay thế các giá trị YOUR_...:

```ini
Environment="AUTH0_DOMAIN=your-tenant.us.auth0.com"
Environment="AUTH0_CLIENT_ID=your_actual_client_id"
Environment="AUTH0_CLIENT_SECRET=your_actual_secret"
Environment="AUTH0_CALLBACK_URL=https://dns.nhangiaz.com/callback"
Environment="SESSION_SECRET=$(openssl rand -base64 32)"
```

Save và reload:

```bash
systemctl daemon-reload
systemctl restart sysmonitor
```

## Bước 6: Thêm Social Connections (Tùy chọn)

Dashboard → **Authentication** → **Social**:

- Google: Bật để đăng nhập bằng Gmail
- GitHub: Bật để đăng nhập bằng GitHub
- Microsoft: Bật để đăng nhập bằng Outlook

## Bước 7: Test

1. Vào https://dns.nhangiaz.com
2. Click "Login with Auth0"
3. Đăng nhập bằng Google/GitHub
4. Xem dashboard sau khi login thành công

## 🚨 Troubleshooting

**Lỗi "OAuth not configured"**
→ Chưa set environment variables, kiểm tra lại service file

**Lỗi "Invalid state"**
→ Clear browser cookies và thử lại

**Callback không hoạt động**
→ Kiểm tra Allowed Callback URLs trong Auth0 settings

## 📝 Tóm tắt URL

| URL | Mô tả |
|-----|-------|
| https://dns.nhangiaz.com | Dashboard (yêu cầu login) |
| https://dns.nhangiaz.com/login | Trang login |
| https://dns.nhangiaz.com/callback | Auth0 callback |
| https://dns.nhangiaz.com/logout | Đăng xuất |

## 🔐 Bảo mật

- Session cookie: 7 ngày
- HTTPS only
- CSRF protection với state parameter
- HttpOnly + Secure + SameSite cookies

Ready! 🚀
