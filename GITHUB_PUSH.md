# Push SysMonitor lên GitHub

## Bước 1: Tạo GitHub Repository

1. Vào https://github.com/new
2. **Repository name**: `sysmonitor`
3. **Description**: `VPS System Monitor with Auth0 authentication`
4. Chọn **Private** (hoặc Public nếu muốn)
5. **Không tick** "Initialize with README"
6. Click **Create repository**

## Bước 2: Lấy URL Repo

Sau khi tạo, copy URL:
```
https://github.com/nhd369/sysmonitor.git
```

## Bước 3: Push Code

```bash
cd /root/.openclaw/workspace/sysmonitor

# Thêm remote
git remote add origin https://github.com/nhd369/sysmonitor.git

# Push lên GitHub
git push -u origin master
```

## Bước 4: Verify

Vào https://github.com/nhd369/sysmonitor để xem code đã push thành công chưa.

---

## 📝 Files đã push:

- `main.go` - Main application code
- `templates/index.html` - Dashboard UI
- `go.mod`, `go.sum` - Dependencies
- `AUTH0_SETUP.md` - Auth0 setup guide
- `AUTH0_PLAN.md` - Auth0 implementation plan

## 🔐 Lưu ý bảo mật:

**Không commit file chứa secrets!** Hiện tại code đã sử dụng environment variables:
- `AUTH0_DOMAIN`
- `AUTH0_CLIENT_ID`
- `AUTH0_CLIENT_SECRET`

Secrets này chỉ có ở server, không có trong code.

---

Done! 🚀
