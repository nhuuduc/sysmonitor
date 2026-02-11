# Kế hoạch triển khai Auth0 cho SysMonitor

## 📋 Tổng quan

**Auth0** là dịch vụ Identity-as-a-Service cho phép:
- Đăng nhập qua Google, GitHub, Microsoft, v.v.
- Quản lý user, role, permission
- JWT token authentication
- Free tier: 7,500 active users/tháng

**Truy cập**: https://auth0.com

---

## Bước 1: Tạo Auth0 Application (5 phút)

### 1.1 Đăng ký tài khoản
1. Vào https://auth0.com/signup
2. Đăng ký bằng email hoặc Google/GitHub
3. Chọn region: **US** hoặc **EU**

### 1.2 Tạo Application mới
1. Dashboard → **Applications** → **Create Application**
2. Name: `SysMonitor VPS`
3. Type: **Regular Web Application**
4. Click **Create**

### 1.3 Cấu hình Application
Vào tab **Settings**:

```
Allowed Callback URLs:
https://dns.nhangiaz.com/callback
http://160.30.137.7:8090/callback

Allowed Logout URLs:
https://dns.nhangiaz.com
http://160.30.137.7:8090

Allowed Web Origins:
https://dns.nhangiaz.com
http://160.30.137.7:8090
```

### 1.4 Lưu thông tin
Copy các giá trị này để dùng sau:
- **Domain**: `your-tenant.auth0.com`
- **Client ID**: `abc123xyz...`
- **Client Secret**: `secret_xyz...`

---

## Bước 2: Cài đặt thư viện Auth0 (2 phút)

```bash
cd /root/.openclaw/workspace/sysmonitor
go get github.com/auth0-community/auth0
go get github.com/dgrijalva/jwt-go
```

---

## Bước 3: Code Auth Middleware

### 3.1 Thêm vào main.go

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "strings"
    
    "github.com/auth0-community/auth0"
    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "gopkg.in/square/go-jose.v2"
)

// Auth0 Configuration
var (
    auth0Domain       = os.Getenv("AUTH0_DOMAIN")       // your-tenant.auth0.com
    auth0ClientID     = os.Getenv("AUTH0_CLIENT_ID")   // abc123xyz...
    auth0ClientSecret = os.Getenv("AUTH0_CLIENT_SECRET") // secret_xyz...
    auth0CallbackURL  = "https://dns.nhangiaz.com/callback"
    
    store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
)

// Auth0 authenticator
type Authenticator struct {
    Domain       string
    ClientID     string
    ClientSecret string
    CallbackURL  string
}

func NewAuthenticator() (*Authenticator, error) {
    return &Authenticator{
        Domain:       auth0Domain,
        ClientID:     auth0ClientID,
        ClientSecret: auth0ClientSecret,
        CallbackURL:  auth0CallbackURL,
    }, nil
}

// Login handler - Redirect to Auth0
func (a *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
    // Build Auth0 authorization URL
    authURL := fmt.Sprintf(
        "https://%s/authorize?"+
        "response_type=code&"+
        "client_id=%s&"+
        "redirect_uri=%s&"+
        "scope=openid profile email&"+
        "state=%s",
        a.Domain,
        a.ClientID,
        url.QueryEscape(a.CallbackURL),
        generateState(),
    )
    
    http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// Callback handler - Process Auth0 response
func (a *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    if code == "" {
        http.Error(w, "Authorization code not found", http.StatusBadRequest)
        return
    }
    
    // Exchange code for token
    tokenURL := fmt.Sprintf("https://%s/oauth/token", a.Domain)
    data := url.Values{}
    data.Set("grant_type", "authorization_code")
    data.Set("client_id", a.ClientID)
    data.Set("client_secret", a.ClientSecret)
    data.Set("code", code)
    data.Set("redirect_uri", a.CallbackURL)
    
    resp, err := http.PostForm(tokenURL, data)
    if err != nil {
        http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()
    
    var tokenResponse struct {
        AccessToken  string `json:"access_token"`
        IDToken      string `json:"id_token"`
        TokenType    string `json:"token_type"`
        ExpiresIn    int    `json:"expires_in"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
        http.Error(w, "Failed to parse token", http.StatusInternalServerError)
        return
-    }
    
    // Verify and parse ID token
    userInfo, err := a.verifyToken(tokenResponse.IDToken)
    if err != nil {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }
    
    // Set session
    session, _ := store.Get(r, "auth-session")
    session.Values["authenticated"] = true
    session.Values["user_email"] = userInfo["email"]
    session.Values["user_name"] = userInfo["name"]
    session.Values["user_picture"] = userInfo["picture"]
    session.Save(r, w)
    
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Verify JWT token
func (a *Authenticator) verifyToken(idToken string) (map[string]interface{}, error) {
    // Fetch Auth0 JWKS
    jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", a.Domain)
    
    client := auth0.NewJWKClient(auth0.JWKClientOptions{
        URI: jwksURL,
    }, nil)
    
    configuration := auth0.NewConfiguration(client, []string{a.ClientID}, a.Domain, jose.RS256)
    validator := auth0.NewValidator(configuration, nil)
    
    token, err := validator.ValidateRequest(r)
    if err != nil {
        return nil, err
    }
    
    claims := map[string]interface{}{}
    err = token.Claims(&claims)
    return claims, err
}

// Logout handler
func (a *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "auth-session")
    session.Values["authenticated"] = false
    session.Save(r, w)
    
    // Redirect to Auth0 logout
    logoutURL := fmt.Sprintf(
        "https://%s/v2/logout?client_id=%s&returnTo=%s",
        a.Domain,
        a.ClientID,
        url.QueryEscape("https://dns.nhangiaz.com/login"),
    )
    
    http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

// Auth middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "auth-session")
        
        if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        
        next(w, r)
    }
}

func generateState() string {
    // Generate random state for CSRF protection
    return "random-state-string"
}
```

---

## Bước 4: Cập nhật Routes

```go
func main() {
    auth, _ := NewAuthenticator()
    
    r := mux.NewRouter()
    
    // Public routes
    r.HandleFunc("/login", auth.LoginHandler)
    r.HandleFunc("/callback", auth.CallbackHandler)
    r.HandleFunc("/logout", auth.LogoutHandler)
    
    // Protected routes
    r.HandleFunc("/", authMiddleware(indexHandler))
    r.HandleFunc("/api/system", authMiddleware(apiSystemHandler))
    r.HandleFunc("/api/processes", authMiddleware(apiProcessesHandler))
    r.HandleFunc("/api/ports", authMiddleware(apiPortsHandler))
    r.HandleFunc("/api/network", authMiddleware(apiNetworkHandler))
    r.HandleFunc("/api/kill/{pid}", authMiddleware(apiKillHandler)).Methods("POST")
    r.HandleFunc("/api/files", authMiddleware(apiFilesHandler))
    r.HandleFunc("/api/files/delete/{path:.*}", authMiddleware(apiDeleteFileHandler)).Methods("DELETE")
    r.HandleFunc("/api/files/content", authMiddleware(apiFileContentHandler))
    r.HandleFunc("/api/files/upload", authMiddleware(apiUploadHandler)).Methods("POST")
    
    port := ":8090"
    fmt.Printf("🚀 SysMonitor with Auth0 running on http://localhost%s\n", port)
    log.Fatal(http.ListenAndServe(port, r))
}
```

---

## Bước 5: Tạo trang Login

```html
<!-- templates/login.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Login - SysMonitor</title>
    <style>
        body {
            background: #0d1117;
            color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .login-box {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            width: 320px;
        }
        h1 { margin-bottom: 10px; }
        p { color: #8b949e; margin-bottom: 30px; }
        .btn-login {
            display: block;
            width: 100%;
            padding: 12px;
            background: #238636;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            margin-bottom: 10px;
        }
        .btn-login:hover { background: #2ea043; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>🔒 SysMonitor</h1>
        <p>System Monitoring Dashboard</p>
        <a href="/login" class="btn-login">Login with Auth0</a>
    </div>
</body>
</html>
```

---

## Bước 6: Environment Variables

```bash
# Tạo file .env
cat > /opt/sysmonitor/.env << 'EOF'
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id_here
AUTH0_CLIENT_SECRET=your_client_secret_here
SESSION_SECRET=your_random_secret_key_here
EOF

# Load environment
export $(cat /opt/sysmonitor/.env | xargs)
```

---

## Bước 7: Cấu hình Social Connections (Tùy chọn)

Trong Auth0 Dashboard:

1. **Authentication** → **Social**
2. Click **Create Connection**
3. Chọn Google/GitHub/Microsoft
4. Bật connection cho application

---

## Bước 8: Test và Deploy

```bash
# Build
cd /root/.openclaw/workspace/sysmonitor
go build -o sysmonitor .

# Set environment variables
export AUTH0_DOMAIN=your-tenant.auth0.com
export AUTH0_CLIENT_ID=xxx
export AUTH0_CLIENT_SECRET=xxx
export SESSION_SECRET=xxx

# Restart service
systemctl restart sysmonitor

# Check logs
journalctl -u sysmonitor -f
```

---

## 📊 Tổng kết Timeline

| Bước | ThờI gian | Mô tả |
|------|-----------|-------|
| 1. Auth0 Setup | 5 phút | Tạo account + application |
| 2. Cài thư viện | 2 phút | go get auth0 |
| 3. Code middleware | 15 phút | Login, callback, logout |
| 4. Update routes | 5 phút | Protect API endpoints |
| 5. Login page | 10 phút | HTML/CSS |
| 6. Test | 5 phút | Verify workflow |
| **Tổng** | **~45 phút** | |

---

## ✅ Checklist

- [ ] Đăng ký Auth0 account
- [ ] Tạo Application
- [ ] Cấu hình callback URLs
- [ ] Cài thư viện Go
- [ ] Code auth middleware
- [ ] Update routes
- [ ] Tạo login page
- [ ] Set environment variables
- [ ] Test login/logout
- [ ] Deploy production

---

Anh muốn mình bắt đầu implement từ bước nào? 🔐
