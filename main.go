package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/oauth2"
)

type SystemInfo struct {
	Hostname    string  `json:"hostname"`
	Platform    string  `json:"platform"`
	Uptime      string  `json:"uptime"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemTotal    uint64  `json:"mem_total"`
	MemUsed     uint64  `json:"mem_used"`
	MemPercent  float64 `json:"mem_percent"`
	DiskTotal   uint64  `json:"disk_total"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskPercent float64 `json:"disk_percent"`
}

type FileInfo struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	SizeStr  string `json:"size_str"`
	IsDir    bool   `json:"is_dir"`
	ModTime  string `json:"mod_time"`
	Mode     string `json:"mode"`
}

var (
	auth0Domain       = os.Getenv("AUTH0_DOMAIN")
	auth0ClientID     = os.Getenv("AUTH0_CLIENT_ID")
	auth0ClientSecret = os.Getenv("AUTH0_CLIENT_SECRET")
	auth0CallbackURL  = os.Getenv("AUTH0_CALLBACK_URL")
	
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	oauthConfig *oauth2.Config
)

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	
	if auth0Domain != "" && auth0ClientID != "" {
		oauthConfig = &oauth2.Config{
			ClientID:     auth0ClientID,
			ClientSecret: auth0ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("https://%s/authorize", auth0Domain),
				TokenURL: fmt.Sprintf("https://%s/oauth/token", auth0Domain),
			},
			RedirectURL: auth0CallbackURL,
			Scopes:      []string{"openid", "profile", "email"},
		}
	}
}

func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if oauthConfig == nil {
		http.Error(w, "OAuth not configured", http.StatusInternalServerError)
		return
	}
	state := generateState()
	session, _ := store.Get(r, "auth-session")
	session.Values["state"] = state
	session.Save(r, w)
	url := oauthConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("connection", "google-oauth2"))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	if oauthConfig == nil {
		http.Error(w, "OAuth not configured", http.StatusInternalServerError)
		return
	}
	
	session, _ := store.Get(r, "auth-session")
	expectedState, _ := session.Values["state"].(string)
	state := r.URL.Query().Get("state")
	
	// Debug logging
	log.Printf("Callback - Expected state: %s, Got state: %s", expectedState, state)
	
	// Clear state from session immediately to prevent replay
	delete(session.Values, "state")
	session.Save(r, w)
	
	if state == "" || expectedState == "" || state != expectedState {
		log.Printf("State mismatch or empty - expected: %s, got: %s", expectedState, state)
		http.Error(w, "Invalid state. Please try logging in again.", http.StatusBadRequest)
		return
	}
	
	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}
	
	userInfo, _ := getUserInfo(token.AccessToken)
	if userInfo.Email != "nhuuduc166@gmail.com" {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	session.Values["authenticated"] = true
	session.Values["user_email"] = userInfo.Email
	session.Save(r, w)
	log.Printf("User logged in: %s", userInfo.Email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type UserInfo struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func getUserInfo(token string) (*UserInfo, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/userinfo", auth0Domain), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var u UserInfo
	json.NewDecoder(resp.Body).Decode(&u)
	return &u, nil
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	logoutURL := fmt.Sprintf("https://%s/v2/logout?client_id=%s&returnTo=%s",
		auth0Domain, auth0ClientID, url.QueryEscape("https://ai.nhangiaz.com/login"))
	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if oauthConfig == nil {
			next(w, r)
			return
		}
		session, _ := store.Get(r, "auth-session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - SysMonitor</title>
<style>
body { background: linear-gradient(135deg, #0d1117, #161b22); color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
.login-box { background: #161b22; border: 1px solid #30363d; border-radius: 16px; padding: 48px; text-align: center; width: 360px; box-shadow: 0 20px 40px rgba(0,0,0,0.3); }
.logo { width: 64px; height: 64px; background: linear-gradient(135deg, #58a6ff, #a371f7); border-radius: 16px; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 32px; }
h1 { margin-bottom: 8px; color: #f0f6fc; }
p { color: #8b949e; margin-bottom: 32px; }
.btn-login { display: flex; align-items: center; justify-content: center; gap: 12px; width: 100%; padding: 14px; background: #fff; color: #3c4043; border: none; border-radius: 8px; font-size: 15px; font-weight: 500; cursor: pointer; text-decoration: none; transition: all 0.2s; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.btn-login:hover { background: #f8f9fa; box-shadow: 0 2px 6px rgba(0,0,0,0.15); transform: translateY(-1px); }
.footer { margin-top: 32px; padding-top: 24px; border-top: 1px solid #21262d; font-size: 12px; color: #6e7681; }
</style>
</head>
<body>
<div class="login-box">
<div class="logo">🔒</div>
<h1>Welcome Back</h1>
<p>Sign in to access SysMonitor Dashboard</p>
<a href="/auth/login" class="btn-login">
<svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
<span>Continue with Google</span>
</a>
<div class="footer">Protected by Auth0</div>
</div>
</body>
</html>`)
}

func getSystemInfo() SystemInfo {
	hostInfo, _ := host.Info()
	cpuPercent, _ := cpu.Percent(time.Second, false)
	memInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")
	uptime := time.Duration(hostInfo.Uptime) * time.Second
	uptimeStr := fmt.Sprintf("%dd %dh %dm", int(uptime.Hours())/24, int(uptime.Hours())%24, int(uptime.Minutes())%60)
	cpuPct := 0.0
	if len(cpuPercent) > 0 {
		cpuPct = cpuPercent[0]
	}
	return SystemInfo{
		Hostname:    hostInfo.Hostname,
		Platform:    hostInfo.Platform + " " + hostInfo.PlatformVersion,
		Uptime:      uptimeStr,
		CPUPercent:  cpuPct,
		MemTotal:    memInfo.Total / 1024 / 1024,
		MemUsed:     memInfo.Used / 1024 / 1024,
		MemPercent:  memInfo.UsedPercent,
		DiskTotal:   diskInfo.Total / 1024 / 1024 / 1024,
		DiskUsed:    diskInfo.Used / 1024 / 1024 / 1024,
		DiskPercent: diskInfo.UsedPercent,
	}
}

func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func getProcesses() []map[string]interface{} {
	procs, _ := process.Processes()
	var result []map[string]interface{}
	for _, p := range procs {
		name, _ := p.Name()
		cpuPct, _ := p.CPUPercent()
		memPct, _ := p.MemoryPercent()
		status, _ := p.Status()
		user, _ := p.Username()
		cmdline, _ := p.Cmdline()
		if len(cmdline) > 100 {
			cmdline = cmdline[:100] + "..."
		}
		result = append(result, map[string]interface{}{
			"pid":     p.Pid,
			"name":    name,
			"cpu":     cpuPct,
			"memory":  memPct,
			"status":  strings.Join(status, ","),
			"user":    user,
			"command": cmdline,
		})
	}
	return result
}

func getPorts() []map[string]interface{} {
	connections, _ := net.Connections("all")
	var result []map[string]interface{}
	for _, conn := range connections {
		if conn.Status == "LISTEN" {
			procName := ""
			if conn.Pid > 0 {
				p, err := process.NewProcess(conn.Pid)
				if err == nil {
					procName, _ = p.Name()
				}
			}
			proto := "TCP"
			if conn.Type == syscall.SOCK_DGRAM {
				proto = "UDP"
			}
			result = append(result, map[string]interface{}{
				"protocol": proto,
				"local_ip": conn.Laddr.IP,
				"port":     conn.Laddr.Port,
				"pid":      conn.Pid,
				"process":  procName,
				"status":   conn.Status,
			})
		}
	}
	return result
}

func getNetworkStats() []map[string]interface{} {
	interfaces, _ := net.IOCounters(true)
	var result []map[string]interface{}
	for _, iface := range interfaces {
		if iface.BytesSent > 0 || iface.BytesRecv > 0 {
			result = append(result, map[string]interface{}{
				"interface":    iface.Name,
				"bytes_sent":   iface.BytesSent,
				"bytes_recv":   iface.BytesRecv,
				"packets_sent": iface.PacketsSent,
				"packets_recv": iface.PacketsRecv,
			})
		}
	}
	return result
}

func getFiles(dir string) ([]FileInfo, error) {
	var files []FileInfo
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, FileInfo{
			Name:    entry.Name(),
			Path:    filepath.Join(dir, entry.Name()),
			Size:    info.Size(),
			SizeStr: formatSize(info.Size()),
			IsDir:   entry.IsDir(),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			Mode:    info.Mode().String(),
		})
	}
	return files, nil
}

func main() {
	r := mux.NewRouter()
	
	r.HandleFunc("/login", loginPage)
	r.HandleFunc("/auth/login", loginHandler)
	r.HandleFunc("/callback", callbackHandler)
	r.HandleFunc("/logout", logoutHandler)
	
	r.HandleFunc("/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/index.html")
	}))
	
	r.HandleFunc("/api/system", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getSystemInfo())
	}))
	
	r.HandleFunc("/api/files", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		dir := r.URL.Query().Get("dir")
		if dir == "" {
			dir = "/"
		}
		if !strings.HasPrefix(dir, "/") {
			dir = "/" + dir
		}
		files, err := getFiles(dir)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "dir": dir, "files": files})
	}))
	
	r.HandleFunc("/api/files/delete/{path:.*}", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		path := vars["path"]
		path, _ = url.QueryUnescape(path)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		info, err := os.Stat(path)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
			return
		}
		if info.IsDir() {
			err = os.RemoveAll(path)
		} else {
			err = os.Remove(path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
		} else {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Deleted successfully"})
		}
	})).Methods("DELETE")
	
	// Processes, Ports, Network APIs
	r.HandleFunc("/api/processes", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getProcesses())
	}))
	
	r.HandleFunc("/api/ports", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getPorts())
	}))
	
	r.HandleFunc("/api/network", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getNetworkStats())
	}))
	
	r.HandleFunc("/api/files/save", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		
		// Validate path
		if req.Path == "" {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Path required"})
			return
		}
		if !strings.HasPrefix(req.Path, "/") {
			req.Path = "/" + req.Path
		}
		
		err := os.WriteFile(req.Path, []byte(req.Content), 0644)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
		} else {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Saved successfully"})
		}
	})).Methods("POST")
	
	// File read API
	r.HandleFunc("/api/files/read", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if path == "" {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Path required"})
			return
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		
		// Check file size (max 1MB)
		info, err := os.Stat(path)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
			return
		}
		if info.Size() > 1024*1024 {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "File too large (max 1MB)"})
			return
		}
		
		content, err := os.ReadFile(path)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "ok",
				"path":    path,
				"content": string(content),
			})
		}
	}))
	
	// Editor page
	r.HandleFunc("/editor", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/editor.html")
	}))
	
	// Download file
	r.HandleFunc("/api/files/download", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if path == "" {
			http.Error(w, "Path required", http.StatusBadRequest)
			return
		}
		
		info, err := os.Stat(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		
		if info.IsDir() {
			http.Error(w, "Cannot download directory", http.StatusBadRequest)
			return
		}
		
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(path)))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, path)
	}))
	
	// Terminal page and WebSocket
	r.HandleFunc("/terminal", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/terminal.html")
	}))
	r.HandleFunc("/ws/terminal", authMiddleware(terminalHandler))
	
	port := ":8090"
	fmt.Printf("🚀 SysMonitor with Auth0 running on http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, r))
}
