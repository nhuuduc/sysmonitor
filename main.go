package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// System structs
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

type ProcessInfo struct {
	PID     int32   `json:"pid"`
	Name    string  `json:"name"`
	CPU     float64 `json:"cpu"`
	Memory  float32 `json:"memory"`
	Status  string  `json:"status"`
	User    string  `json:"user"`
	Command string  `json:"command"`
}

type PortInfo struct {
	Protocol string `json:"protocol"`
	LocalIP  string `json:"local_ip"`
	Port     uint32 `json:"port"`
	PID      int32  `json:"pid"`
	Process  string `json:"process"`
	Status   string `json:"status"`
}

type NetworkStats struct {
	Interface   string `json:"interface"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
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

// Auth0 Configuration
var (
	auth0Domain       = getEnv("AUTH0_DOMAIN", "")
	auth0ClientID     = getEnv("AUTH0_CLIENT_ID", "")
	auth0ClientSecret = getEnv("AUTH0_CLIENT_SECRET", "")
	auth0CallbackURL  = getEnv("AUTH0_CALLBACK_URL", "https://ai.nhangiaz.com/callback")
	
	store = sessions.NewCookieStore([]byte(getEnv("SESSION_SECRET", "default-secret-change-me")))
	
	oauthConfig *oauth2.Config
)

type UserInfo struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	Picture   string `json:"picture"`
	Sub       string `json:"sub"`
}

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   true, // HTTPS only
		SameSite: http.SameSiteStrictMode,
	}
	
	// Setup OAuth2 config for Auth0
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

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// Generate random state for CSRF protection
func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Auth Handlers
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
	
	// Verify state
	session, _ := store.Get(r, "auth-session")
	expectedState, ok := session.Values["state"].(string)
	if !ok || expectedState == "" {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	
	state := r.URL.Query().Get("state")
	if state != expectedState {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}
	
	// Exchange code for token
	code := r.URL.Query().Get("code")
	if code == "" {
		error := r.URL.Query().Get("error")
		errorDescription := r.URL.Query().Get("error_description")
		showErrorPage(w, error, errorDescription)
		return
	}
	
	token, err := oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		showErrorPage(w, "Token Exchange Failed", err.Error())
		return
	}
	
	// Get user info from Auth0
	userInfo, err := getUserInfo(token.AccessToken)
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Whitelist check - only allow specific email
	allowedEmail := "nhuuduc166@gmail.com"
	if userInfo.Email != allowedEmail {
		showErrorPage(w, "Access Denied", "Your email ("+userInfo.Email+") is not authorized to access this system.")
		return
	}
	
	// Set session
	session.Values["authenticated"] = true
	session.Values["user_email"] = userInfo.Email
	session.Values["user_name"] = userInfo.Name
	session.Values["user_picture"] = userInfo.Picture
	session.Values["user_sub"] = userInfo.Sub
	delete(session.Values, "state") // Clear state
	session.Save(r, w)
	
	log.Printf("✅ User logged in: %s (%s)", userInfo.Email, userInfo.Name)
	
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/userinfo", auth0Domain), nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+accessToken)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed: %d", resp.StatusCode)
	}
	
	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}
	
	return &userInfo, nil
}

func showErrorPage(w http.ResponseWriter, title, message string) {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - SysMonitor</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
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
        .error-box {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            width: 320px;
        }
        .error-icon { font-size: 48px; margin-bottom: 20px; }
        h1 { margin-bottom: 10px; color: #f85149; font-size: 1.2rem; }
        p { color: #8b949e; margin-bottom: 30px; font-size: 14px; word-break: break-word; }
        .btn-back {
            display: block;
            width: 100%;
            padding: 12px;
            background: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            transition: background 0.2s;
        }
        .btn-back:hover { background: #30363d; }
    </style>
</head>
<body>
    <div class="error-box">
        <div class="error-icon">⚠️</div>
        <h1>` + title + `</h1>
        <p>` + message + `</p>
        <a href="/login" class="btn-back">← Back to Login</a>
    </div>
</body>
</html>`
	w.Write([]byte(tmpl))
}
	session, _ := store.Get(r, "auth-session")
	session.Values["authenticated"] = false
	delete(session.Values, "user_email")
	delete(session.Values, "user_name")
	delete(session.Values, "user_picture")
	session.Save(r, w)
	
	// Redirect to Auth0 logout
	logoutURL := fmt.Sprintf(
		"https://%s/v2/logout?client_id=%s&returnTo=%s",
		auth0Domain,
		auth0ClientID,
		url.QueryEscape("https://ai.nhangiaz.com/login"),
	)
	
	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

// Auth middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if not configured
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

func getProcesses() []ProcessInfo {
	procs, _ := process.Processes()
	var result []ProcessInfo

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

		result = append(result, ProcessInfo{
			PID:     p.Pid,
			Name:    name,
			CPU:     cpuPct,
			Memory:  memPct,
			Status:  strings.Join(status, ","),
			User:    user,
			Command: cmdline,
		})
	}
	return result
}

func getPorts() []PortInfo {
	connections, _ := net.Connections("all")
	var result []PortInfo

	for _, conn := range connections {
		if conn.Status == "LISTEN" {
			procName := ""
			if conn.Pid > 0 {
				p, err := process.NewProcess(conn.Pid)
				if err == nil {
					procName, _ = p.Name()
				}
			}

			result = append(result, PortInfo{
				Protocol: typeToProtocol(conn.Type),
				LocalIP:  conn.Laddr.IP,
				Port:     conn.Laddr.Port,
				PID:      conn.Pid,
				Process:  procName,
				Status:   conn.Status,
			})
		}
	}
	return result
}

func typeToProtocol(t uint32) string {
	switch t {
	case syscall.SOCK_STREAM:
		return "TCP"
	case syscall.SOCK_DGRAM:
		return "UDP"
	default:
		return "Unknown"
	}
}

func getNetworkStats() []NetworkStats {
	interfaces, _ := net.IOCounters(true)
	var result []NetworkStats

	for _, iface := range interfaces {
		if iface.BytesSent > 0 || iface.BytesRecv > 0 {
			result = append(result, NetworkStats{
				Interface:   iface.Name,
				BytesSent:   iface.BytesSent,
				BytesRecv:   iface.BytesRecv,
				PacketsSent: iface.PacketsSent,
				PacketsRecv: iface.PacketsRecv,
			})
		}
	}
	return result
}

// File Management Functions
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

		sizeStr := formatSize(info.Size())
		files = append(files, FileInfo{
			Name:    entry.Name(),
			Path:    filepath.Join(dir, entry.Name()),
			Size:    info.Size(),
			SizeStr: sizeStr,
			IsDir:   entry.IsDir(),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			Mode:    info.Mode().String(),
		})
	}
	return files, nil
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

func deleteFile(path string) error {
	return os.Remove(path)
}

func deleteDirectory(path string) error {
	return os.RemoveAll(path)
}

func readFileContent(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func uploadFile(destPath string, src io.Reader) error {
	file, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, src)
	return err
}

func killProcess(pid int) error {
	cmd := exec.Command("kill", "-9", strconv.Itoa(pid))
	return cmd.Run()
}

// Handlers
			"message": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"dir":    dir,
		"files":  files,
	})
}

func apiDeleteFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]
	path, _ = url.QueryUnescape(path)

	w.Header().Set("Content-Type", "application/json")

	if path == "" {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Path required"})
		return
	}
	
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	info, err := os.Stat(path)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
		return
	}

	if info.IsDir() {
		err = deleteDirectory(path)
	} else {
		err = deleteFile(path)
	}

	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
	} else {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Deleted successfully"})
	}
}

func apiFileContentHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")

	w.Header().Set("Content-Type", "application/json")

	if path == "" {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Path required"})
		return
	}

	content, err := readFileContent(path)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"path":    path,
		"content": content,
	})
}

func apiUploadHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20) // 10 MB max

	file, handler, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Failed to get file"})
		return
	}
	defer file.Close()

	dir := r.FormValue("dir")
	if dir == "" {
		dir = "/tmp"
	}

	destPath := filepath.Join(dir, handler.Filename)
	err = uploadFile(destPath, file)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
	} else {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Uploaded successfully", "path": destPath})
	}
}

func main() {
	r := mux.NewRouter()

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Auth routes (public)
	r.HandleFunc("/login", loginPageHandler)
	r.HandleFunc("/auth/login", loginHandler)
	r.HandleFunc("/callback", callbackHandler)
	r.HandleFunc("/logout", logoutHandler)

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
	if oauthConfig == nil {
		fmt.Println("⚠️  Warning: OAuth not configured. Set AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET")
	}
	log.Fatal(http.ListenAndServe(port, r))
}
