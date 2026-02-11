# Kế hoạch: Terminal Tab cho SysMonitor

## 🎯 Mục tiêu
Thêm tab Terminal để điều khiển VPS trực tiếp từ browser, giống như SSH client.

## 🏗️ Kiến trúc

```
Browser <--WebSocket--> Go Backend <--PTY--> Shell (bash/zsh)
```

### Components:
1. **Frontend**: Xterm.js (terminal emulator in browser)
2. **Backend**: WebSocket + PTY (pseudo-terminal)
3. **Shell**: Bash/Zsh chạy trên VPS

## 📦 Tech Stack

| Component | Library | Purpose |
|-----------|---------|---------|
| Frontend | xterm.js | Terminal UI trong browser |
| Frontend | xterm-addon-fit | Auto-resize terminal |
| Frontend | xterm-addon-web-links | Clickable links |
| Backend | gorilla/websocket | WebSocket connection |
| Backend | creack/pty | PTY (pseudo-terminal) |

## 🛠️ Implementation Steps

### Bước 1: Cài thư viện Backend (5 phút)

```bash
go get github.com/creack/pty
go get github.com/gorilla/websocket
```

### Bước 2: Tạo WebSocket Handler (20 phút)

```go
// terminal.go
package main

import (
    "github.com/creack/pty"
    "github.com/gorilla/websocket"
    "os"
    "os/exec"
    "sync"
)

type Terminal struct {
    pty    *os.File
    cmd    *exec.Cmd
    conn   *websocket.Conn
    mu     sync.Mutex
}

func handleTerminal(w http.ResponseWriter, r *http.Request) {
    // Upgrade HTTP to WebSocket
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    defer conn.Close()
    
    // Start bash shell with PTY
    cmd := exec.Command("/bin/bash", "-l")
    cmd.Env = os.Environ()
    
    ptyFile, err := pty.Start(cmd)
    if err != nil {
        conn.WriteMessage(websocket.TextMessage, []byte("Failed to start terminal"))
        return
    }
    defer ptyFile.Close()
    
    // Goroutine: Read from PTY, write to WebSocket
    go func() {
        buf := make([]byte, 1024)
        for {
            n, err := ptyFile.Read(buf)
            if err != nil {
                return
            }
            conn.WriteMessage(websocket.BinaryMessage, buf[:n])
        }
    }()
    
    // Read from WebSocket, write to PTY
    for {
        _, msg, err := conn.ReadMessage()
        if err != nil {
            break
        }
        ptyFile.Write(msg)
    }
    
    cmd.Process.Kill()
}
```

### Bước 3: Frontend - Xterm.js (30 phút)

```html
<!-- Terminal Tab -->
<div class="tab-pane" id="terminal">
    <div id="terminal-container" style="height: 60vh;"></div>
</div>

<script>
// Load xterm.js
import { Terminal } from 'https://cdn.skypack.dev/xterm';
import { FitAddon } from 'https://cdn.skypack.dev/xterm-addon-fit';

const term = new Terminal({
    cursorBlink: true,
    fontSize: 14,
    fontFamily: 'Monaco, "Courier New", monospace',
    theme: {
        background: '#0d1117',
        foreground: '#c9d1d9',
        cursor: '#58a6ff',
        selection: '#264f78'
    }
});

const fitAddon = new FitAddon();
term.loadAddon(fitAddon);

// Open terminal in container
term.open(document.getElementById('terminal-container'));
fitAddon.fit();

// Connect WebSocket
const ws = new WebSocket('wss://ai.nhangiaz.com/ws/terminal');
ws.binaryType = 'arraybuffer';

// Receive data from server
ws.onmessage = (event) => {
    const data = new Uint8Array(event.data);
    term.write(data);
};

// Send data to server
term.onData((data) => {
    ws.send(data);
});

// Resize
window.addEventListener('resize', () => {
    fitAddon.fit();
});
</script>
```

### Bước 4: Route và Auth (10 phút)

```go
// Add routes
r.HandleFunc("/ws/terminal", authMiddleware(terminalHandler))
r.HandleFunc("/terminal", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "templates/terminal.html")
}))
```

### Bước 5: UI Tab (5 phút)

Thêm vào bottom navigation:
```html
<a href="#" class="nav-item" data-tab="terminal">
    <i class="bi bi-terminal"></i>Terminal
</a>
```

## 🎨 Terminal Features

| Feature | Status |
|---------|--------|
| Full color support | ✅ |
| Unicode/UTF-8 | ✅ |
| Mouse support | ✅ |
| Copy/Paste | ✅ Ctrl+Shift+C/V |
| Resize | ✅ Auto-fit |
| Scrollback | ✅ 1000 lines |
| Command history | ✅ (bash built-in) |
| Tab completion | ✅ |

## 🔒 Security Considerations

1. **Authentication**: WebSocket cũng cần auth (check session)
2. **Rate limiting**: Giới hạn số lệnh/thờI gian
3. **Command logging**: Log các command đã chạy (audit)
4. **Timeout**: Auto disconnect sau 30 phút idle
5. **Restricted commands**: Có thể chặn rm -rf /, v.v. (optional)

## 📱 Mobile Support

- Virtual keyboard handling
- Touch scrolling
- Pinch to zoom (font size)
- Special keys toolbar (Ctrl, Tab, Escape)

## ⏱️ Timeline

| Bước | ThờI gian |
|------|-----------|
| 1. Install libs | 5 phút |
| 2. Backend WebSocket | 30 phút |
| 3. Frontend xterm.js | 30 phút |
| 4. Testing | 20 phút |
| **Tổng** | **~1.5 giờ** |

## 🚀 Next Steps

Anh muốn mình:
1. **Implement ngay** terminal?
2. **Làm font size trước**, terminal sau?
3. **Chỉ plan** để anh tự làm?

## 📝 Font Size Customization (Nhanh - 10 phút)

Thêm vào editor modal:
```javascript
// Font size controls
function changeFontSize(size) {
    if (codeEditor) {
        codeEditor.getWrapperElement().style.fontSize = size + 'px';
        codeEditor.refresh();
    }
}

// UI: [A-] [14px] [A+]
```

Ready! 🖥️✨
