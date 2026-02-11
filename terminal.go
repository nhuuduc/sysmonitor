package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins (protected by auth)
	},
}

type TerminalSession struct {
	ptyFile *os.File
	cmd     *exec.Cmd
	conn    *websocket.Conn
	mu      sync.Mutex
}

func terminalHandler(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("Terminal session started from %s", r.RemoteAddr)

	// Start bash shell with PTY
	cmd := exec.Command("/bin/bash", "-l")
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"LANG=en_US.UTF-8",
		"LC_ALL=en_US.UTF-8",
		"LC_CTYPE=UTF-8",
	)

	ptyFile, err := pty.Start(cmd)
	if err != nil {
		log.Printf("Failed to start PTY: %v", err)
		conn.WriteMessage(websocket.TextMessage, []byte("Failed to start terminal: "+err.Error()))
		return
	}
	defer ptyFile.Close()

	// Set initial size
	pty.Setsize(ptyFile, &pty.Winsize{Rows: 24, Cols: 80})

	session := &TerminalSession{
		ptyFile: ptyFile,
		cmd:     cmd,
		conn:    conn,
	}

	// Goroutine: Read from PTY, write to WebSocket
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptyFile.Read(buf)
			if err != nil {
				return
			}
			session.mu.Lock()
			err = conn.WriteMessage(websocket.BinaryMessage, buf[:n])
			session.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()

	// Read from WebSocket, write to PTY
	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		if messageType == websocket.TextMessage {
			// Check for resize message
			if len(msg) > 0 && msg[0] == '{' {
				// JSON message for resize
				var resizeMsg struct {
					Cols int `json:"cols"`
					Rows int `json:"rows"`
				}
				if err := json.Unmarshal(msg, &resizeMsg); err == nil && resizeMsg.Cols > 0 && resizeMsg.Rows > 0 {
					pty.Setsize(ptyFile, &pty.Winsize{
						Rows: uint16(resizeMsg.Rows),
						Cols: uint16(resizeMsg.Cols),
					})
					continue
				}
			}
		}

		// Write input to PTY
		ptyFile.Write(msg)
	}

	// Cleanup
	cmd.Process.Kill()
	cmd.Wait()
	log.Printf("Terminal session ended from %s", r.RemoteAddr)
}
