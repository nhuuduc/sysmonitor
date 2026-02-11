# Kế hoạch: File Editor cho SysMonitor

## 🎯 Mục tiêu
Thêm chức năng chỉnh sửa file trực tiếp trên browser với UI đẹp, hỗ trợ syntax highlighting cho các định dạng phổ biến.

## 📋 Các định dạng file hỗ trợ

| Định dạng | Extension | Syntax Highlight | Đặc biệt |
|-----------|-----------|------------------|----------|
| JSON | .json | ✅ | Format/Validate |
| Environment | .env | ✅ | Key-value pairs |
| Text | .txt | ⚪ | Plain text |
| XML | .xml | ✅ | Tree view (optional) |
| YAML | .yml, .yaml | ✅ | Indentation |
| Markdown | .md | ✅ | Preview mode |
| JavaScript | .js | ✅ | - |
| Go | .go | ✅ | - |
| Python | .py | ✅ | - |
| SQL | .sql | ✅ | - |
| HTML | .html | ✅ | - |
| CSS | .css | ✅ | - |
| Nginx | .conf | ✅ | - |
| Config | .ini, .toml | ✅ | - |

## 🏗️ Kiến trúc

### 1. Frontend - Code Editor

**Thư viện đề xuất:** Monaco Editor (VS Code editor)
- Pros: Giống VS Code, syntax highlighting tốt, autocomplete
- Cons: Nặng (~2MB)

**Thư viện nhẹ hơn:** CodeMirror 6
- Pros: Nhẹ, dễ tích hợp, nhiều theme
- Cons: Ít feature hơn Monaco

**Lựa chọn:** CodeMirror 6 (vì nhẹ, phù hợp mobile)

### 2. API Endpoints

```
GET  /api/files/content?path=/path/to/file    - Đọc file
POST /api/files/save                          - Lưu file
```

### 3. UI Components

```
┌─────────────────────────────────────┐
│  🔙 Back    /etc/nginx/nginx.conf   │  ← Header với breadcrumb
├─────────────────────────────────────┤
│                                     │
│  ┌─────────────────────────────┐   │
│  │  1  │  server {            │   │  ← Code editor
│  │  2  │      listen 80;      │   │     (line numbers + syntax)
│  │  3  │      server_name...  │   │
│  │     │  }                   │   │
│  └─────────────────────────────┘   │
│                                     │
├─────────────────────────────────────┤
│  [💾 Save]  [↩️ Undo]  Status: OK  │  ← Action bar
└─────────────────────────────────────┘
```

## 🛠️ Implementation Steps

### Bước 1: Thêm CodeMirror vào frontend (30 phút)

```html
<!-- templates/editor.html -->
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.js"></script>
    
    <!-- Modes -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/javascript/javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/xml/xml.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/yaml/yaml.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/shell/shell.min.js"></script>
    
    <!-- Theme -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/theme/dracula.min.css">
</head>
<body>
    <textarea id="editor"></textarea>
    <script>
        const editor = CodeMirror.fromTextArea(document.getElementById('editor'), {
            lineNumbers: true,
            mode: 'javascript',
            theme: 'dracula',
            lineWrapping: true,
            tabSize: 2
        });
    </script>
</body>
</html>
```

### Bước 2: API Backend (20 phút)

```go
// main.go - Thêm endpoints

// Đọc file
r.HandleFunc("/api/files/read", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Query().Get("path")
    content, err := os.ReadFile(path)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
        return
    }
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status": "ok",
        "path": path,
        "content": string(content),
    })
}))

// Lưu file
r.HandleFunc("/api/files/save", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Path    string `json:"path"`
        Content string `json:"content"`
    }
    json.NewDecoder(r.Body).Decode(&req)
    
    err := os.WriteFile(req.Path, []byte(req.Content), 0644)
    if err != nil {
        json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
        return
    }
    json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "File saved"})
})).Methods("POST")
```

### Bước 3: File Manager UI - Thêm nút Edit (15 phút)

```javascript
// Trong file manager, thêm nút Edit
function renderFileItem(file) {
    const isEditable = isEditableFile(file.name);
    return `
        <div class="file-item">
            <span class="file-name">${file.name}</span>
            ${isEditable ? 
                `<button onclick="editFile('${file.path}')">✏️ Edit</button>` : 
                ''}
            <button onclick="deleteFile('${file.path}')">🗑️</button>
        </div>
    `;
}

function isEditableFile(filename) {
    const editableExts = ['.json', '.env', '.txt', '.xml', '.yml', '.yaml', 
                          '.md', '.js', '.go', '.py', '.sql', '.html', '.css', 
                          '.conf', '.ini', '.toml', '.sh'];
    return editableExts.some(ext => filename.toLowerCase().endsWith(ext));
}

function editFile(path) {
    window.location.href = `/editor?path=${encodeURIComponent(path)}`;
}
```

### Bước 4: Trang Editor (30 phút)

Tạo route `/editor` hiển thị CodeMirror với:
- Breadcrumb navigation
- Editor với syntax highlighting theo file type
- Save/Cancel buttons
- Status bar (line:col, file size)

### Bước 5: Auto-detect language mode (10 phút)

```javascript
function getLanguageMode(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const modes = {
        'js': 'javascript',
        'json': 'javascript',
        'go': 'go',
        'py': 'python',
        'sql': 'sql',
        'xml': 'xml',
        'html': 'xml',
        'yml': 'yaml',
        'yaml': 'yaml',
        'md': 'markdown',
        'sh': 'shell',
        'env': 'shell',
        'conf': 'nginx',
        'ini': 'properties',
        'toml': 'toml'
    };
    return modes[ext] || 'text';
}
```

## 🎨 UI/UX Features

### Dark Theme (giống VS Code)
- Background: #1e1e1e
- Text: #d4d4d4
- Line numbers: #858585
- Selection: #264f78
- Cursor: #aeafad

### Features
- ✅ Line numbers
- ✅ Syntax highlighting
- ✅ Auto-indentation
- ✅ Line wrapping (toggle)
- ✅ Search/Replace (Ctrl+F)
- ✅ Undo/Redo (Ctrl+Z/Y)
- ✅ Auto-save (optional)
- ✅ File change detection (warning if modified)

## 🔒 Security Considerations

1. **Path validation**: Chỉ cho phép edit trong /root, /etc, /opt, /var
2. **Backup**: Tạo .bak file trước khi save
3. **Size limit**: Giới hạn file size (max 1MB)
4. **Permission check**: Kiểm tra write permission trước khi save

## 📱 Mobile Support

- Editor responsive
- Toolbar buttons lớn hơn trên mobile
- Hide line numbers trên mobile nhỏ
- Virtual keyboard handling

## ⏱️ Timeline

| Bước | ThờI gian |
|------|-----------|
| 1. CodeMirror integration | 30 phút |
| 2. Backend APIs | 20 phút |
| 3. UI Components | 30 phút |
| 4. Testing | 20 phút |
| **Tổng** | **~1.5 giờ** |

## 🚀 Next Steps

Anh muốn mình:
1. **Implement ngay** chức năng này?
2. **Chỉ làm plan** trước?
3. **Ưu tiên** file type nào trước?

Ready to code! 💻✨
