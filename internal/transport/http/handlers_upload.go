package http

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// 用于生成用户目录名的安全字符（仅保留字母数字、下划线、横线、点）
var safeUsernameRe = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

// UploadHandler 上传静态资源：multipart form 字段 fileName、file；通过 token 鉴权，保存至 uploads/<用户名>/<文件名>
// POST /api/v1/auth/upload，Content-Type: multipart/form-data
func (h *Handler) UploadHandler(w http.ResponseWriter, r *http.Request) {
	token := getTokenFromRequest(r)
	if token == "" {
		writeError(w, "UNAUTHORIZED", "Missing or invalid token", http.StatusUnauthorized, "")
		return
	}
	user, err := h.AuthService.Validate(r.Context(), token)
	if err != nil {
		writeError(w, "INVALID_TOKEN", "Token validation failed", http.StatusUnauthorized, "")
		return
	}
	const maxFormMem = 10 << 20 // 10MB
	if err := r.ParseMultipartForm(maxFormMem); err != nil {
		writeError(w, "INVALID_REQUEST", "Invalid multipart form", http.StatusBadRequest, "")
		return
	}
	fileName := strings.TrimSpace(r.FormValue("fileName"))
	if fileName == "" {
		writeError(w, "INVALID_REQUEST", "fileName is required", http.StatusBadRequest, "")
		return
	}
	fileName = filepath.Base(fileName)
	if fileName == "" || fileName == "." || strings.Contains(fileName, "..") {
		writeError(w, "INVALID_REQUEST", "Invalid fileName", http.StatusBadRequest, "")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, "INVALID_REQUEST", "file is required", http.StatusBadRequest, "")
		return
	}
	defer file.Close()
	safeUsername := safeUsernameRe.ReplaceAllString(user.Username, "_")
	if safeUsername == "" {
		safeUsername = fmt.Sprintf("user_%d", user.ID)
	}
	dir := filepath.Join("uploads", safeUsername)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[AUTH] upload mkdir %s: %v", dir, err)
		writeError(w, "INTERNAL_ERROR", "Failed to create upload directory", http.StatusInternalServerError, "")
		return
	}
	dstPath := filepath.Join(dir, fileName)
	dst, err := os.Create(dstPath)
	if err != nil {
		log.Printf("[AUTH] upload create file %s: %v", dstPath, err)
		writeError(w, "INTERNAL_ERROR", "Failed to save file", http.StatusInternalServerError, "")
		return
	}
	defer dst.Close()
	if _, err := io.Copy(dst, file); err != nil {
		_ = os.Remove(dstPath)
		writeError(w, "INTERNAL_ERROR", "Failed to write file", http.StatusInternalServerError, "")
		return
	}
	relativePath := filepath.Join("uploads", safeUsername, fileName)
	if filepath.Separator == '\\' {
		relativePath = strings.ReplaceAll(relativePath, "\\", "/")
	}
	// 资源访问路径：相对路径 /static/... 与完整 URL（供客户端直接使用）
	staticRoute := "/static/" + relativePath
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if s := r.Header.Get("X-Forwarded-Proto"); s != "" {
		scheme = s
	}
	accessURL := scheme + "://" + r.Host + staticRoute
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"path":       relativePath,
		"route":      staticRoute,
		"access_url": accessURL,
	})
}
