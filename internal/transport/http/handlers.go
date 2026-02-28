package http

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"monai-auth/internal/auth"
	"monai-auth/internal/domain"
)

// Handler 结构体包含对业务服务的依赖
type Handler struct {
	AuthService auth.Service
}

// UserInfoResponse 验证接口返回的用户信息
type UserInfoResponse struct {
	ID   int64  `json:"id"`
	Role string `json:"role"`
}

// ErrorResponse 统一错误响应格式
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHandler(authService auth.Service) *Handler {
	return &Handler{AuthService: authService}
}

// writeError 写入统一格式的 JSON 错误响应并记录日志
func writeError(w http.ResponseWriter, code string, message string, status int, logMsg string) {
	if logMsg != "" {
		log.Printf("[AUTH] %s", logMsg)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: code, Message: message})
}

// LoginHandler 处理 /login 请求
func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "INVALID_REQUEST", "Invalid request body", http.StatusBadRequest, "")
		return
	}

	token, err := h.AuthService.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			writeError(w, "INVALID_CREDENTIALS", "Invalid credentials", http.StatusUnauthorized,
				"login failed email="+req.Email+" reason=invalid_credentials")
			return
		}
		writeError(w, "INTERNAL_ERROR", "Server error", http.StatusInternalServerError,
			"login failed email="+req.Email+" reason=internal")
		return
	}

	// 将 token 写入 HttpOnly Cookie，避免在前端 JS 中直接访问
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		// 本地开发通常是 http，如果有 https 环境建议将 Secure 设为 true
		// Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// authTokenCookieName 与登录时设置的 Cookie 名称一致
const authTokenCookieName = "auth_token"

// LogoutHandler 处理登出：清除服务端下发的 auth_token Cookie，客户端无需再持有 token
func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ValidateHandler 处理 /validate 请求 (用于其他服务验证JWT)
func (h *Handler) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	var token string

	// 优先从 HttpOnly Cookie 中读取 token
	if c, err := r.Cookie(authTokenCookieName); err == nil && c.Value != "" {
		token = c.Value
	} else {
		// 兼容旧调用方式：Authorization: Bearer <token>
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, "UNAUTHORIZED", "Missing or invalid token", http.StatusUnauthorized, "")
			return
		}
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	user, err := h.AuthService.Validate(r.Context(), token)
	if err != nil {
		writeError(w, "INVALID_TOKEN", "Token validation failed", http.StatusUnauthorized,
			"validate failed reason=invalid_token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(UserInfoResponse{
		ID:   user.ID,
		Role: user.Role,
	})
}

// RegisterHandler 处理注册请求
func (h *Handler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "INVALID_REQUEST", "Invalid request body", http.StatusBadRequest, "")
		return
	}
	_, err := h.AuthService.Register(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrEmailExists), errors.Is(err, domain.ErrUserExists):
			writeError(w, "EMAIL_EXISTS", "Email already registered", http.StatusConflict,
				"register failed email="+req.Email+" reason=email_exists")
			return
		case errors.Is(err, domain.ErrInvalidEmail):
			writeError(w, "INVALID_EMAIL", "Invalid email format", http.StatusBadRequest, "")
			return
		case errors.Is(err, domain.ErrPasswordTooShort):
			writeError(w, "PASSWORD_TOO_SHORT", "Password too short", http.StatusBadRequest, "")
			return
		default:
			writeError(w, "INTERNAL_ERROR", "User registration failed", http.StatusInternalServerError,
				"register failed email="+req.Email+" reason=internal")
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
}
