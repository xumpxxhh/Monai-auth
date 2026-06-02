package http

import (
	"encoding/json"
	"log"
	"net/http"

	"monai-auth/internal/auth"
)

// TokenResponse 授权码兑换 token 的响应（OAuth2 风格）
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	UserID      int64  `json:"user_id"`
}

// Client 子应用（客户端）配置，用于授权码流程
type Client struct {
	ClientID            string
	ClientSecret        string
	AllowedRedirectURIs []string
}

// Handler 结构体包含对业务服务的依赖
type Handler struct {
	AuthService           auth.Service
	StateStore            auth.StateStore
	CodeStore             auth.CodeStore
	LoginPagePath         string
	AuthBaseURL           string // 认证中心对外 base URL，用于拼完整登录页地址
	AllowedRedirectURIs   []string
	Clients               []Client
	AccessTokenExpireSec  int
	RefreshTokenExpireSec int
}

// HandlerOpts 可选配置
type HandlerOpts struct {
	StateStore            auth.StateStore
	CodeStore             auth.CodeStore
	LoginPagePath         string
	AuthBaseURL           string
	AllowedRedirectURIs   []string
	Clients               []Client
	AccessTokenExpireSec  int
	RefreshTokenExpireSec int
}

// UserInfoResponse 验证接口返回的用户信息
type UserInfoResponse struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

// CurrentUserResponse 当前用户基本信息（/me）
type CurrentUserResponse struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

// ErrorResponse 统一错误响应格式
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHandler(authService auth.Service, opts *HandlerOpts) *Handler {
	h := &Handler{AuthService: authService}
	if opts != nil {
		h.StateStore = opts.StateStore
		h.CodeStore = opts.CodeStore
		if opts.LoginPagePath != "" {
			h.LoginPagePath = opts.LoginPagePath
		} else {
			h.LoginPagePath = "/auth"
		}
		h.AuthBaseURL = opts.AuthBaseURL
		h.AllowedRedirectURIs = opts.AllowedRedirectURIs
		h.Clients = opts.Clients
		h.AccessTokenExpireSec = opts.AccessTokenExpireSec
		if h.AccessTokenExpireSec <= 0 {
			h.AccessTokenExpireSec = 2 * 3600 // 2小时
		}
		h.RefreshTokenExpireSec = opts.RefreshTokenExpireSec
		if h.RefreshTokenExpireSec <= 0 {
			h.RefreshTokenExpireSec = 7 * 24 * 3600 // 7天
		}
	} else {
		h.LoginPagePath = "/auth"
		h.AccessTokenExpireSec = 2 * 3600
		h.RefreshTokenExpireSec = 7 * 24 * 3600
	}
	return h
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
