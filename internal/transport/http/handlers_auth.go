package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"monai-auth/internal/domain"
)

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

	// 解析 token 获取用户信息，两个分支均需要 userID
	user, err := h.AuthService.Validate(r.Context(), token)
	if err != nil {
		writeError(w, "INTERNAL_ERROR", "Server error", http.StatusInternalServerError, "")
		return
	}

	// SSO 授权码流程：带 server_state 时生成授权码并返回子应用回调 URL（不 302，不写 Cookie）
	if req.ServerState != "" && h.StateStore != nil && h.CodeStore != nil {
		if redirectURI := h.buildSSOredirectURI(r.Context(), user.ID, req.ServerState); redirectURI != "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"redirect_url": redirectURI})
			return
		}
	}

	// 非 SSO：下发双 Cookie 并返回 ok
	h.setTokenCookies(w, r.Context(), token, user.ID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// LogoutHandler 处理登出：吊销 refresh token，清除两个 Cookie
func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// 吊销 refresh token（从数据库删除）
	if c, err := r.Cookie(refreshTokenCookieName); err == nil && c.Value != "" {
		_ = h.AuthService.RevokeRefreshToken(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    "",
		Path:     refreshTokenCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ValidateHandler 处理 /validate 请求 (用于其他服务验证JWT)
func (h *Handler) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	token := getTokenFromRequest(r)
	if token == "" {
		writeError(w, "UNAUTHORIZED", "Missing or invalid token", http.StatusUnauthorized, "")
		return
	}
	user, err := h.AuthService.Validate(r.Context(), token)
	if err != nil {
		writeError(w, "INVALID_TOKEN", "Token validation failed", http.StatusUnauthorized,
			"validate failed reason=invalid_token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(UserInfoResponse{
		ID:    user.ID,
		Email: user.Email,
	})
}

// MeHandler 获取当前登录用户基本信息
// GET /api/v1/auth/me，鉴权方式同 validate（Cookie 或 Authorization: Bearer）
func (h *Handler) MeHandler(w http.ResponseWriter, r *http.Request) {
	token := getTokenFromRequest(r)
	if token == "" {
		writeError(w, "UNAUTHORIZED", "Missing or invalid token", http.StatusUnauthorized, "")
		return
	}
	user, err := h.AuthService.Validate(r.Context(), token)
	if err != nil {
		writeError(w, "INVALID_TOKEN", "Token validation failed", http.StatusUnauthorized,
			"me failed reason=invalid_token")
		return
	}
	createdAt := ""
	if !user.CreatedAt.IsZero() {
		createdAt = user.CreatedAt.Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(CurrentUserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: createdAt,
	})
}

// RefreshHandler 用 refresh_token Cookie 换取新的 access_token 和 refresh_token（Token 轮换）
// POST /api/v1/auth/refresh
func (h *Handler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(refreshTokenCookieName)
	if err != nil || c.Value == "" {
		writeError(w, "UNAUTHORIZED", "Missing refresh token", http.StatusUnauthorized, "")
		return
	}
	refreshExpiry := time.Duration(h.RefreshTokenExpireSec) * time.Second
	newAccessToken, newRefreshToken, err := h.AuthService.RefreshAccessToken(r.Context(), c.Value, refreshExpiry)
	if err != nil {
		writeError(w, "INVALID_TOKEN", "Invalid or expired refresh token", http.StatusUnauthorized,
			"refresh failed: "+err.Error())
		return
	}
	h.writeTokenCookies(w, newAccessToken, newRefreshToken)
	w.WriteHeader(http.StatusNoContent)
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

// authTokenCookieName 与登录时设置的 Cookie 名称一致
const authTokenCookieName = "auth_token"

// refreshTokenCookieName refresh token Cookie 名
const refreshTokenCookieName = "refresh_token"

// refreshTokenCookiePath 限制 refresh token Cookie 只在刷新接口携带，缩小暴露面
const refreshTokenCookiePath = "/api/v1/auth/refresh"

// getTokenFromRequest 从 Cookie 或 Authorization 头获取 token
func getTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(authTokenCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

