package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"monai-auth/internal/auth"
	"monai-auth/internal/domain"
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
	ID   int64  `json:"id"`
	Role string `json:"role"`
}

// CurrentUserResponse 当前用户基本信息（/me）
type CurrentUserResponse struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

// ErrorResponse 统一错误响应格式
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHandler(authService auth.Service, opts *HandlerOpts) *Handler {
	// TODO
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

// buildSSOredirectURI 从 StateStore 取回 client_id/redirect_uri，生成授权码，
// 返回带 code 的完整回调 URL；任意步骤失败时返回空字符串。
func (h *Handler) buildSSOredirectURI(ctx context.Context, userID int64, serverState string) string {
	clientID, redirectURI, _, ok := h.StateStore.GetAndConsume(serverState)
	if !ok || redirectURI == "" {
		return ""
	}
	code, err := h.CodeStore.Save(userID, clientID, redirectURI)
	if err != nil {
		return ""
	}
	u, err := url.Parse(redirectURI)
	if err != nil || u == nil {
		return ""
	}
	q := u.Query()
	q.Set("code", code)
	u.RawQuery = q.Encode()
	return u.String()
}

// isRedirectURIAllowed 检查 redirectURI 的 host 是否在指定客户端的 allowed_redirect_uris 白名单内。
// 仅比较 scheme+host，路径部分不参与校验，防止任意子路径绕过。
func (h *Handler) isRedirectURIAllowed(clientID, redirectURI string) bool {
	target, err := url.Parse(redirectURI)
	if err != nil || target.Host == "" {
		return false
	}
	targetOrigin := target.Scheme + "://" + target.Host
	for _, c := range h.Clients {
		if c.ClientID != clientID {
			continue
		}
		for _, allowed := range c.AllowedRedirectURIs {
			a, err := url.Parse(allowed)
			if err != nil {
				continue
			}
			if a.Scheme+"://"+a.Host == targetOrigin {
				return true
			}
		}
		// 找到了对应 client 但无匹配项，无需继续遍历
		return false
	}
	return false
}

// writeTokenCookies 将已有的 access_token 和 refresh_token 直接写入 Cookie。
// 用于 token 值已经确定的场景（如 RefreshHandler 轮换后）。
func (h *Handler) writeTokenCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   h.AccessTokenExpireSec,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookieName,
		Value:    refreshToken,
		Path:     refreshTokenCookiePath,
		MaxAge:   h.RefreshTokenExpireSec,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// setTokenCookies 签发 refresh token 后，连同 access_token 一起写入 Cookie。
// 用于登录、授权码换 token 等需要新建 session 的场景。
func (h *Handler) setTokenCookies(w http.ResponseWriter, ctx context.Context, accessToken string, userID int64) {
	refreshExpiry := time.Duration(h.RefreshTokenExpireSec) * time.Second
	rt, err := h.AuthService.IssueRefreshToken(ctx, userID, refreshExpiry)
	if err != nil {
		log.Printf("[AUTH] failed to issue refresh token for user %d: %v", userID, err)
		// refresh token 签发失败时至少保证 access_token Cookie 写入
		http.SetCookie(w, &http.Cookie{
			Name:     authTokenCookieName,
			Value:    accessToken,
			Path:     "/",
			MaxAge:   h.AccessTokenExpireSec,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		return
	}
	h.writeTokenCookies(w, accessToken, rt)
}

// authTokenCookieName 与登录时设置的 Cookie 名称一致
const authTokenCookieName = "auth_token"

// refreshTokenCookieName refresh token Cookie 名
const refreshTokenCookieName = "refresh_token"

// refreshTokenCookiePath 限制 refresh token Cookie 只在刷新接口携带，缩小暴露面
const refreshTokenCookiePath = "/api/v1/auth/refresh"

// RequestLoginResponse 请求登录接口返回的登录页地址
type RequestLoginResponse struct {
	LoginURL string `json:"login_url"`
}

// SSORequestLoginHandler 子应用请求登录：接收 client_id、redirect_uri，服务端生成 state 并返回登录页完整 URL（不 302）
// GET /api/v1/auth/request-login?client_id=xxx&redirect_uri=<url-encoded>
func (h *Handler) SSORequestLoginHandler(w http.ResponseWriter, r *http.Request) {
	if h.StateStore == nil {
		writeError(w, "INTERNAL_ERROR", "SSO not configured", http.StatusInternalServerError, "")
		return
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	redirectURI := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
	if clientID == "" {
		writeError(w, "INVALID_REQUEST", "client_id is required", http.StatusBadRequest, "")
		return
	}
	if redirectURI == "" {
		writeError(w, "INVALID_REQUEST", "redirect_uri is required", http.StatusBadRequest, "")
		return
	}
	if !h.isRedirectURIAllowed(clientID, redirectURI) {
		writeError(w, "INVALID_REDIRECT_URI", "redirect_uri is not allowed for this client", http.StatusBadRequest,
			fmt.Sprintf("SSO redirect_uri not in allowlist: client=%s uri=%s", clientID, redirectURI))
		return
	}
	// state 由服务端生成并绑定 client_id、redirect_uri
	state, err := h.StateStore.Save(clientID, redirectURI, "")
	if err != nil {
		writeError(w, "INTERNAL_ERROR", "Failed to create state", http.StatusInternalServerError, "")
		return
	}
	base := strings.TrimSuffix(h.AuthBaseURL, "/")
	path := strings.TrimPrefix(h.LoginPagePath, "/")
	loginURL := base + "/" + path + "?client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=" + url.QueryEscape(state)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RequestLoginResponse{LoginURL: loginURL})
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
		ID:   user.ID,
		Role: user.Role,
	})
}

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
		Role:      user.Role,
		CreatedAt: createdAt,
	})
}

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
		os.Remove(dstPath)
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

// TokenHandler 用授权码换取 access_token。
// 必须由子应用的后端（服务器）调用，不可由前端/浏览器调用。请求体中的 client_secret 由子应用后端携带，本接口仅读取并校验。
// POST /api/v1/auth/token，Body: grant_type=authorization_code&code=xxx&client_id=xxx&client_secret=xxx&redirect_uri=xxx（可选）
func (h *Handler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if h.CodeStore == nil {
		writeError(w, "INTERNAL_ERROR", "Token exchange not configured", http.StatusInternalServerError, "")
		return
	}
	// 支持 form 或 JSON（调用方为子应用后端，其请求体中携带 client_secret）
	var grantType, code, clientID, clientSecret, redirectURI string
	if r.Header.Get("Content-Type") == "application/json" {
		var body struct {
			GrantType    string `json:"grant_type"`
			Code         string `json:"code"`
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			RedirectURI  string `json:"redirect_uri"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, "INVALID_REQUEST", "Invalid request body", http.StatusBadRequest, "")
			return
		}
		grantType, code, clientID, clientSecret, redirectURI = body.GrantType, body.Code, body.ClientID, body.ClientSecret, body.RedirectURI
	} else {
		_ = r.ParseForm()
		grantType = r.FormValue("grant_type")
		code = strings.TrimSpace(r.FormValue("code"))
		clientID = strings.TrimSpace(r.FormValue("client_id"))
		clientSecret = r.FormValue("client_secret")
		redirectURI = strings.TrimSpace(r.FormValue("redirect_uri"))
	}
	if grantType != "authorization_code" {
		writeError(w, "INVALID_REQUEST", "grant_type must be authorization_code", http.StatusBadRequest, "")
		return
	}
	if code == "" || clientID == "" || clientSecret == "" {
		writeError(w, "INVALID_REQUEST", "code, client_id, client_secret are required", http.StatusBadRequest, "")
		return
	}
	var client *Client
	for i := range h.Clients {
		if h.Clients[i].ClientID == clientID {
			client = &h.Clients[i]
			break
		}
	}
	if client == nil || client.ClientSecret != clientSecret {
		writeError(w, "INVALID_CLIENT", "invalid client_id or client_secret", http.StatusUnauthorized, "")
		return
	}
	userID, codeClientID, codeRedirectURI, ok := h.CodeStore.GetAndConsume(code)
	if !ok {
		writeError(w, "INVALID_GRANT", "invalid or expired code", http.StatusBadRequest, "")
		return
	}
	if codeClientID != clientID {
		writeError(w, "INVALID_GRANT", "code was issued for another client", http.StatusBadRequest, "")
		return
	}
	if redirectURI != "" && redirectURI != codeRedirectURI {
		writeError(w, "INVALID_GRANT", "redirect_uri does not match", http.StatusBadRequest, "")
		return
	}
	accessToken, err := h.AuthService.IssueToken(r.Context(), userID)
	if err != nil {
		writeError(w, "INTERNAL_ERROR", "Failed to issue token", http.StatusInternalServerError, "")
		return
	}
	expiresIn := h.AccessTokenExpireSec
	if expiresIn <= 0 {
		expiresIn = 86400
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		UserID:      userID,
	})
}

// TokenByCodeRequest 前端用 code 换 token 的请求（无子应用后端时使用）
type TokenByCodeRequest struct {
	ClientID    string `json:"client_id"`
	Code        string `json:"code"`
	RedirectURI string `json:"redirect_uri"`
}

// TokenByCodeHandler 前端直连：用 client_id + 登录成功后返回的凭证（redirect_url 中的 code）换取 token，无需 client_secret。
// 适用于没有子应用后端的场景：登录接口返回 {"redirect_url": "xxx?code=xxx&state=xxx"} 后，前端从 redirect_url 解析出 code，再调用本接口。
// POST /api/v1/auth/token-by-code
func (h *Handler) TokenByCodeHandler(w http.ResponseWriter, r *http.Request) {
	if h.CodeStore == nil {
		writeError(w, "INTERNAL_ERROR", "Token exchange not configured", http.StatusInternalServerError, "")
		return
	}
	var req TokenByCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "INVALID_REQUEST", "Invalid request body", http.StatusBadRequest, "")
		return
	}
	clientID := strings.TrimSpace(req.ClientID)
	code := strings.TrimSpace(req.Code)
	redirectURI := strings.TrimSpace(req.RedirectURI)
	if clientID == "" || code == "" || redirectURI == "" {
		writeError(w, "INVALID_REQUEST", "client_id, code and redirect_uri are required", http.StatusBadRequest, "")
		return
	}
	userID, codeClientID, codeRedirectURI, ok := h.CodeStore.GetAndConsume(code)
	if !ok {
		writeError(w, "INVALID_GRANT", "invalid or expired code", http.StatusBadRequest, "")
		return
	}
	if codeClientID != clientID {
		writeError(w, "INVALID_GRANT", "code was not issued for this client_id", http.StatusBadRequest, "")
		return
	}
	if codeRedirectURI != redirectURI {
		writeError(w, "INVALID_GRANT", "redirect_uri does not match", http.StatusBadRequest,
			fmt.Sprintf("token-by-code redirect_uri mismatch: client=%s got=%s want=%s", clientID, redirectURI, codeRedirectURI))
		return
	}
	accessToken, err := h.AuthService.IssueToken(r.Context(), userID)
	if err != nil {
		writeError(w, "INTERNAL_ERROR", "Failed to issue token", http.StatusInternalServerError, "")
		return
	}
	// Cookie 落在认证中心域；前端若与认证中心同源可直接带 Cookie 访问 /me、/validate；若跨域且需 user_id 可再调 GET /me（带 credentials）
	h.setTokenCookies(w, r.Context(), accessToken, userID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
