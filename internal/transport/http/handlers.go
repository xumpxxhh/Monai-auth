package http

import (
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
	AuthService          auth.Service
	StateStore           auth.StateStore
	CodeStore            auth.CodeStore
	UserAssetRepository  domain.UserAssetRepository // 上传资源写入 user_assets 表，可为 nil 则仅落盘
	CookieSecure         bool   // 生产 HTTPS 时 true，Cookie 仅通过 HTTPS 发送
	LoginPagePath        string
	AuthBaseURL          string // 认证中心对外 base URL，用于拼完整登录页地址
	AllowedRedirectURIs  []string
	Clients              []Client
	AccessTokenExpireSec int
}

// HandlerOpts 可选配置
type HandlerOpts struct {
	StateStore           auth.StateStore
	CodeStore            auth.CodeStore
	UserAssetRepository  domain.UserAssetRepository
	CookieSecure         bool // 生产 HTTPS 时 true
	LoginPagePath        string
	AuthBaseURL          string
	AllowedRedirectURIs  []string
	Clients              []Client
	AccessTokenExpireSec int
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
	h := &Handler{AuthService: authService}
	if opts != nil {
		h.StateStore = opts.StateStore
		h.CodeStore = opts.CodeStore
		h.UserAssetRepository = opts.UserAssetRepository
		h.CookieSecure = opts.CookieSecure
		if opts.LoginPagePath != "" {
			h.LoginPagePath = opts.LoginPagePath
		} else {
			h.LoginPagePath = "/monai/login"
		}
		h.AuthBaseURL = opts.AuthBaseURL
		h.AllowedRedirectURIs = opts.AllowedRedirectURIs
		h.Clients = opts.Clients
		h.AccessTokenExpireSec = opts.AccessTokenExpireSec
		if h.AccessTokenExpireSec <= 0 {
			h.AccessTokenExpireSec = 86400 // 24h
		}
	} else {
		h.LoginPagePath = "/monai/login"
		h.AccessTokenExpireSec = 86400
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

	// SSO 授权码流程：带 server_state 时用其取回 client_id/redirect_uri，生成 code 并返回完整回调 URL 字符串（不 302）
	if req.ServerState != "" && h.StateStore != nil && h.CodeStore != nil {
		clientID, redirectURI, _, ok := h.StateStore.GetAndConsume(req.ServerState)
		if ok && redirectURI != "" {
			user, errUser := h.AuthService.Validate(r.Context(), token)
			if errUser == nil {
				code, errCode := h.CodeStore.Save(user.ID, clientID, redirectURI)
				if errCode == nil {
					u, _ := url.Parse(redirectURI)
					if u != nil {
						q := u.Query()
						q.Set("code", code)
						// q.Set("state", req.ServerState)
						u.RawQuery = q.Encode()
						w.Header().Set("Content-Type", "application/json")
						fmt.Println("redirect_url", u.String())
						_ = json.NewEncoder(w).Encode(map[string]string{"redirect_url": u.String()})
						return
					}
				}
			}
		}
	}

	// 非 SSO：将 token 写入 HttpOnly Cookie 并返回 JSON
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// authTokenCookieName 与登录时设置的 Cookie 名称一致
const authTokenCookieName = "auth_token"

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

// LogoutHandler 处理登出：清除服务端下发的 auth_token Cookie，客户端无需再持有 token
func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.CookieSecure,
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
	originalFileName := strings.TrimSpace(r.FormValue("fileName"))
	if originalFileName == "" {
		writeError(w, "INVALID_REQUEST", "fileName is required", http.StatusBadRequest, "")
		return
	}
	fileName := filepath.Base(originalFileName)
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
	// 写入 user_assets 表（若已注入 UserAssetRepository）
	var size *int
	if fi, err := dst.Stat(); err == nil {
		s := int(fi.Size())
		size = &s
	}
	if h.UserAssetRepository != nil {
		if err := h.UserAssetRepository.Create(r.Context(), user.ID, relativePath, "avatar", originalFileName, size); err != nil {
			log.Printf("[AUTH] upload create user_asset: %v", err)
			// 文件已落盘，仅记录日志，不中断响应
		}
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
	ClientID string `json:"client_id"`
	Code     string `json:"code"`
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
	if clientID == "" || code == "" {
		writeError(w, "INVALID_REQUEST", "client_id and code are required", http.StatusBadRequest, "")
		return
	}
	userID, codeClientID, _, ok := h.CodeStore.GetAndConsume(code)
	if !ok {
		writeError(w, "INVALID_GRANT", "invalid or expired code", http.StatusBadRequest, "")
		return
	}
	if codeClientID != clientID {
		writeError(w, "INVALID_GRANT", "code was not issued for this client_id", http.StatusBadRequest, "")
		return
	}
	accessToken, err := h.AuthService.IssueToken(r.Context(), userID)
	if err != nil {
		writeError(w, "INTERNAL_ERROR", "Failed to issue token", http.StatusInternalServerError, "")
		return
	}
	// Cookie 落在认证中心域；前端若与认证中心同源可直接带 Cookie 访问 /me、/validate；若跨域且需 user_id 可再调 GET /me（带 credentials）
	http.SetCookie(w, &http.Cookie{
		Name:     authTokenCookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
