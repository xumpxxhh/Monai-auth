package http

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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
	codeChallenge := strings.TrimSpace(r.URL.Query().Get("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(r.URL.Query().Get("code_challenge_method"))
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	if codeChallenge == "" {
		writeError(w, "INVALID_REQUEST", "code_challenge is required", http.StatusBadRequest, "")
		return
	}
	if codeChallengeMethod != "S256" {
		writeError(w, "INVALID_REQUEST", "code_challenge_method must be S256", http.StatusBadRequest, "")
		return
	}
	if !isValidCodeChallenge(codeChallenge) {
		writeError(w, "INVALID_REQUEST", "invalid code_challenge format", http.StatusBadRequest, "")
		return
	}
	// state 由服务端生成并绑定 client_id、redirect_uri、PKCE challenge
	state, err := h.StateStore.Save(clientID, redirectURI, "", codeChallenge, codeChallengeMethod)
	if err != nil {
		writeError(w, "INTERNAL_ERROR", "Failed to create state", http.StatusInternalServerError, "")
		return
	}
	base := strings.TrimSuffix(h.AuthBaseURL, "/")
	p := strings.TrimPrefix(h.LoginPagePath, "/")
	loginURL := base + "/" + p + "?client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=" + url.QueryEscape(state)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RequestLoginResponse{LoginURL: loginURL})
}

// buildSSOredirectURI 从 StateStore 取回 client_id/redirect_uri，生成授权码，
// 返回带 code 的完整回调 URL；任意步骤失败时返回空字符串。
func (h *Handler) buildSSOredirectURI(ctx context.Context, userID int64, serverState string) string {
	clientID, redirectURI, _, codeChallenge, codeChallengeMethod, ok := h.StateStore.GetAndConsume(serverState)
	if !ok || redirectURI == "" {
		return ""
	}
	code, err := h.CodeStore.Save(userID, clientID, redirectURI, codeChallenge, codeChallengeMethod)
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
	userID, codeClientID, codeRedirectURI, _, _, ok := h.CodeStore.GetAndConsume(code)
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
	ClientID     string `json:"client_id"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier"`
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
	codeVerifier := strings.TrimSpace(req.CodeVerifier)
	if clientID == "" || code == "" || redirectURI == "" || codeVerifier == "" {
		writeError(w, "INVALID_REQUEST", "client_id, code, redirect_uri and code_verifier are required", http.StatusBadRequest, "")
		return
	}
	userID, codeClientID, codeRedirectURI, codeChallenge, codeChallengeMethod, ok := h.CodeStore.GetAndConsume(code)
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
	if !verifyPKCEChallenge(codeVerifier, codeChallenge, codeChallengeMethod) {
		writeError(w, "INVALID_GRANT", "code_verifier does not match code_challenge", http.StatusBadRequest,
			fmt.Sprintf("PKCE verification failed: client=%s", clientID))
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

// verifyPKCEChallenge 验证 code_verifier 与存储的 code_challenge 是否匹配（仅支持 S256）。
// 使用 subtle.ConstantTimeCompare 避免时序攻击。
func verifyPKCEChallenge(codeVerifier, codeChallenge, method string) bool {
	if method != "S256" || codeVerifier == "" || codeChallenge == "" {
		return false
	}
	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// isValidCodeChallenge 校验 code_challenge 是否符合 S256 base64url 格式（固定 43 字符）。
func isValidCodeChallenge(s string) bool {
	if len(s) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}
