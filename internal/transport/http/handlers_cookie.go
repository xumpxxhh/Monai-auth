package http

import (
	"context"
	"log"
	"net/http"
	"time"
)

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
