package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	httptransport "monai-auth/internal/transport/http"
)

// staticCORSHandler 为 /static/ 响应加 CORS 头，跨域加载时浏览器才能按 Cache-Control 正常缓存
func staticCORSHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}

// cacheControlHandler 包装 handler，为 200 响应添加 Cache-Control: public, max-age=<sec>
func cacheControlHandler(next http.Handler, maxAge int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&cacheControlResponseWriter{ResponseWriter: w, maxAge: maxAge}, r)
	})
}

type cacheControlResponseWriter struct {
	http.ResponseWriter
	maxAge int
	sent   bool
}

func (w *cacheControlResponseWriter) WriteHeader(code int) {
	if !w.sent {
		w.sent = true
		if code == http.StatusOK || code == http.StatusNotModified {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", w.maxAge))
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *cacheControlResponseWriter) Write(p []byte) (int, error) {
	if !w.sent {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

// registerRoutes 注册所有 HTTP 路由
func registerRoutes(r *chi.Mux, h *httptransport.Handler, allowedOrigins []string) {
	r.Use(httptransport.LoggerMiddleware)
	if len(allowedOrigins) > 0 {
		r.Use(httptransport.CORSMiddleware(allowedOrigins))
	}

	// 敏感接口：10次/15分钟，防爆破与授权码滥用
	sensitive := httptransport.RateLimitMiddleware(10, 15*time.Minute)
	r.With(sensitive).Get("/api/v1/auth/request-login", h.SSORequestLoginHandler)
	r.With(sensitive).Post("/api/v1/auth/login", h.LoginHandler)
	r.With(sensitive).Post("/api/v1/auth/register", h.RegisterHandler)
	r.With(sensitive).Post("/api/v1/auth/token", h.TokenHandler)
	r.With(sensitive).Post("/api/v1/auth/token-by-code", h.TokenByCodeHandler)

	// 普通接口：120次/分钟，满足正常业务轮询
	normal := httptransport.RateLimitMiddleware(120, time.Minute)
	r.With(normal).Post("/api/v1/auth/logout", h.LogoutHandler)
	r.With(normal).Get("/api/v1/auth/validate", h.ValidateHandler)
	r.With(normal).Get("/api/v1/auth/me", h.MeHandler)
	r.With(normal).Post("/api/v1/auth/upload", h.UploadHandler)
	r.With(normal).Post("/api/v1/auth/refresh", h.RefreshHandler)

	const staticCacheMaxAge = 3 * 24 * 3600 // 3 天
	staticHandler := http.StripPrefix("/static/uploads", cacheControlHandler(http.FileServer(http.Dir("./uploads")), staticCacheMaxAge))
	r.Handle("/static/uploads/*", staticCORSHandler(staticHandler))
}
