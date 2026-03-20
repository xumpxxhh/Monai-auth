package http

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// responseWriter 封装 http.ResponseWriter 以捕获状态码
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// LoggerMiddleware 记录请求日志的中间件
func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		log.Printf(
			"[%s]\t%s\t%s\t%d\t%v",
			r.Method,
			r.RequestURI,
			clientIP(r),
			rw.status,
			duration,
		)
	})
}

// CORSMiddleware 基于配置的允许域名列表设置 CORS 相关响应头
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowAll := false
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
			break
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" && (allowAll || isOriginAllowed(origin, allowedOrigins)) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			}

			// 预检请求直接返回
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isOriginAllowed(origin string, allowed []string) bool {
	for _, o := range allowed {
		if o == origin {
			return true
		}
	}
	return false
}

// ipCounter 记录某个 IP 在当前窗口内的请求次数
type ipCounter struct {
	count   int
	resetAt time.Time
}

// rateLimiter 基于固定窗口的 per-IP 限速器
type rateLimiter struct {
	mu       sync.Mutex
	counters map[string]*ipCounter
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		counters: make(map[string]*ipCounter),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

// allow 判断该 IP 是否允许本次请求，并更新计数
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	c, ok := rl.counters[ip]
	if !ok || now.After(c.resetAt) {
		rl.counters[ip] = &ipCounter{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	if c.count >= rl.limit {
		return false
	}
	c.count++
	return true
}

// cleanup 每分钟清理已过期的 IP 条目，防止内存无限增长
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, c := range rl.counters {
			if now.After(c.resetAt) {
				delete(rl.counters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP 从请求中提取真实客户端 IP。
// 优先取 nginx 设置的 X-Real-IP（值为 $remote_addr，不可伪造），
// 回退到 RemoteAddr。
// 不使用 X-Forwarded-For：nginx 用 $proxy_add_x_forwarded_for 时客户端可在该头里
// 预置假 IP，取第一个会被欺骗。
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	// net.SplitHostPort 正确处理 IPv4（1.2.3.4:port）和 IPv6（[::1]:port）
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// RateLimitMiddleware 对所有请求按 IP 限速：每个窗口期内最多 limit 次请求。
func RateLimitMiddleware(limit int, window time.Duration) func(http.Handler) http.Handler {
	rl := newRateLimiter(limit, window)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !rl.allow(ip) {
				log.Printf("[RATE_LIMIT] blocked ip=%s path=%s", ip, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"code":"TOO_MANY_REQUESTS","message":"rate limit exceeded"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
