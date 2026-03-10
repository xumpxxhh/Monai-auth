package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"monai-auth/internal/auth"
	userrepo "monai-auth/internal/repository/mysql" // 明确地使用别名 userrepo
	httptransport "monai-auth/internal/transport/http"
)

// ClientConfig 子应用（客户端）配置
type ClientConfig struct {
	ClientID             string   `mapstructure:"client_id"`
	ClientSecret         string   `mapstructure:"client_secret"`
	AllowedRedirectURIs  []string `mapstructure:"allowed_redirect_uris"`
}

// Config 结构体映射 config.yaml
type Config struct {
	Server struct {
		Port                string         `mapstructure:"port"`
		JWTSecret           string         `mapstructure:"jwt_secret"`
		JWTExpirationHours  int            `mapstructure:"jwt_expiration_hours"`
		AllowedOrigins      []string       `mapstructure:"allowed_origins"`
		AuthBaseURL         string         `mapstructure:"auth_base_url"`
		LoginPagePath       string         `mapstructure:"login_page_path"`
		AllowedRedirectURIs []string       `mapstructure:"allowed_redirect_uris"`
		Clients             []ClientConfig `mapstructure:"clients"`
	} `mapstructure:"server"`
	Database struct {
		Host     string `mapstructure:"host"`
		Port     string `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		DBName   string `mapstructure:"dbname"`
	} `mapstructure:"database"`
}

// validateConfig 校验必填配置项
func validateConfig(cfg Config) error {
	if cfg.Server.Port == "" {
		return fmt.Errorf("server.port is required")
	}
	if cfg.Server.JWTSecret == "" {
		return fmt.Errorf("server.jwt_secret is required and must be non-empty")
	}
	if cfg.Server.JWTExpirationHours < 1 || cfg.Server.JWTExpirationHours > 720 {
		return fmt.Errorf("server.jwt_expiration_hours must be between 1 and 720")
	}
	if cfg.Database.Host == "" || cfg.Database.Port == "" || cfg.Database.User == "" || cfg.Database.DBName == "" {
		return fmt.Errorf("database host, port, user, dbname are required")
	}
	return nil
}

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

// initDB 初始化并返回 GORM 数据库连接
func initDB(cfg Config) *gorm.DB {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.DBName,
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connection successful.")
	return db
}

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AutomaticEnv() // 环境变量可覆盖配置文件

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Unable to decode config into struct: %v", err)
	}
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	// 2. 初始化数据库和依赖注入 (DI)
	gormDB := initDB(cfg)

	// 仓库层 (Repository)
	userRepo := userrepo.NewGORMUserRepository(gormDB)
	userAssetRepo := userrepo.NewGORMUserAssetRepository(gormDB)

	// Token 服务
	expiry := time.Duration(cfg.Server.JWTExpirationHours) * time.Hour
	tokenService := auth.NewJWTService(cfg.Server.JWTSecret, expiry)

	// 核心鉴权服务 (Service)
	authService := auth.NewAuthService(userRepo, tokenService)

	// SSO state 与 授权码 存储
	stateStore := auth.NewMemoryStateStore(10 * time.Minute)
	codeStore := auth.NewMemoryCodeStore(5 * time.Minute)
	loginPagePath := cfg.Server.LoginPagePath
	if loginPagePath == "" {
		loginPagePath = "/monai/login"
	}
	// 将配置中的 clients 转为 transport 层使用的 Client
	clients := make([]httptransport.Client, 0, len(cfg.Server.Clients))
	for _, c := range cfg.Server.Clients {
		clients = append(clients, httptransport.Client{
			ClientID:            c.ClientID,
			ClientSecret:       c.ClientSecret,
			AllowedRedirectURIs: c.AllowedRedirectURIs,
		})
	}

	authBaseURL := cfg.Server.AuthBaseURL
	if authBaseURL == "" {
		authBaseURL = "http://localhost:" + cfg.Server.Port
	}
	// 传输层 (Handler)
	httpHandler := httptransport.NewHandler(authService, &httptransport.HandlerOpts{
		StateStore:           stateStore,
		CodeStore:            codeStore,
		UserAssetRepository:  userAssetRepo,
		LoginPagePath:        loginPagePath,
		AuthBaseURL:          authBaseURL,
		AllowedRedirectURIs:  cfg.Server.AllowedRedirectURIs,
		Clients:              clients,
		AccessTokenExpireSec: cfg.Server.JWTExpirationHours * 3600,
	})

	// 3. 配置 HTTP 路由
	r := chi.NewRouter()
	r.Use(httptransport.LoggerMiddleware)
	if len(cfg.Server.AllowedOrigins) > 0 {
		r.Use(httptransport.CORSMiddleware(cfg.Server.AllowedOrigins))
	}
	r.Get("/api/v1/auth/request-login", httpHandler.SSORequestLoginHandler)
	r.Post("/api/v1/auth/login", httpHandler.LoginHandler)
	r.Post("/api/v1/auth/logout", httpHandler.LogoutHandler)
	r.Get("/api/v1/auth/validate", httpHandler.ValidateHandler)
	r.Get("/api/v1/auth/me", httpHandler.MeHandler)
	r.Post("/api/v1/auth/upload", httpHandler.UploadHandler)
	r.Post("/api/v1/auth/token", httpHandler.TokenHandler)
	r.Post("/api/v1/auth/token-by-code", httpHandler.TokenByCodeHandler)
	r.Post("/api/v1/auth/register", httpHandler.RegisterHandler)
	// 上传文件的访问路径（跨域可访问 + 3 天缓存，便于前端另一域名下走缓存）
	const staticCacheMaxAge = 3 * 24 * 3600 // 3 天
	staticHandler := http.StripPrefix("/static", cacheControlHandler(http.FileServer(http.Dir(".")), staticCacheMaxAge))
	r.Handle("/static/*", staticCORSHandler(staticHandler))

	// 4. 启动服务
	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	log.Printf("Auth Service starting on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}
