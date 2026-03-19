package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/viper"

	"monai-auth/internal/auth"
	userrepo "monai-auth/internal/repository/mysql"
	httptransport "monai-auth/internal/transport/http"
)

func main() {
	// 1. 加载配置
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AutomaticEnv()
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

	// 2. 初始化数据库
	gormDB := initDB(cfg)

	// 3. 依赖注入
	userRepo := userrepo.NewGORMUserRepository(gormDB)
	refreshTokenRepo := userrepo.NewGORMRefreshTokenRepository(gormDB)
	tokenService := auth.NewJWTService(cfg.Server.JWTSecret, time.Duration(cfg.Server.JWTExpirationHours)*time.Hour)
	authService := auth.NewAuthService(userRepo, tokenService, refreshTokenRepo)

	stateStore := auth.NewMemoryStateStore(10 * time.Minute)
	codeStore := auth.NewMemoryCodeStore(5 * time.Minute)

	loginPagePath := cfg.Server.LoginPagePath
	if loginPagePath == "" {
		loginPagePath = "/auth"
	}
	authBaseURL := cfg.Server.AuthBaseURL
	if authBaseURL == "" {
		authBaseURL = "http://localhost:" + cfg.Server.Port
	}
	refreshTokenExpiryDays := cfg.Server.RefreshTokenExpiryDays
	if refreshTokenExpiryDays <= 0 {
		refreshTokenExpiryDays = 7
	}

	clients := make([]httptransport.Client, 0, len(cfg.Server.Clients))
	for _, c := range cfg.Server.Clients {
		clients = append(clients, httptransport.Client{
			ClientID:            c.ClientID,
			ClientSecret:        c.ClientSecret,
			AllowedRedirectURIs: c.AllowedRedirectURIs,
		})
	}

	httpHandler := httptransport.NewHandler(authService, &httptransport.HandlerOpts{
		StateStore:            stateStore,
		CodeStore:             codeStore,
		LoginPagePath:         loginPagePath,
		AuthBaseURL:           authBaseURL,
		AllowedRedirectURIs:   cfg.Server.AllowedRedirectURIs,
		Clients:               clients,
		AccessTokenExpireSec:  cfg.Server.JWTExpirationHours * 3600,
		RefreshTokenExpireSec: refreshTokenExpiryDays * 24 * 3600,
	})

	// 4. 注册路由并启动
	r := chi.NewRouter()
	registerRoutes(r, httpHandler, cfg.Server.AllowedOrigins)

	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	log.Printf("Auth Service starting on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}
