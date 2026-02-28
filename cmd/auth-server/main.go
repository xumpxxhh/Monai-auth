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

// Config 结构体映射 config.yaml
type Config struct {
	Server struct {
		Port               string   `mapstructure:"port"`
		JWTSecret          string   `mapstructure:"jwt_secret"`
		JWTExpirationHours int      `mapstructure:"jwt_expiration_hours"`
		AllowedOrigins     []string `mapstructure:"allowed_origins"`
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
	// 使用 userrepo 别名
	userRepo := userrepo.NewGORMUserRepository(gormDB)

	// Token 服务
	expiry := time.Duration(cfg.Server.JWTExpirationHours) * time.Hour
	tokenService := auth.NewJWTService(cfg.Server.JWTSecret, expiry)

	// 核心鉴权服务 (Service)
	authService := auth.NewAuthService(userRepo, tokenService)

	// 传输层 (Handler)
	httpHandler := httptransport.NewHandler(authService)

	// 3. 配置 HTTP 路由
	r := chi.NewRouter()
	r.Use(httptransport.LoggerMiddleware)
	if len(cfg.Server.AllowedOrigins) > 0 {
		r.Use(httptransport.CORSMiddleware(cfg.Server.AllowedOrigins))
	}
	r.Post("/api/v1/auth/login", httpHandler.LoginHandler)
	r.Post("/api/v1/auth/logout", httpHandler.LogoutHandler)
	r.Get("/api/v1/auth/validate", httpHandler.ValidateHandler)
	r.Post("/api/v1/auth/register", httpHandler.RegisterHandler)

	// 4. 启动服务
	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	log.Printf("Auth Service starting on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}
