package main

import (
	"fmt"
	"log"
	n_http "net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"monai-auth/internal/auth"
	userrepo "monai-auth/internal/repository/mysql" // 明确地使用别名 userrepo
	"monai-auth/internal/transport/http"
)

// Config 结构体映射 config.yaml
type Config struct {
	Server struct {
		Port               string `mapstructure:"port"`
		JWTSecret          string `mapstructure:"jwt_secret"`
		JWTExpirationHours int    `mapstructure:"jwt_expiration_hours"`
	} `mapstructure:"server"`
	Database struct {
		Host     string `mapstructure:"host"`
		Port     string `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		DBName   string `mapstructure:"dbname"`
	} `mapstructure:"database"`
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
	// ... 配置加载逻辑保持不变 ...
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Unable to decode config into struct: %v", err)
	}

	// 2. 初始化数据库和依赖注入 (DI)
	gormDB := initDB(cfg) // 初始化 GORM 连接

	// 仓库层 (Repository)
	// 使用 userrepo 别名
	userRepo := userrepo.NewGORMUserRepository(gormDB)

	// Token 服务
	expiry := time.Duration(cfg.Server.JWTExpirationHours) * time.Hour
	tokenService := auth.NewJWTService(cfg.Server.JWTSecret, expiry)

	// 核心鉴权服务 (Service)
	authService := auth.NewAuthService(userRepo, tokenService)

	// 传输层 (Handler)
	httpHandler := http.NewHandler(authService)

	// 3. 配置 HTTP 路由
	r := chi.NewRouter()
	r.Post("/api/v1/auth/login", httpHandler.LoginHandler)
	r.Get("/api/v1/auth/validate", httpHandler.ValidateHandler)

	// 4. 启动服务
	addr := fmt.Sprintf(":%s", cfg.Server.Port)
	log.Printf("Auth Service starting on %s", addr)
	if err := n_http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}
