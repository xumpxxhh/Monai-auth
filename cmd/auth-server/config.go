package main

import "fmt"

// ClientConfig 子应用（客户端）配置
type ClientConfig struct {
	ClientID            string   `mapstructure:"client_id"`
	ClientSecret        string   `mapstructure:"client_secret"`
	AllowedRedirectURIs []string `mapstructure:"allowed_redirect_uris"`
}

// Config 结构体映射 config.yaml
type Config struct {
	Server struct {
		Port                   string         `mapstructure:"port"`
		JWTSecret              string         `mapstructure:"jwt_secret"`
		JWTExpirationHours     int            `mapstructure:"jwt_expiration_hours"`
		RefreshTokenExpiryDays int            `mapstructure:"refresh_token_expiry_days"`
		AllowedOrigins         []string       `mapstructure:"allowed_origins"`
		AuthBaseURL            string         `mapstructure:"auth_base_url"`
		LoginPagePath          string         `mapstructure:"login_page_path"`
		AllowedRedirectURIs    []string       `mapstructure:"allowed_redirect_uris"`
		Clients                []ClientConfig `mapstructure:"clients"`
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
