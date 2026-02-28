package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// User 是核心用户模型
type User struct {
	ID           int64
	Username     string
	Role         string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

// 定义服务可能返回的常见错误
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserExists         = errors.New("username already exists")
	ErrEmailExists        = errors.New("email already exists")
	ErrInvalidEmail       = errors.New("invalid email format")
	ErrPasswordTooShort   = errors.New("password too short")
)

// 简单邮箱格式校验
var emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// MinPasswordLength 注册时密码最小长度
const MinPasswordLength = 6

// ValidateRegisterRequest 校验注册请求
func ValidateRegisterRequest(req RegisterRequest) error {
	if strings.TrimSpace(req.Email) == "" {
		return ErrInvalidEmail
	}
	if !emailRegexp.MatchString(req.Email) {
		return ErrInvalidEmail
	}
	if len(req.Password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	return nil
}

// LoginRequest 是登录时需要的DTO
type LoginRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest  注册DTO
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
