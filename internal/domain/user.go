package domain

import (
	"errors"
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
)

// LoginRequest 是登录时需要的DTO
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest  注册DTO
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
