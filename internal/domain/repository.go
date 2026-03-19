package domain

import (
	"context"
	"time"
)

// UserRepository 定义了数据持久化的操作契约
type UserRepository interface {
	// FindByID 根据 ID 查找用户
	FindByID(ctx context.Context, id int64) (*User, error)

	// FindByEmail 根据 Email 查找用户
	FindByEmail(ctx context.Context, email string) (*User, error)

	// ExistsByEmail 检查指定 email 是否已存在
	ExistsByEmail(ctx context.Context, email string) (bool, error)

	// CreateUser 创建新用户
	CreateUser(ctx context.Context, user *User) error
}

// RefreshToken Refresh Token 领域模型
type RefreshToken struct {
	ID        int64
	UserID    int64
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// RefreshTokenRepository Refresh Token 持久化接口
type RefreshTokenRepository interface {
	// Save 保存一个新的 refresh token
	Save(ctx context.Context, rt *RefreshToken) error

	// FindByToken 根据 token 字符串查找（仅返回未过期记录）
	FindByToken(ctx context.Context, token string) (*RefreshToken, error)

	// DeleteByToken 删除指定 token（登出/轮换时调用）
	DeleteByToken(ctx context.Context, token string) error

	// DeleteByUserID 删除某用户的所有 refresh token（强制下线时调用）
	DeleteByUserID(ctx context.Context, userID int64) error
}
