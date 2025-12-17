package domain

import (
	"context"
)

// UserRepository 定义了数据持久化的操作契约
type UserRepository interface {
	// FindByID 根据 ID 查找用户
	FindByID(ctx context.Context, id string) (*User, error)

	// FindByEmail 根据 Email 查找用户
	FindByEmail(ctx context.Context, email string) (*User, error)

	// CreateUser 创建新用户
	CreateUser(ctx context.Context, user *User) error
}
