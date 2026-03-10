package domain

import (
	"context"
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

// UserAssetRepository 用户上传资源（如头像）的持久化
type UserAssetRepository interface {
	Create(ctx context.Context, userID int64, filePath, fileType, originalName string, size *int) error
}
