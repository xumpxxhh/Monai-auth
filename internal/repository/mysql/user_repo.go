package mysql

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"monai-auth/internal/domain"
)

// GORMUserRepository 实现了 domain.UserRepository 接口
type GORMUserRepository struct {
	DB *gorm.DB
}

// NewGORMUserRepository 创建一个新的 GORM 仓库实例
func NewGORMUserRepository(db *gorm.DB) *GORMUserRepository {
	return &GORMUserRepository{DB: db}
}

// mapGORMToDomain 将 GORM 模型转换为领域模型
func mapGORMToDomain(gormUser *UserGORM) *domain.User {
	return &domain.User{
		ID:           gormUser.ID,
		Username:     gormUser.Username,
		Email:        gormUser.Email,
		PasswordHash: gormUser.PasswordHash,
		Role:         "standard",
		CreatedAt:    gormUser.CreatedAt,
	}
}

// FindByID 根据 ID 查找用户
func (r *GORMUserRepository) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	var userGORM UserGORM

	// GORM 的 First 方法会自动添加 WHERE deleted_at IS NULL
	result := r.DB.WithContext(ctx).Where("id = ?", id).First(&userGORM)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm find by ID failed: %w", result.Error)
	}

	return mapGORMToDomain(&userGORM), nil
}

// FindByEmail 根据 Email 查找用户
func (r *GORMUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var userGORM UserGORM

	// GORM 的 First 方法会自动添加 WHERE deleted_at IS NULL
	result := r.DB.WithContext(ctx).Where("email = ?", email).First(&userGORM)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("gorm find by email failed: %w", result.Error)
	}

	return mapGORMToDomain(&userGORM), nil
}

// ExistsByEmail 检查指定 email 是否已存在
func (r *GORMUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.DB.WithContext(ctx).
		Model(&UserGORM{}).
		Where("email = ?", email).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("check email existence failed: %w", err)
	}

	return count > 0, nil
}

// CreateUser 创建新用户
func (r *GORMUserRepository) CreateUser(ctx context.Context, user *domain.User) error {
	username := user.Username
	if username == "" {
		username = user.Email
	}
	userGORM := UserGORM{
		Username:     username,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		Status:       "active",
		LastLoginAt:  time.Now(),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	result := r.DB.WithContext(ctx).Create(&userGORM)

	if result.Error != nil {
		if isDuplicateEntryError(result.Error) {
			return domain.ErrEmailExists
		}
		return fmt.Errorf("gorm create user failed: %w", result.Error)
	}

	user.ID = userGORM.ID
	return nil
}

// isDuplicateEntryError 检查 GORM 错误是否是 MySQL 唯一约束冲突 (错误码 1062)
func isDuplicateEntryError(err error) bool {
	// GORM 错误通常需要解包才能获取底层驱动错误
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	// 复杂的错误检查可能需要导入 go-sql-driver/mysql 并检查 *mysql.MySQLError.Number == 1062
	return false
}
