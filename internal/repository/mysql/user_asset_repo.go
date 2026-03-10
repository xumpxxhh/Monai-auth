package mysql

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// GORMUserAssetRepository 实现 domain.UserAssetRepository
type GORMUserAssetRepository struct {
	DB *gorm.DB
}

// NewGORMUserAssetRepository 创建 user_assets 仓库实例
func NewGORMUserAssetRepository(db *gorm.DB) *GORMUserAssetRepository {
	return &GORMUserAssetRepository{DB: db}
}

// Create 写入一条 user_assets 记录
func (r *GORMUserAssetRepository) Create(ctx context.Context, userID int64, filePath, fileType, originalName string, size *int) error {
	if fileType == "" {
		fileType = "avatar"
	}
	m := UserAssetGORM{
		UserID:       userID,
		FilePath:     filePath,
		FileType:     fileType,
		OriginalName: originalName,
		Size:         size,
	}
	if err := r.DB.WithContext(ctx).Create(&m).Error; err != nil {
		return fmt.Errorf("create user_asset: %w", err)
	}
	return nil
}
