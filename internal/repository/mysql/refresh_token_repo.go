package mysql

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"monai-auth/internal/domain"
)

type gormRefreshTokenRepository struct {
	db *gorm.DB
}

// NewGORMRefreshTokenRepository 创建 MySQL Refresh Token 仓库
func NewGORMRefreshTokenRepository(db *gorm.DB) domain.RefreshTokenRepository {
	return &gormRefreshTokenRepository{db: db}
}

func (r *gormRefreshTokenRepository) Save(ctx context.Context, rt *domain.RefreshToken) error {
	m := &RefreshTokenGORM{
		UserID:    rt.UserID,
		Token:     rt.Token,
		ExpiresAt: rt.ExpiresAt,
	}
	return r.db.WithContext(ctx).Create(m).Error
}

func (r *gormRefreshTokenRepository) FindByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	var m RefreshTokenGORM
	err := r.db.WithContext(ctx).
		Where("token = ? AND expires_at > ?", token, time.Now()).
		First(&m).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return &domain.RefreshToken{
		ID:        m.ID,
		UserID:    m.UserID,
		Token:     m.Token,
		ExpiresAt: m.ExpiresAt,
		CreatedAt: m.CreatedAt,
	}, nil
}

func (r *gormRefreshTokenRepository) DeleteByToken(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).
		Where("token = ?", token).
		Delete(&RefreshTokenGORM{}).Error
}

func (r *gormRefreshTokenRepository) DeleteByUserID(ctx context.Context, userID int64) error {
	return r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&RefreshTokenGORM{}).Error
}
