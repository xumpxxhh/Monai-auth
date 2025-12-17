// internal/repository/mysql/model.go (可选，可以单独创建一个文件存放模型)
package mysql

import (
	"time"

	"gorm.io/gorm"
)

// UserGORM 是用于 GORM 交互的结构体，匹配数据库字段
type UserGORM struct {
	// ID, CreatedAt, UpdatedAt, DeletedAt 遵循您的表定义
	ID           int64  `gorm:"primaryKey;autoIncrement"`
	Username     string `gorm:"unique;type:varchar(100);not null"`
	FirstName    string
	LastName     string
	AvatarURL    string
	PhoneNumber  *string `gorm:"unique;type:varchar(20)"` // 使用指针处理 NULLABLE 字段
	Email        string  `gorm:"unique;type:varchar(255);not null"`
	PasswordHash string  `gorm:"type:varchar(255);not null"`
	Status       string  `gorm:"type:enum('active', 'inactive', 'suspended', 'pending');default:'active'"`
	LastLoginAt  time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"column:deleted_at;index"` // 映射到您的 deleted_at 字段，启用 GORM 软删除
}

// TableName 指定 GORM 使用的表名
func (UserGORM) TableName() string {
	return "users"
}
