package main

import (
	"fmt"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	userrepo "monai-auth/internal/repository/mysql"
)

// initDB 初始化并返回 GORM 数据库连接，同时自动迁移所需表结构
func initDB(cfg Config) *gorm.DB {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.DBName,
	)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	if err := db.AutoMigrate(&userrepo.RefreshTokenGORM{}); err != nil {
		log.Fatalf("Failed to migrate refresh_tokens table: %v", err)
	}
	log.Println("Database connection successful.")
	return db
}
