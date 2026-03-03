// 临时脚本：创建 user_assets 表。在项目根目录执行: go run scripts/create_user_assets.go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type UserAsset struct {
	ID           uint   `gorm:"primaryKey;autoIncrement"`
	UserID       int64  `gorm:"not null;index"`
	FilePath     string `gorm:"type:varchar(512);not null"`
	FileType     string `gorm:"type:varchar(32);not null;default:avatar;index"`
	OriginalName string `gorm:"type:varchar(255)"`
	Size         *int   `gorm:"type:int unsigned"`
	CreatedAt    time.Time
}

func (UserAsset) TableName() string { return "user_assets" }

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}
	cfg := struct {
		Host string `mapstructure:"host"`
		Port string `mapstructure:"port"`
		User string `mapstructure:"user"`
		Pass string `mapstructure:"password"`
		DB   string `mapstructure:"dbname"`
	}{}
	if err := viper.UnmarshalKey("database", &cfg); err != nil {
		log.Fatalf("解析配置失败: %v", err)
	}
	if cfg.Host == "" || cfg.DB == "" {
		log.Fatal("configs/config.yaml 中缺少 database.host 或 database.dbname")
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.DB)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	if err := db.AutoMigrate(&UserAsset{}); err != nil {
		log.Fatalf("创建表失败: %v", err)
	}
	log.Println("user_assets 表已创建或已为最新结构。")
}
