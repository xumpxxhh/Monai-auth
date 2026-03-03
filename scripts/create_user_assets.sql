-- 用户资源表（本地目录 + 数据库存路径）
-- 使用方式: mysql -u root -p identity_db < scripts/create_user_assets.sql

CREATE TABLE IF NOT EXISTS `user_assets` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`       BIGINT NOT NULL COMMENT '所属用户',
  `file_path`     VARCHAR(512) NOT NULL COMMENT '相对路径，如 uploads/avatars/123_xxx.jpg',
  `file_type`     VARCHAR(32) NOT NULL DEFAULT 'avatar' COMMENT '类型: avatar/cover/gallery',
  `original_name` VARCHAR(255) DEFAULT NULL COMMENT '原始文件名',
  `size`          INT UNSIGNED DEFAULT NULL COMMENT '文件大小(字节)',
  `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_assets_user_id` (`user_id`),
  KEY `idx_user_assets_file_type` (`file_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户上传资源（图片等）';
