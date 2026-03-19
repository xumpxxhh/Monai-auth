-- Refresh Token 表（用于双 Token 认证机制）
-- 使用方式: mysql -u root -p identity_db < scripts/create_refresh_tokens.sql

CREATE TABLE IF NOT EXISTS `refresh_tokens` (
  `id`         BIGINT       NOT NULL AUTO_INCREMENT,
  `user_id`    BIGINT       NOT NULL                COMMENT '所属用户 ID，关联 users.id',
  `token`      VARCHAR(128) NOT NULL                COMMENT '64位十六进制随机字符串',
  `expires_at` DATETIME     NOT NULL                COMMENT 'Token 过期时间',
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_refresh_tokens_token`    (`token`),
  KEY        `idx_refresh_tokens_user_id`   (`user_id`),
  KEY        `idx_refresh_tokens_expires_at`(`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Refresh Token（双 Token 认证）';
