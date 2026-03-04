-- 用户表
-- 使用方式: mysql -u root -p <database_name> < scripts/create_users.sql

CREATE TABLE IF NOT EXISTS users
(
    id            bigint auto_increment comment '唯一主键'
        primary key,
    username      VARCHAR(100)                                not null comment '公开显示的用户名，可用于登录。',
    first_name    VARCHAR(100)      default ''                null comment '名字。',
    last_name     VARCHAR(100)      default ''                null comment '姓氏。',
    avatar_url    VARCHAR(512)      default ''                null comment '头像图片的存储路径或 URL。',
    phone_number  VARCHAR(20)                                 null comment '电话号码，如果用于登录或找回密码',
    email         VARCHAR(255)                                not null comment '主要联系方式和登录凭证。',
    password_hash VARCHAR(255)                                not null comment '存储加密后的密码',
    status        ENUM ('active', 'inactive', 'suspended', 'pending') default 'active'                 null comment '账户状态：1: active (活动), 2: inactive (非活动), 3: suspended (封禁), 4: pending (待验证)。',
    last_login_at TIMESTAMP         default CURRENT_TIMESTAMP not null comment '最后一次登录时间。',
    created_at    TIMESTAMP         default CURRENT_TIMESTAMP not null comment '记录创建时间（默认当前时间）。',
    updated_at    TIMESTAMP         default CURRENT_TIMESTAMP not null comment '记录更新时间。',
    deleted_at    TIMESTAMP                                   null comment '软删除机制。非空则表示用户已被“删除”（实际只是隐藏）。',
    constraint users_pk_2 unique (username),
    constraint users_pk_3 unique (phone_number),
    constraint users_pk_4 unique (email)
)
    comment '用户表';
