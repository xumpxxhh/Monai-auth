package auth

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"monai-auth/internal/domain"
)

// Service 定义了鉴权服务的核心业务接口
type Service interface {
	Login(ctx context.Context, req domain.LoginRequest) (string, error)
	Register(ctx context.Context, email, password string) (string, error)
	Validate(ctx context.Context, tokenString string) (*domain.User, error)
}

type authService struct {
	repo         domain.UserRepository
	tokenService TokenService
}

// NewAuthService 创建鉴权服务实例
func NewAuthService(repo domain.UserRepository, tokenService TokenService) Service {
	return &authService{
		repo:         repo,
		tokenService: tokenService,
	}
}

// Login 处理用户登录逻辑
func (s *authService) Login(ctx context.Context, req domain.LoginRequest) (string, error) {
	user, err := s.repo.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", domain.ErrInvalidCredentials
		}
		return "", fmt.Errorf("repository lookup error: %w", err)
	}

	// 验证密码
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return "", domain.ErrInvalidCredentials
	}

	// 生成并返回 JWT
	token, err := s.tokenService.GenerateToken(user.ID, user.Role)
	if err != nil {
		return "", fmt.Errorf("token generation failed: %w", err)
	}

	return token, nil
}

// Register 处理用户注册逻辑 (简化版)
func (s *authService) Register(ctx context.Context, email, password string) (string, error) {
	// 检查用户是否已存在... (省略)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	newUser := &domain.User{
		ID:           "new-id-123", // 实际应用中由DB生成
		Email:        email,
		PasswordHash: string(hashedPassword),
		Role:         "standard",
	}

	if err := s.repo.CreateUser(ctx, newUser); err != nil {
		return "", err
	}
	return newUser.ID, nil
}

// Validate 验证令牌并返回用户模型 (用于其他服务调用)
func (s *authService) Validate(ctx context.Context, tokenString string) (*domain.User, error) {
	claims, err := s.tokenService.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// 查找用户确保用户未被禁用/删除
	user, err := s.repo.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	return user, nil
}
