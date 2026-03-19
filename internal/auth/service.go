package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"monai-auth/internal/domain"
)

// Service 定义了鉴权服务的核心业务接口
type Service interface {
	Login(ctx context.Context, req domain.LoginRequest) (string, error)
	Register(ctx context.Context, req domain.RegisterRequest) (int64, error)
	Validate(ctx context.Context, tokenString string) (*domain.User, error)
	// IssueToken 为指定用户签发 access_token（用于授权码换 token）
	IssueToken(ctx context.Context, userID int64) (string, error)
	// IssueRefreshToken 签发 refresh token 并持久化，返回 token 字符串
	IssueRefreshToken(ctx context.Context, userID int64, expiry time.Duration) (string, error)
	// RefreshAccessToken 用 refresh token 换发新的 access_token；
	// 同时轮换 refresh token（旧的删除，返回新的 refresh token 字符串）
	RefreshAccessToken(ctx context.Context, refreshToken string, refreshExpiry time.Duration) (accessToken string, newRefreshToken string, err error)
	// RevokeRefreshToken 吊销单个 refresh token（登出时调用）
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
	// RevokeAllRefreshTokens 吊销某用户所有 refresh token（强制下线时调用）
	RevokeAllRefreshTokens(ctx context.Context, userID int64) error
}

type authService struct {
	repo            domain.UserRepository
	tokenService    TokenService
	refreshTokenRepo domain.RefreshTokenRepository
}

// NewAuthService 创建鉴权服务实例
func NewAuthService(repo domain.UserRepository, tokenService TokenService, refreshTokenRepo domain.RefreshTokenRepository) Service {
	return &authService{
		repo:            repo,
		tokenService:    tokenService,
		refreshTokenRepo: refreshTokenRepo,
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

// Register 处理用户注册逻辑
func (s *authService) Register(ctx context.Context, req domain.RegisterRequest) (int64, error) {
	if err := domain.ValidateRegisterRequest(req); err != nil {
		return -1, err
	}
	// 检查用户是否已存在
	isExist, err := s.repo.ExistsByEmail(ctx, req.Email)
	if err != nil {
		return -1, err
	}
	if isExist {
		return -1, domain.ErrEmailExists
	}
	username := req.Username
	if username == "" {
		username = req.Email
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return -1, fmt.Errorf("password hash failed: %w", err)
	}

	newUser := &domain.User{
		Username:     username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Role:         "standard",
	}

	if err := s.repo.CreateUser(ctx, newUser); err != nil {
		return -1, err
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

// IssueToken 根据 userID 签发 JWT（用于授权码兑换 token）
func (s *authService) IssueToken(ctx context.Context, userID int64) (string, error) {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return "", err
	}
	return s.tokenService.GenerateToken(user.ID, user.Role)
}

// generateRefreshTokenString 生成 32 字节随机 hex 字符串
func generateRefreshTokenString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *authService) IssueRefreshToken(ctx context.Context, userID int64, expiry time.Duration) (string, error) {
	tokenStr, err := generateRefreshTokenString()
	if err != nil {
		return "", err
	}
	rt := &domain.RefreshToken{
		UserID:    userID,
		Token:     tokenStr,
		ExpiresAt: time.Now().Add(expiry),
	}
	if err := s.refreshTokenRepo.Save(ctx, rt); err != nil {
		return "", fmt.Errorf("failed to save refresh token: %w", err)
	}
	return tokenStr, nil
}

func (s *authService) RefreshAccessToken(ctx context.Context, refreshToken string, refreshExpiry time.Duration) (string, string, error) {
	rt, err := s.refreshTokenRepo.FindByToken(ctx, refreshToken)
	if err != nil {
		return "", "", errors.New("invalid or expired refresh token")
	}
	user, err := s.repo.FindByID(ctx, rt.UserID)
	if err != nil {
		return "", "", domain.ErrUserNotFound
	}
	// 签发新 access_token
	accessToken, err := s.tokenService.GenerateToken(user.ID, user.Role)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}
	// 轮换 refresh token：删除旧的，生成新的
	if err := s.refreshTokenRepo.DeleteByToken(ctx, refreshToken); err != nil {
		return "", "", fmt.Errorf("failed to revoke old refresh token: %w", err)
	}
	newRefreshToken, err := s.IssueRefreshToken(ctx, user.ID, refreshExpiry)
	if err != nil {
		return "", "", err
	}
	return accessToken, newRefreshToken, nil
}

func (s *authService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	return s.refreshTokenRepo.DeleteByToken(ctx, refreshToken)
}

func (s *authService) RevokeAllRefreshTokens(ctx context.Context, userID int64) error {
	return s.refreshTokenRepo.DeleteByUserID(ctx, userID)
}
