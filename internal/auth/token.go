package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims 定义了 JWT 的负载 (Payload)
type Claims struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// TokenService 定义了令牌操作接口
type TokenService interface {
	GenerateToken(userID int64, role string) (string, error)
	ValidateToken(tokenString string) (*Claims, error)
}

type jwtService struct {
	secret string
	expiry time.Duration
}

// NewJWTService 创建 JWT 服务的实例
func NewJWTService(secret string, expiry time.Duration) TokenService {
	return &jwtService{
		secret: secret,
		expiry: expiry,
	}
}

// GenerateToken 生成 JWT
func (s *jwtService) GenerateToken(userID int64, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secret))
}

// ValidateToken 校验 JWT
func (s *jwtService) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.secret), nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid or expired token")
	}
	return claims, nil
}
