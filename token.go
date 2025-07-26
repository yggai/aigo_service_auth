package main

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenService Token服务接口
type TokenService interface {
	// 生成Token
	GenerateToken(userID uint) (string, error)
	// 验证Token
	ValidateToken(tokenString string) (uint, error)
	// 撤销Token
	RevokeToken(tokenString string) error
	// 清理过期Token
	CleanupExpiredTokens() error
}

// Claims JWT声明
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

// tokenService Token服务实现
type tokenService struct {
	secretKey     []byte
	expiration    time.Duration
	revokedTokens map[string]bool // 简化实现，实际应该使用Redis等
}

// NewTokenService 创建Token服务实例
func NewTokenService(secretKey string, expiration time.Duration) TokenService {
	return &tokenService{
		secretKey:     []byte(secretKey),
		expiration:    expiration,
		revokedTokens: make(map[string]bool),
	}
}

// GenerateToken 生成Token
func (s *tokenService) GenerateToken(userID uint) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secretKey)
}

// ValidateToken 验证Token
func (s *tokenService) ValidateToken(tokenString string) (uint, error) {
	// 检查Token是否被撤销
	if s.revokedTokens[tokenString] {
		return 0, errors.New("token已被撤销")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("无效的签名方法")
		}
		return s.secretKey, nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims.UserID, nil
	}

	return 0, errors.New("无效的token")
}

// RevokeToken 撤销Token
func (s *tokenService) RevokeToken(tokenString string) error {
	s.revokedTokens[tokenString] = true
	return nil
}

// CleanupExpiredTokens 清理过期Token
func (s *tokenService) CleanupExpiredTokens() error {
	// 简化实现，实际应该定期清理过期的撤销Token
	// 这里可以解析每个撤销的token，检查是否过期，如果过期则从map中删除
	return nil
}
