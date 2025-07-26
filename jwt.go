package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTService JWT服务接口
type JWTService interface {
	// 生成Token
	GenerateToken(userID uint) (string, error)
	// 生成带自定义过期时间的Token
	GenerateTokenWithExpiration(userID uint, expiration time.Duration) (string, error)
	// 验证Token
	ValidateToken(tokenString string) (uint, error)
	// 解析Token获取Claims
	ParseToken(tokenString string) (*JWTClaims, error)
	// 撤销Token
	RevokeToken(tokenString string) error
	// 检查Token是否被撤销
	IsTokenRevoked(tokenString string) bool
	// 清理过期的撤销Token
	CleanupExpiredTokens() error
	// 获取Token剩余有效时间
	GetTokenRemainingTime(tokenString string) (time.Duration, error)
	// 刷新Token
	RefreshToken(tokenString string) (string, error)
	// 生成JTI（JWT ID）
	GenerateJTI() string
	// 批量撤销用户的所有Token
	RevokeAllUserTokens(userID uint) error
}

// JWTClaims JWT声明
type JWTClaims struct {
	UserID uint   `json:"user_id"`
	JTI    string `json:"jti"` // JWT ID，用于唯一标识Token
	jwt.RegisteredClaims
}

// JWTConfig JWT配置
type JWTConfig struct {
	SecretKey         string
	DefaultExpiration time.Duration
	RefreshExpiration time.Duration
	Issuer            string
	AllowRefresh      bool
	MaxRefreshCount   int
}

// DefaultJWTConfig 默认JWT配置
func DefaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		SecretKey:         "default-secret-key",
		DefaultExpiration: 24 * time.Hour,
		RefreshExpiration: 7 * 24 * time.Hour,
		Issuer:            "aigo_service_auth",
		AllowRefresh:      true,
		MaxRefreshCount:   5,
	}
}

// jwtService JWT服务实现
type jwtService struct {
	config        *JWTConfig
	secretKey     []byte
	revokedTokens map[string]time.Time // Token -> 撤销时间
	userTokens    map[uint][]string    // 用户ID -> Token列表
	tokenUsers    map[string]uint      // Token -> 用户ID
	refreshCounts map[string]int       // Token -> 刷新次数
	mutex         sync.RWMutex         // 读写锁保护并发访问
}

// NewJWTService 创建JWT服务实例
func NewJWTService(config *JWTConfig) JWTService {
	if config == nil {
		config = DefaultJWTConfig()
	}

	return &jwtService{
		config:        config,
		secretKey:     []byte(config.SecretKey),
		revokedTokens: make(map[string]time.Time),
		userTokens:    make(map[uint][]string),
		tokenUsers:    make(map[string]uint),
		refreshCounts: make(map[string]int),
	}
}

// GenerateJTI 生成JWT ID
func (s *jwtService) GenerateJTI() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateToken 生成Token
func (s *jwtService) GenerateToken(userID uint) (string, error) {
	return s.GenerateTokenWithExpiration(userID, s.config.DefaultExpiration)
}

// GenerateTokenWithExpiration 生成带自定义过期时间的Token
func (s *jwtService) GenerateTokenWithExpiration(userID uint, expiration time.Duration) (string, error) {
	if userID == 0 {
		return "", errors.New("用户ID不能为0")
	}

	if expiration <= 0 {
		return "", errors.New("过期时间必须大于0")
	}

	now := time.Now()
	jti := s.GenerateJTI()

	claims := &JWTClaims{
		UserID: userID,
		JTI:    jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.config.Issuer,
			Subject:   fmt.Sprintf("user:%d", userID),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", fmt.Errorf("生成Token失败: %w", err)
	}

	// 记录用户Token关系
	s.mutex.Lock()
	s.userTokens[userID] = append(s.userTokens[userID], tokenString)
	s.tokenUsers[tokenString] = userID
	s.mutex.Unlock()

	return tokenString, nil
}

// ValidateToken 验证Token
func (s *jwtService) ValidateToken(tokenString string) (uint, error) {
	if tokenString == "" {
		return 0, errors.New("Token不能为空")
	}

	// 检查Token是否被撤销
	if s.IsTokenRevoked(tokenString) {
		return 0, errors.New("Token已被撤销")
	}

	claims, err := s.ParseToken(tokenString)
	if err != nil {
		return 0, err
	}

	return claims.UserID, nil
}

// ParseToken 解析Token获取Claims
func (s *jwtService) ParseToken(tokenString string) (*JWTClaims, error) {
	if tokenString == "" {
		return nil, errors.New("Token不能为空")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("无效的签名方法: %v", token.Header["alg"])
		}
		return s.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("解析Token失败: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("无效的Token")
}

// RevokeToken 撤销Token
func (s *jwtService) RevokeToken(tokenString string) error {
	if tokenString == "" {
		return errors.New("Token不能为空")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.revokedTokens[tokenString] = time.Now()

	// 从用户Token列表中移除
	if userID, exists := s.tokenUsers[tokenString]; exists {
		if tokens, ok := s.userTokens[userID]; ok {
			newTokens := make([]string, 0, len(tokens))
			for _, token := range tokens {
				if token != tokenString {
					newTokens = append(newTokens, token)
				}
			}
			s.userTokens[userID] = newTokens
		}
		delete(s.tokenUsers, tokenString)
	}

	// 清理刷新计数
	delete(s.refreshCounts, tokenString)

	return nil
}

// IsTokenRevoked 检查Token是否被撤销
func (s *jwtService) IsTokenRevoked(tokenString string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	_, revoked := s.revokedTokens[tokenString]
	return revoked
}

// CleanupExpiredTokens 清理过期的撤销Token
func (s *jwtService) CleanupExpiredTokens() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	expiredTokens := make([]string, 0)

	// 找出过期的撤销Token
	for tokenString := range s.revokedTokens {
		claims, err := s.parseTokenUnsafe(tokenString)
		if err != nil || (claims.ExpiresAt != nil && claims.ExpiresAt.Before(now)) {
			expiredTokens = append(expiredTokens, tokenString)
		}
	}

	// 清理过期的撤销Token
	for _, tokenString := range expiredTokens {
		delete(s.revokedTokens, tokenString)
	}

	return nil
}

// parseTokenUnsafe 不安全的Token解析（不验证签名，仅用于内部清理）
func (s *jwtService) parseTokenUnsafe(tokenString string) (*JWTClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok {
		return claims, nil
	}

	return nil, errors.New("无法解析Claims")
}

// GetTokenRemainingTime 获取Token剩余有效时间
func (s *jwtService) GetTokenRemainingTime(tokenString string) (time.Duration, error) {
	claims, err := s.ParseToken(tokenString)
	if err != nil {
		// 如果解析失败且错误信息包含过期相关内容，返回统一的过期错误
		if strings.Contains(err.Error(), "expired") {
			return 0, errors.New("Token已过期")
		}
		return 0, err
	}

	if claims.ExpiresAt == nil {
		return 0, errors.New("Token没有过期时间")
	}

	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining <= 0 {
		return 0, errors.New("Token已过期")
	}

	return remaining, nil
}

// RefreshToken 刷新Token
func (s *jwtService) RefreshToken(tokenString string) (string, error) {
	if !s.config.AllowRefresh {
		return "", errors.New("不允许刷新Token")
	}

	if tokenString == "" {
		return "", errors.New("Token不能为空")
	}

	// 解析原Token
	claims, err := s.ParseToken(tokenString)
	if err != nil {
		return "", fmt.Errorf("解析原Token失败: %w", err)
	}

	// 检查刷新次数
	s.mutex.RLock()
	refreshCount := s.refreshCounts[tokenString]
	s.mutex.RUnlock()

	if refreshCount >= s.config.MaxRefreshCount {
		return "", errors.New("Token刷新次数已达上限")
	}

	// 检查是否在刷新期限内
	if claims.ExpiresAt != nil {
		refreshDeadline := claims.ExpiresAt.Add(-s.config.RefreshExpiration)
		if time.Now().Before(refreshDeadline) {
			return "", errors.New("Token还未到刷新时间")
		}
	}

	// 生成新Token
	newToken, err := s.GenerateToken(claims.UserID)
	if err != nil {
		return "", fmt.Errorf("生成新Token失败: %w", err)
	}

	// 更新刷新计数 - 在撤销原Token之前保存计数
	s.mutex.Lock()
	s.refreshCounts[newToken] = refreshCount + 1
	s.mutex.Unlock()

	// 撤销原Token
	err = s.RevokeToken(tokenString)
	if err != nil {
		// 如果撤销失败，也要清理新Token的刷新计数
		s.mutex.Lock()
		delete(s.refreshCounts, newToken)
		s.mutex.Unlock()
		return "", fmt.Errorf("撤销原Token失败: %w", err)
	}

	return newToken, nil
}

// RevokeAllUserTokens 批量撤销用户的所有Token
func (s *jwtService) RevokeAllUserTokens(userID uint) error {
	if userID == 0 {
		return errors.New("用户ID不能为0")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tokens, exists := s.userTokens[userID]
	if !exists {
		return nil // 用户没有Token，直接返回
	}

	now := time.Now()
	for _, tokenString := range tokens {
		s.revokedTokens[tokenString] = now
		delete(s.tokenUsers, tokenString)
		delete(s.refreshCounts, tokenString)
	}

	// 清空用户Token列表
	delete(s.userTokens, userID)

	return nil
}
