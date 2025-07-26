package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
)

// AuthService 认证服务接口
type AuthService interface {
	// 用户登录
	Login(username, password string) (*User, string, error)
	// 验证Token
	ValidateToken(token string) (*User, error)
	// 刷新Token
	RefreshToken(token string) (string, error)
	// 用户登出
	Logout(token string) error
	// 修改密码
	ChangePassword(userID uint, oldPassword, newPassword string) error
	// 重置密码
	ResetPassword(email string) (string, error)
	// 验证重置码并设置新密码
	ConfirmPasswordReset(resetCode, newPassword string) error
}

// PasswordConfig 密码配置
type PasswordConfig struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultPasswordConfig 默认密码配置
var DefaultPasswordConfig = &PasswordConfig{
	Time:    1,
	Memory:  64 * 1024,
	Threads: 4,
	KeyLen:  32,
	SaltLen: 16,
}

// authService 认证服务实现
type authService struct {
	db             *gorm.DB
	userService    UserService
	tokenService   TokenService
	passwordConfig *PasswordConfig
}

// NewAuthService 创建认证服务实例
func NewAuthService(db *gorm.DB, userService UserService, tokenService TokenService) AuthService {
	return &authService{
		db:             db,
		userService:    userService,
		tokenService:   tokenService,
		passwordConfig: DefaultPasswordConfig,
	}
}

// HashPassword 哈希密码
func (s *authService) HashPassword(password string) (string, error) {
	salt := make([]byte, s.passwordConfig.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, s.passwordConfig.Time, s.passwordConfig.Memory, s.passwordConfig.Threads, s.passwordConfig.KeyLen)

	// 编码为base64字符串
	encoded := base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	return encoded, nil
}

// VerifyPassword 验证密码
func (s *authService) VerifyPassword(password, hashedPassword string) (bool, error) {
	parts := []byte(hashedPassword)

	// 查找分隔符
	sepIndex := -1
	for i, b := range parts {
		if b == '$' {
			sepIndex = i
			break
		}
	}

	if sepIndex == -1 {
		return false, errors.New("invalid hash format")
	}

	salt, err := base64.RawStdEncoding.DecodeString(string(parts[:sepIndex]))
	if err != nil {
		return false, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(string(parts[sepIndex+1:]))
	if err != nil {
		return false, err
	}

	// 计算提供密码的哈希
	computedHash := argon2.IDKey([]byte(password), salt, s.passwordConfig.Time, s.passwordConfig.Memory, s.passwordConfig.Threads, s.passwordConfig.KeyLen)

	// 使用constant time比较防止时序攻击
	return subtle.ConstantTimeCompare(hash, computedHash) == 1, nil
}

// Login 用户登录
func (s *authService) Login(username, password string) (*User, string, error) {
	// 获取用户
	user, err := s.userService.GetUserByUsername(username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", errors.New("用户名或密码错误")
		}
		return nil, "", err
	}

	// 检查用户状态
	if user.Status != 1 {
		return nil, "", errors.New("用户已被禁用")
	}

	// 验证密码
	valid, err := s.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		return nil, "", err
	}
	if !valid {
		return nil, "", errors.New("用户名或密码错误")
	}

	// 生成Token
	token, err := s.tokenService.GenerateToken(user.ID)
	if err != nil {
		return nil, "", err
	}

	// 更新最后登录时间
	now := time.Now()
	user.LastLoginAt = &now
	s.userService.UpdateUser(user)

	return user, token, nil
}

// ValidateToken 验证Token
func (s *authService) ValidateToken(token string) (*User, error) {
	userID, err := s.tokenService.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	user, err := s.userService.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	// 检查用户状态
	if user.Status != 1 {
		return nil, errors.New("用户已被禁用")
	}

	return user, nil
}

// RefreshToken 刷新Token
func (s *authService) RefreshToken(token string) (string, error) {
	userID, err := s.tokenService.ValidateToken(token)
	if err != nil {
		return "", err
	}

	// 生成新Token
	newToken, err := s.tokenService.GenerateToken(userID)
	if err != nil {
		return "", err
	}

	// 使旧Token失效
	s.tokenService.RevokeToken(token)

	return newToken, nil
}

// Logout 用户登出
func (s *authService) Logout(token string) error {
	return s.tokenService.RevokeToken(token)
}

// ChangePassword 修改密码
func (s *authService) ChangePassword(userID uint, oldPassword, newPassword string) error {
	user, err := s.userService.GetUserByID(userID)
	if err != nil {
		return err
	}

	// 验证旧密码
	valid, err := s.VerifyPassword(oldPassword, user.PasswordHash)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("原密码错误")
	}

	// 哈希新密码
	hashedPassword, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// 更新密码
	user.PasswordHash = hashedPassword
	return s.userService.UpdateUser(user)
}

// ResetPassword 重置密码
func (s *authService) ResetPassword(email string) (string, error) {
	_, err := s.userService.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", errors.New("邮箱不存在")
		}
		return "", err
	}

	// 生成重置码
	resetCode := s.generateResetCode()

	// 存储重置码（这里简化处理，实际应该存储到缓存或数据库中）
	// TODO: 实现重置码存储逻辑

	return resetCode, nil
}

// ConfirmPasswordReset 验证重置码并设置新密码
func (s *authService) ConfirmPasswordReset(resetCode, newPassword string) error {
	// TODO: 实现重置码验证逻辑
	// 这里应该从缓存或数据库中验证重置码的有效性

	// 哈希新密码
	hashedPassword, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// 更新用户密码
	// TODO: 根据重置码找到对应用户并更新密码
	_ = hashedPassword

	return errors.New("功能待实现")
}

// generateResetCode 生成重置码
func (s *authService) generateResetCode() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}
