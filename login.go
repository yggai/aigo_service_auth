package main

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// LoginService 登录服务接口
type LoginService interface {
	// 用户登录
	Login(username, password string) (*User, string, error)
	// 验证Token
	ValidateToken(token string) (*User, error)
	// 刷新Token
	RefreshToken(token string) (string, error)
	// 用户登出
	Logout(token string) error
}

// loginService 登录服务实现
type loginService struct {
	db           *gorm.DB
	userService  UserService
	tokenService TokenService
	authService  AuthService
}

// NewLoginService 创建登录服务实例
func NewLoginService(db *gorm.DB, userService UserService, tokenService TokenService, authService AuthService) LoginService {
	return &loginService{
		db:           db,
		userService:  userService,
		tokenService: tokenService,
		authService:  authService,
	}
}

// Login 用户登录
func (s *loginService) Login(username, password string) (*User, string, error) {
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
	authServiceImpl, ok := s.authService.(*authService)
	if !ok {
		return nil, "", errors.New("认证服务类型错误")
	}

	valid, err := authServiceImpl.VerifyPassword(password, user.PasswordHash)
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
func (s *loginService) ValidateToken(token string) (*User, error) {
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
func (s *loginService) RefreshToken(token string) (string, error) {
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
func (s *loginService) Logout(token string) error {
	return s.tokenService.RevokeToken(token)
}
