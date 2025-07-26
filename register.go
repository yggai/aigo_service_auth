package main

import (
	"time"
)

// RegisterService 注册服务接口
type RegisterService interface {
	// 用户注册
	Register(username, email, password, invitationCode string) (*User, string, error)
	// 验证用户名是否可用
	IsUsernameAvailable(username string) (bool, error)
	// 验证邮箱是否可用
	IsEmailAvailable(email string) (bool, error)
	// 验证邀请码是否有效
	ValidateInvitationCode(code string) (bool, error)
}

// registerService 注册服务实现
type registerService struct {
	userService  UserService
	tokenService TokenService
}

// NewRegisterService 创建注册服务实例
func NewRegisterService(userService UserService, tokenService TokenService) RegisterService {
	return &registerService{
		userService:  userService,
		tokenService: tokenService,
	}
}

// Register 用户注册
func (s *registerService) Register(username, email, password, invitationCode string) (*User, string, error) {
	// 创建用户对象
	user := &User{
		Username:       username,
		Email:          email,
		PasswordHash:   password, // UserService会自动哈希
		Status:         1,
		InvitationCode: invitationCode,
	}

	// 创建用户
	err := s.userService.CreateUser(user)
	if err != nil {
		return nil, "", err
	}

	// 生成Token
	token, err := s.tokenService.GenerateToken(user.ID)
	if err != nil {
		return nil, "", err
	}

	// 设置注册时间为最后登录时间
	now := time.Now()
	user.LastLoginAt = &now
	s.userService.UpdateUser(user)

	return user, token, nil
}

// IsUsernameAvailable 验证用户名是否可用
func (s *registerService) IsUsernameAvailable(username string) (bool, error) {
	_, err := s.userService.GetUserByUsername(username)
	if err != nil {
		// 如果用户不存在，说明用户名可用
		return true, nil
	}
	// 用户存在，用户名不可用
	return false, nil
}

// IsEmailAvailable 验证邮箱是否可用
func (s *registerService) IsEmailAvailable(email string) (bool, error) {
	_, err := s.userService.GetUserByEmail(email)
	if err != nil {
		// 如果用户不存在，说明邮箱可用
		return true, nil
	}
	// 用户存在，邮箱不可用
	return false, nil
}

// ValidateInvitationCode 验证邀请码是否有效
func (s *registerService) ValidateInvitationCode(code string) (bool, error) {
	return s.userService.ValidateInvitationCode(code)
}
