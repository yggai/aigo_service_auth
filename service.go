package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
)

// UserService 用户服务接口
type UserService interface {
	// 创建用户
	CreateUser(user *User) error
	// 根据ID获取用户
	GetUserByID(id uint) (*User, error)
	// 根据用户名获取用户
	GetUserByUsername(username string) (*User, error)
	// 根据邮箱获取用户
	GetUserByEmail(email string) (*User, error)
	// 更新用户
	UpdateUser(user *User) error
	// 删除用户
	DeleteUser(id uint) error
	// 分页获取用户列表
	ListUsers(page, pageSize int) ([]*User, int64, error)
	// 验证邀请码是否有效
	ValidateInvitationCode(code string) (bool, error)
}

// userService 用户服务实现
type userService struct {
	db *gorm.DB
}

// NewUserService 创建用户服务实例
func NewUserService(db *gorm.DB) UserService {
	return &userService{
		db: db,
	}
}

// CreateUser 创建用户
func (s *userService) CreateUser(user *User) error {
	// 检查用户名是否已存在
	var existingUser User
	err := s.db.Where("username = ?", user.Username).First(&existingUser).Error
	if err == nil {
		return errors.New("用户名已存在")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// 检查邮箱是否已存在
	err = s.db.Where("email = ?", user.Email).First(&existingUser).Error
	if err == nil {
		return errors.New("邮箱已存在")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// 如果提供了邀请码，验证邀请码
	if user.InvitationCode != "" {
		valid, err := s.ValidateInvitationCode(user.InvitationCode)
		if err != nil {
			return err
		}
		if !valid {
			return errors.New("邀请码无效")
		}
	}

	// 如果密码未哈希，则进行哈希处理
	if user.PasswordHash != "" && !s.isPasswordHashed(user.PasswordHash) {
		hashedPassword, err := s.hashPassword(user.PasswordHash)
		if err != nil {
			return err
		}
		user.PasswordHash = hashedPassword
	}

	// 设置创建时间
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	// 保存用户
	return s.db.Create(user).Error
}

// GetUserByID 根据ID获取用户
func (s *userService) GetUserByID(id uint) (*User, error) {
	var user User
	if err := s.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername 根据用户名获取用户
func (s *userService) GetUserByUsername(username string) (*User, error) {
	var user User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByEmail 根据邮箱获取用户
func (s *userService) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUser 更新用户
func (s *userService) UpdateUser(user *User) error {
	// 检查用户是否存在
	var existingUser User
	if err := s.db.First(&existingUser, user.ID).Error; err != nil {
		return err
	}

	// 更新时间
	user.UpdatedAt = time.Now()

	// 更新用户
	return s.db.Save(user).Error
}

// DeleteUser 删除用户
func (s *userService) DeleteUser(id uint) error {
	// 检查用户是否存在
	var user User
	if err := s.db.First(&user, id).Error; err != nil {
		return err
	}

	// 删除用户（软删除）
	return s.db.Delete(&user).Error
}

// ListUsers 分页获取用户列表
func (s *userService) ListUsers(page, pageSize int) ([]*User, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}

	var users []*User
	var total int64

	// 获取总数
	if err := s.db.Model(&User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	if err := s.db.Offset(offset).Limit(pageSize).Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// ValidateInvitationCode 验证邀请码是否有效
func (s *userService) ValidateInvitationCode(code string) (bool, error) {
	// 这里应该实现邀请码验证逻辑
	// 实际项目中，邀请码可能存储在单独的表中
	// 这里简化处理，假设邀请码格式正确且未被使用
	if len(code) != 8 {
		return false, nil
	}

	// TODO: 实现邀请码验证的具体逻辑
	return true, nil
}

// hashPassword 哈希密码
func (s *userService) hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// 编码为base64字符串
	encoded := base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	return encoded, nil
}

// isPasswordHashed 检查密码是否已经哈希
func (s *userService) isPasswordHashed(password string) bool {
	// 简单检查：哈希后的密码包含$分隔符且长度较长
	return len(password) > 50 && strings.Contains(password, "$")
}
