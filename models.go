package main

import (
	"time"

	"gorm.io/gorm"
)

// User 用户模型
type User struct {
	gorm.Model
	Username       string     `gorm:"size:50;uniqueIndex;not null" json:"username"`
	Email          string     `gorm:"size:100;uniqueIndex;not null" json:"email"`
	PasswordHash   string     `gorm:"size:255;not null" json:"-"` // 不返回密码哈希
	Phone          string     `gorm:"size:20;index" json:"phone,omitempty"`
	Avatar         string     `gorm:"size:255" json:"avatar,omitempty"`
	Status         uint8      `gorm:"default:1;comment:'1-正常,2-禁用'" json:"status"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
	InvitationCode string     `gorm:"size:50;index" json:"invitation_code,omitempty"`
	InvitedBy      uint       `gorm:"index" json:"invited_by,omitempty"`
}

// TableName 设置表名
func (User) TableName() string {
	return "sys_users"
}

// BeforeCreate 创建前钩子 - 可以添加默认值或验证
func (u *User) BeforeCreate(tx *gorm.DB) error {
	// 可以在这里添加密码哈希处理或其他前置操作
	return nil
}

// BeforeUpdate 更新前钩子
func (u *User) BeforeUpdate(tx *gorm.DB) error {
	// 可以在这里添加更新时的业务逻辑
	return nil
}
