package main

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

// Role 角色模型
type Role struct {
	gorm.Model
	Name        string `gorm:"size:50;uniqueIndex;not null" json:"name"`
	DisplayName string `gorm:"size:100;not null" json:"display_name"`
	Description string `gorm:"size:255" json:"description,omitempty"`
	Status      uint8  `gorm:"default:1;comment:'1-正常,2-禁用'" json:"status"`
}

// Permission 权限模型
type Permission struct {
	gorm.Model
	Name        string `gorm:"size:100;uniqueIndex;not null" json:"name"`
	DisplayName string `gorm:"size:100;not null" json:"display_name"`
	Resource    string `gorm:"size:100;not null" json:"resource"`
	Action      string `gorm:"size:50;not null" json:"action"`
	Description string `gorm:"size:255" json:"description,omitempty"`
}

// UserRole 用户角色关联
type UserRole struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"not null;index" json:"user_id"`
	RoleID    uint      `gorm:"not null;index" json:"role_id"`
	CreatedAt time.Time `json:"created_at"`
	User      User      `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Role      Role      `gorm:"foreignKey:RoleID" json:"role,omitempty"`
}

// RolePermission 角色权限关联
type RolePermission struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	RoleID       uint       `gorm:"not null;index" json:"role_id"`
	PermissionID uint       `gorm:"not null;index" json:"permission_id"`
	CreatedAt    time.Time  `json:"created_at"`
	Role         Role       `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	Permission   Permission `gorm:"foreignKey:PermissionID" json:"permission,omitempty"`
}

// TableName 设置表名
func (Role) TableName() string {
	return "sys_roles"
}

func (Permission) TableName() string {
	return "sys_permissions"
}

func (UserRole) TableName() string {
	return "sys_user_roles"
}

func (RolePermission) TableName() string {
	return "sys_role_permissions"
}

// RoleService 角色服务接口
type RoleService interface {
	// 角色管理
	CreateRole(role *Role) error
	GetRoleByID(id uint) (*Role, error)
	GetRoleByName(name string) (*Role, error)
	UpdateRole(role *Role) error
	DeleteRole(id uint) error
	ListRoles(page, pageSize int) ([]*Role, int64, error)

	// 权限管理
	CreatePermission(permission *Permission) error
	GetPermissionByID(id uint) (*Permission, error)
	ListPermissions(page, pageSize int) ([]*Permission, int64, error)

	// 角色权限关联
	AssignPermissionToRole(roleID, permissionID uint) error
	RemovePermissionFromRole(roleID, permissionID uint) error
	GetRolePermissions(roleID uint) ([]*Permission, error)

	// 用户角色关联
	AssignRoleToUser(userID, roleID uint) error
	RemoveRoleFromUser(userID, roleID uint) error
	GetUserRoles(userID uint) ([]*Role, error)
	GetUsersWithRole(roleID uint) ([]*User, error)

	// 权限验证
	HasPermission(userID uint, resource, action string) (bool, error)
	HasRole(userID uint, roleName string) (bool, error)
}

// roleService 角色服务实现
type roleService struct {
	db *gorm.DB
}

// NewRoleService 创建角色服务实例
func NewRoleService(db *gorm.DB) RoleService {
	return &roleService{db: db}
}

// CreateRole 创建角色
func (s *roleService) CreateRole(role *Role) error {
	// 检查角色名是否已存在
	var existingRole Role
	err := s.db.Where("name = ?", role.Name).First(&existingRole).Error
	if err == nil {
		return errors.New("角色名已存在")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	return s.db.Create(role).Error
}

// GetRoleByID 根据ID获取角色
func (s *roleService) GetRoleByID(id uint) (*Role, error) {
	var role Role
	if err := s.db.First(&role, id).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

// GetRoleByName 根据名称获取角色
func (s *roleService) GetRoleByName(name string) (*Role, error) {
	var role Role
	if err := s.db.Where("name = ?", name).First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateRole 更新角色
func (s *roleService) UpdateRole(role *Role) error {
	return s.db.Save(role).Error
}

// DeleteRole 删除角色
func (s *roleService) DeleteRole(id uint) error {
	// 检查是否有用户使用该角色
	var count int64
	s.db.Model(&UserRole{}).Where("role_id = ?", id).Count(&count)
	if count > 0 {
		return errors.New("该角色正在被使用，无法删除")
	}

	// 删除角色权限关联
	s.db.Where("role_id = ?", id).Delete(&RolePermission{})

	// 删除角色
	return s.db.Delete(&Role{}, id).Error
}

// ListRoles 分页获取角色列表
func (s *roleService) ListRoles(page, pageSize int) ([]*Role, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}

	var roles []*Role
	var total int64

	if err := s.db.Model(&Role{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := s.db.Offset(offset).Limit(pageSize).Find(&roles).Error; err != nil {
		return nil, 0, err
	}

	return roles, total, nil
}

// CreatePermission 创建权限
func (s *roleService) CreatePermission(permission *Permission) error {
	// 检查权限名是否已存在
	var existingPermission Permission
	err := s.db.Where("name = ?", permission.Name).First(&existingPermission).Error
	if err == nil {
		return errors.New("权限名已存在")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	return s.db.Create(permission).Error
}

// GetPermissionByID 根据ID获取权限
func (s *roleService) GetPermissionByID(id uint) (*Permission, error) {
	var permission Permission
	if err := s.db.First(&permission, id).Error; err != nil {
		return nil, err
	}
	return &permission, nil
}

// ListPermissions 分页获取权限列表
func (s *roleService) ListPermissions(page, pageSize int) ([]*Permission, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}

	var permissions []*Permission
	var total int64

	if err := s.db.Model(&Permission{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := s.db.Offset(offset).Limit(pageSize).Find(&permissions).Error; err != nil {
		return nil, 0, err
	}

	return permissions, total, nil
}

// AssignPermissionToRole 为角色分配权限
func (s *roleService) AssignPermissionToRole(roleID, permissionID uint) error {
	// 检查是否已经分配
	var existing RolePermission
	err := s.db.Where("role_id = ? AND permission_id = ?", roleID, permissionID).First(&existing).Error
	if err == nil {
		return errors.New("权限已分配给该角色")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	rolePermission := &RolePermission{
		RoleID:       roleID,
		PermissionID: permissionID,
		CreatedAt:    time.Now(),
	}

	return s.db.Create(rolePermission).Error
}

// RemovePermissionFromRole 从角色移除权限
func (s *roleService) RemovePermissionFromRole(roleID, permissionID uint) error {
	return s.db.Where("role_id = ? AND permission_id = ?", roleID, permissionID).Delete(&RolePermission{}).Error
}

// GetRolePermissions 获取角色的所有权限
func (s *roleService) GetRolePermissions(roleID uint) ([]*Permission, error) {
	var permissions []*Permission
	err := s.db.Table("sys_permissions p").
		Joins("JOIN sys_role_permissions rp ON p.id = rp.permission_id").
		Where("rp.role_id = ?", roleID).
		Find(&permissions).Error
	return permissions, err
}

// AssignRoleToUser 为用户分配角色
func (s *roleService) AssignRoleToUser(userID, roleID uint) error {
	// 检查是否已经分配
	var existing UserRole
	err := s.db.Where("user_id = ? AND role_id = ?", userID, roleID).First(&existing).Error
	if err == nil {
		return errors.New("角色已分配给该用户")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	userRole := &UserRole{
		UserID:    userID,
		RoleID:    roleID,
		CreatedAt: time.Now(),
	}

	return s.db.Create(userRole).Error
}

// RemoveRoleFromUser 从用户移除角色
func (s *roleService) RemoveRoleFromUser(userID, roleID uint) error {
	return s.db.Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&UserRole{}).Error
}

// GetUserRoles 获取用户的所有角色
func (s *roleService) GetUserRoles(userID uint) ([]*Role, error) {
	var roles []*Role
	err := s.db.Table("sys_roles r").
		Joins("JOIN sys_user_roles ur ON r.id = ur.role_id").
		Where("ur.user_id = ?", userID).
		Find(&roles).Error
	return roles, err
}

// GetUsersWithRole 获取拥有指定角色的所有用户
func (s *roleService) GetUsersWithRole(roleID uint) ([]*User, error) {
	var users []*User
	err := s.db.Table("sys_users u").
		Joins("JOIN sys_user_roles ur ON u.id = ur.user_id").
		Where("ur.role_id = ?", roleID).
		Find(&users).Error
	return users, err
}

// HasPermission 检查用户是否有指定权限
func (s *roleService) HasPermission(userID uint, resource, action string) (bool, error) {
	var count int64
	err := s.db.Table("sys_permissions p").
		Joins("JOIN sys_role_permissions rp ON p.id = rp.permission_id").
		Joins("JOIN sys_user_roles ur ON rp.role_id = ur.role_id").
		Where("ur.user_id = ? AND p.resource = ? AND p.action = ?", userID, resource, action).
		Count(&count).Error

	return count > 0, err
}

// HasRole 检查用户是否有指定角色
func (s *roleService) HasRole(userID uint, roleName string) (bool, error) {
	var count int64
	err := s.db.Table("sys_roles r").
		Joins("JOIN sys_user_roles ur ON r.id = ur.role_id").
		Where("ur.user_id = ? AND r.name = ?", userID, roleName).
		Count(&count).Error

	return count > 0, err
}
