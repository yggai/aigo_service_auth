package main

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// Example 展示如何使用用户管理和权限系统
func Example(db *gorm.DB) {
	// 1. 初始化服务
	userService := NewUserService(db)
	tokenService := NewTokenService("your-secret-key", 24*time.Hour)
	authService := NewAuthService(db, userService, tokenService)
	roleService := NewRoleService(db)

	// 2. 创建角色和权限
	adminRole := &Role{
		Name:        "admin",
		DisplayName: "管理员",
		Description: "系统管理员角色",
		Status:      1,
	}
	roleService.CreateRole(adminRole)

	userRole := &Role{
		Name:        "user",
		DisplayName: "普通用户",
		Description: "普通用户角色",
		Status:      1,
	}
	roleService.CreateRole(userRole)

	// 创建权限
	permissions := []*Permission{
		{
			Name:        "user.create",
			DisplayName: "创建用户",
			Resource:    "user",
			Action:      "create",
			Description: "创建新用户的权限",
		},
		{
			Name:        "user.read",
			DisplayName: "查看用户",
			Resource:    "user",
			Action:      "read",
			Description: "查看用户信息的权限",
		},
		{
			Name:        "user.update",
			DisplayName: "更新用户",
			Resource:    "user",
			Action:      "update",
			Description: "更新用户信息的权限",
		},
		{
			Name:        "user.delete",
			DisplayName: "删除用户",
			Resource:    "user",
			Action:      "delete",
			Description: "删除用户的权限",
		},
	}

	for _, permission := range permissions {
		roleService.CreatePermission(permission)
	}

	// 3. 为角色分配权限
	// 管理员拥有所有权限
	for i := uint(1); i <= 4; i++ {
		roleService.AssignPermissionToRole(adminRole.ID, i)
	}

	// 普通用户只能查看
	roleService.AssignPermissionToRole(userRole.ID, 2) // user.read

	// 4. 创建用户
	user := &User{
		Username:     "admin",
		Email:        "admin@example.com",
		PasswordHash: "admin123", // 会自动哈希
		Status:       1,
	}
	userService.CreateUser(user)

	// 5. 为用户分配角色
	roleService.AssignRoleToUser(user.ID, adminRole.ID)

	// 6. 用户登录
	loginUser, token, err := authService.Login("admin", "admin123")
	if err != nil {
		fmt.Printf("登录失败: %v\n", err)
		return
	}
	fmt.Printf("登录成功，用户: %s, Token: %s\n", loginUser.Username, token)

	// 7. 验证权限
	hasPermission, err := roleService.HasPermission(user.ID, "user", "create")
	if err != nil {
		fmt.Printf("权限检查失败: %v\n", err)
		return
	}
	fmt.Printf("用户是否有创建用户权限: %v\n", hasPermission)

	// 8. 验证角色
	hasRole, err := roleService.HasRole(user.ID, "admin")
	if err != nil {
		fmt.Printf("角色检查失败: %v\n", err)
		return
	}
	fmt.Printf("用户是否是管理员: %v\n", hasRole)
}

// InitDatabase 初始化数据库表
func InitDatabase(db *gorm.DB) error {
	// 自动迁移所有表
	return db.AutoMigrate(
		&User{},
		&Role{},
		&Permission{},
		&UserRole{},
		&RolePermission{},
	)
}
