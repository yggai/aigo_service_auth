package main

import (
	"fmt"
	"os"
	"testing"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// TestDB 测试数据库管理器
type TestDB struct {
	DB       *gorm.DB
	TestName string
}

// SetupTestDB 设置测试数据库
func SetupTestDB(t *testing.T) *TestDB {
	// 获取数据库连接信息
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		dsn = "test:test#$%^1234567888@tcp(127.0.0.1:13307)/test?charset=utf8mb4&parseTime=True&loc=Local"
	}

	// 连接数据库
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Skipf("无法连接到MySQL数据库: %v。请确保MySQL服务器正在运行并可以访问。", err)
	}

	// 验证数据库连接
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("无法获取数据库实例: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("无法ping通数据库: %v", err)
	}

	testDB := &TestDB{
		DB:       db,
		TestName: t.Name(),
	}

	// 清理数据库
	testDB.CleanupDB()

	// 自动迁移表结构
	err = db.AutoMigrate(&User{}, &Role{}, &Permission{}, &UserRole{}, &RolePermission{})
	if err != nil {
		t.Fatalf("表迁移失败: %v", err)
	}

	return testDB
}

// CleanupDB 清理数据库
func (tdb *TestDB) CleanupDB() {
	// 禁用外键检查
	tdb.DB.Exec("SET FOREIGN_KEY_CHECKS = 0")

	// 按正确顺序删除表以避免外键约束问题
	tables := []string{
		"sys_user_roles",
		"sys_role_permissions",
		"sys_users",
		"sys_roles",
		"sys_permissions",
	}

	for _, table := range tables {
		tdb.DB.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table))
	}

	// 重新启用外键检查
	tdb.DB.Exec("SET FOREIGN_KEY_CHECKS = 1")
}

// TeardownTestDB 清理测试数据库
func (tdb *TestDB) TeardownTestDB() {
	// 清理所有测试数据
	tdb.ClearAllData()
}

// ClearAllData 清理所有数据但保留表结构
func (tdb *TestDB) ClearAllData() {
	// 禁用外键检查
	tdb.DB.Exec("SET FOREIGN_KEY_CHECKS = 0")

	// 清理所有表数据
	tables := []string{
		"sys_user_roles",
		"sys_role_permissions",
		"sys_users",
		"sys_roles",
		"sys_permissions",
	}

	for _, table := range tables {
		tdb.DB.Exec(fmt.Sprintf("DELETE FROM %s", table))
		// 重置自增ID
		tdb.DB.Exec(fmt.Sprintf("ALTER TABLE %s AUTO_INCREMENT = 1", table))
	}

	// 重新启用外键检查
	tdb.DB.Exec("SET FOREIGN_KEY_CHECKS = 1")
}

// CreateTestUser 创建测试用户
func (tdb *TestDB) CreateTestUser(username, email, password string) *User {
	// 使用UserService创建用户，这样密码会被正确哈希
	userService := NewUserService(tdb.DB)

	user := &User{
		Username:     username,
		Email:        email,
		PasswordHash: password, // UserService会自动哈希
		Status:       1,
	}

	err := userService.CreateUser(user)
	if err != nil {
		panic(fmt.Sprintf("创建测试用户失败: %v", err))
	}

	return user
}

// CreateTestRole 创建测试角色
func (tdb *TestDB) CreateTestRole(name, displayName, description string) *Role {
	role := &Role{
		Name:        name,
		DisplayName: displayName,
		Description: description,
		Status:      1,
	}

	result := tdb.DB.Create(role)
	if result.Error != nil {
		panic(fmt.Sprintf("创建测试角色失败: %v", result.Error))
	}

	return role
}

// CreateTestPermission 创建测试权限
func (tdb *TestDB) CreateTestPermission(name, displayName, resource, action string) *Permission {
	permission := &Permission{
		Name:        name,
		DisplayName: displayName,
		Resource:    resource,
		Action:      action,
	}

	result := tdb.DB.Create(permission)
	if result.Error != nil {
		panic(fmt.Sprintf("创建测试权限失败: %v", result.Error))
	}

	return permission
}
