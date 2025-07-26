package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthService(t *testing.T) {
	// 设置测试数据库
	testDB := SetupTestDB(t)
	defer testDB.TeardownTestDB()

	// 创建服务实例
	userService := NewUserService(testDB.DB)
	tokenService := NewTokenService("test-secret-key", time.Hour)
	authService := NewAuthService(testDB.DB, userService, tokenService)

	t.Run("用户登录成功", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		user := testDB.CreateTestUser("testuser", "test@example.com", password)

		// 测试登录成功（间接测试密码哈希和验证）
		loginUser, token, err := authService.Login("testuser", password)
		assert.NoError(t, err)
		assert.Equal(t, user.Username, loginUser.Username)
		assert.NotEmpty(t, token)
	})

	t.Run("用户登录失败-错误密码", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		testDB.CreateTestUser("testuser", "test@example.com", password)

		// 测试登录失败 - 错误密码
		_, _, err := authService.Login("testuser", "wrongpassword")
		assert.Error(t, err)
		assert.Equal(t, "用户名或密码错误", err.Error())
	})

	t.Run("用户登录失败-用户不存在", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试登录失败 - 用户不存在
		_, _, err := authService.Login("nonexistent", "password")
		assert.Error(t, err)
		assert.Equal(t, "用户名或密码错误", err.Error())
	})

	t.Run("Token验证", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		user := testDB.CreateTestUser("testuser", "test@example.com", password)

		// 登录获取Token
		_, token, err := authService.Login("testuser", password)
		assert.NoError(t, err)

		// 测试Token验证
		validatedUser, err := authService.ValidateToken(token)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, validatedUser.ID)
	})

	t.Run("Token刷新", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		testDB.CreateTestUser("testuser", "test@example.com", password)

		// 登录获取Token
		_, token, err := authService.Login("testuser", password)
		assert.NoError(t, err)

		// 等待1秒确保时间戳不同
		time.Sleep(time.Second)

		// 测试Token刷新
		newToken, err := authService.RefreshToken(token)
		assert.NoError(t, err)
		assert.NotEmpty(t, newToken)
		assert.NotEqual(t, token, newToken)
	})

	t.Run("用户登出", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		testDB.CreateTestUser("testuser", "test@example.com", password)

		// 登录获取Token
		_, token, err := authService.Login("testuser", password)
		assert.NoError(t, err)

		// 测试登出
		err = authService.Logout(token)
		assert.NoError(t, err)
	})

	t.Run("修改密码", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		user := testDB.CreateTestUser("testuser", "test@example.com", password)

		// 测试修改密码
		newPassword := "newpassword123"
		err := authService.ChangePassword(user.ID, password, newPassword)
		assert.NoError(t, err)

		// 验证新密码可以登录
		_, _, err = authService.Login("testuser", newPassword)
		assert.NoError(t, err)

		// 验证旧密码不能登录
		_, _, err = authService.Login("testuser", password)
		assert.Error(t, err)
	})

	t.Run("用户状态检查", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		user := testDB.CreateTestUser("testuser", "test@example.com", password)

		// 禁用用户
		user.Status = 2
		userService.UpdateUser(user)

		// 测试禁用用户无法登录
		_, _, err := authService.Login("testuser", password)
		assert.Error(t, err)
		assert.Equal(t, "用户已被禁用", err.Error())
	})
}
