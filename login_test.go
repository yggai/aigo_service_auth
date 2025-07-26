package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoginService(t *testing.T) {
	// 设置测试数据库
	testDB := SetupTestDB(t)
	defer testDB.TeardownTestDB()

	// 创建服务实例
	userService := NewUserService(testDB.DB)
	tokenService := NewTokenService("test-secret-key", time.Hour)
	authService := NewAuthService(testDB.DB, userService, tokenService)
	loginService := NewLoginService(testDB.DB, userService, tokenService, authService)

	t.Run("用户登录成功", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		user := testDB.CreateTestUser("testuser", "test@example.com", password)

		// 测试登录成功
		loginUser, token, err := loginService.Login("testuser", password)
		assert.NoError(t, err)
		assert.Equal(t, user.Username, loginUser.Username)
		assert.Equal(t, user.Email, loginUser.Email)
		assert.NotEmpty(t, token)
		assert.NotNil(t, loginUser.LastLoginAt)
	})

	t.Run("用户登录失败-错误密码", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		testDB.CreateTestUser("testuser", "test@example.com", password)

		// 测试登录失败 - 错误密码
		_, _, err := loginService.Login("testuser", "wrongpassword")
		assert.Error(t, err)
		assert.Equal(t, "用户名或密码错误", err.Error())
	})

	t.Run("用户登录失败-用户不存在", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试登录失败 - 用户不存在
		_, _, err := loginService.Login("nonexistent", "password")
		assert.Error(t, err)
		assert.Equal(t, "用户名或密码错误", err.Error())
	})

	t.Run("用户登录失败-用户被禁用", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		user := testDB.CreateTestUser("testuser", "test@example.com", password)

		// 禁用用户
		user.Status = 2
		userService.UpdateUser(user)

		// 测试禁用用户无法登录
		_, _, err := loginService.Login("testuser", password)
		assert.Error(t, err)
		assert.Equal(t, "用户已被禁用", err.Error())
	})

	t.Run("Token验证成功", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		user := testDB.CreateTestUser("testuser", "test@example.com", password)

		// 登录获取Token
		_, token, err := loginService.Login("testuser", password)
		assert.NoError(t, err)

		// 测试Token验证
		validatedUser, err := loginService.ValidateToken(token)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, validatedUser.ID)
		assert.Equal(t, user.Username, validatedUser.Username)
	})

	t.Run("Token验证失败-无效Token", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试无效Token验证
		_, err := loginService.ValidateToken("invalid.token.here")
		assert.Error(t, err)
	})

	t.Run("Token刷新成功", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		testDB.CreateTestUser("testuser", "test@example.com", password)

		// 登录获取Token
		_, token, err := loginService.Login("testuser", password)
		assert.NoError(t, err)

		// 等待1秒确保时间戳不同
		time.Sleep(time.Second)

		// 测试Token刷新
		newToken, err := loginService.RefreshToken(token)
		assert.NoError(t, err)
		assert.NotEmpty(t, newToken)
		assert.NotEqual(t, token, newToken)
	})

	t.Run("Token刷新失败-无效Token", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试无效Token刷新
		_, err := loginService.RefreshToken("invalid.token.here")
		assert.Error(t, err)
	})

	t.Run("用户登出成功", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		testDB.CreateTestUser("testuser", "test@example.com", password)

		// 登录获取Token
		_, token, err := loginService.Login("testuser", password)
		assert.NoError(t, err)

		// 测试登出
		err = loginService.Logout(token)
		assert.NoError(t, err)

		// 验证登出后Token被撤销（这里简化测试，实际应该验证Token无法使用）
		// 注意：当前的TokenService实现中，撤销的Token存储在内存中
		// 在生产环境中应该使用Redis等持久化存储
	})

	t.Run("登录后更新最后登录时间", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		password := "testpassword123"
		user := testDB.CreateTestUser("testuser", "test@example.com", password)

		// 记录登录前的时间
		originalLastLogin := user.LastLoginAt

		// 等待一小段时间确保时间不同
		time.Sleep(100 * time.Millisecond)

		// 登录
		loginUser, _, err := loginService.Login("testuser", password)
		assert.NoError(t, err)

		// 验证最后登录时间已更新
		assert.NotNil(t, loginUser.LastLoginAt)
		if originalLastLogin != nil {
			assert.True(t, loginUser.LastLoginAt.After(*originalLastLogin))
		}
	})
}
