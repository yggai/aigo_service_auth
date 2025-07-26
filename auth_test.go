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

	t.Run("用户注册成功", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试用户注册
		user, token, err := authService.Register("newuser", "newuser@example.com", "password123", "")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.NotEmpty(t, token)
		assert.Equal(t, "newuser", user.Username)
		assert.Equal(t, "newuser@example.com", user.Email)
		assert.Equal(t, uint8(1), user.Status)
		assert.NotNil(t, user.LastLoginAt)

		// 验证用户已保存到数据库
		savedUser, err := userService.GetUserByUsername("newuser")
		assert.NoError(t, err)
		assert.Equal(t, user.ID, savedUser.ID)
	})

	t.Run("用户注册成功-带邀请码", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试带邀请码的用户注册
		user, token, err := authService.Register("inviteduser", "invited@example.com", "password123", "12345678")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.NotEmpty(t, token)
		assert.Equal(t, "inviteduser", user.Username)
		assert.Equal(t, "12345678", user.InvitationCode)
	})

	t.Run("用户注册失败-用户名已存在", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 先注册一个用户
		_, _, err := authService.Register("existinguser", "existing@example.com", "password123", "")
		assert.NoError(t, err)

		// 尝试注册相同用户名的用户
		_, _, err = authService.Register("existinguser", "different@example.com", "password123", "")
		assert.Error(t, err)
		assert.Equal(t, "用户名已存在", err.Error())
	})

	t.Run("用户注册失败-邮箱已存在", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 先注册一个用户
		_, _, err := authService.Register("user1", "same@example.com", "password123", "")
		assert.NoError(t, err)

		// 尝试注册相同邮箱的用户
		_, _, err = authService.Register("user2", "same@example.com", "password123", "")
		assert.Error(t, err)
		assert.Equal(t, "邮箱已存在", err.Error())
	})

	t.Run("用户注册失败-无效邀请码", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 尝试使用无效邀请码注册
		_, _, err := authService.Register("user", "user@example.com", "password123", "invalid")
		assert.Error(t, err)
		assert.Equal(t, "邀请码无效", err.Error())
	})

	t.Run("注册后可以正常登录", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 注册用户
		registerUser, registerToken, err := authService.Register("logintest", "logintest@example.com", "password123", "")
		assert.NoError(t, err)
		assert.NotEmpty(t, registerToken)

		// 等待1秒确保时间戳不同
		time.Sleep(time.Second)

		// 使用注册的用户名和密码登录
		loginUser, loginToken, err := authService.Login("logintest", "password123")
		assert.NoError(t, err)
		assert.Equal(t, registerUser.ID, loginUser.ID)
		assert.NotEmpty(t, loginToken)
		// 由于时间戳不同，Token应该不同
		assert.NotEqual(t, registerToken, loginToken)
	})

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
