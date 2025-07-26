package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoginRegisterIntegration(t *testing.T) {
	// 设置测试数据库
	testDB := SetupTestDB(t)
	defer testDB.TeardownTestDB()

	// 创建服务实例
	userService := NewUserService(testDB.DB)
	tokenService := NewTokenService("test-secret-key", time.Hour)
	authService := NewAuthService(testDB.DB, userService, tokenService)
	registerService := NewRegisterService(userService, tokenService)
	loginService := NewLoginService(testDB.DB, userService, tokenService, authService)

	t.Run("完整的注册登录流程", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		username := "integrationuser"
		email := "integration@example.com"
		password := "password123"
		invitationCode := "12345678"

		// 1. 验证用户名和邮箱可用
		usernameAvailable, err := registerService.IsUsernameAvailable(username)
		assert.NoError(t, err)
		assert.True(t, usernameAvailable)

		emailAvailable, err := registerService.IsEmailAvailable(email)
		assert.NoError(t, err)
		assert.True(t, emailAvailable)

		// 2. 验证邀请码有效
		invitationValid, err := registerService.ValidateInvitationCode(invitationCode)
		assert.NoError(t, err)
		assert.True(t, invitationValid)

		// 3. 用户注册
		registerUser, registerToken, err := registerService.Register(username, email, password, invitationCode)
		assert.NoError(t, err)
		assert.NotNil(t, registerUser)
		assert.NotEmpty(t, registerToken)
		assert.Equal(t, username, registerUser.Username)
		assert.Equal(t, email, registerUser.Email)

		// 4. 验证注册后用户名和邮箱不再可用
		usernameAvailable, err = registerService.IsUsernameAvailable(username)
		assert.NoError(t, err)
		assert.False(t, usernameAvailable)

		emailAvailable, err = registerService.IsEmailAvailable(email)
		assert.NoError(t, err)
		assert.False(t, emailAvailable)

		// 5. 等待1秒确保时间戳不同
		time.Sleep(time.Second)

		// 6. 使用注册的用户名和密码登录
		loginUser, loginToken, err := loginService.Login(username, password)
		assert.NoError(t, err)
		assert.NotNil(t, loginUser)
		assert.NotEmpty(t, loginToken)
		assert.Equal(t, registerUser.ID, loginUser.ID)
		assert.Equal(t, registerUser.Username, loginUser.Username)
		assert.Equal(t, registerUser.Email, loginUser.Email)

		// 7. 验证注册Token和登录Token不同（由于时间戳不同）
		assert.NotEqual(t, registerToken, loginToken)

		// 8. 验证Token可以正常使用
		validatedUser, err := loginService.ValidateToken(loginToken)
		assert.NoError(t, err)
		assert.Equal(t, loginUser.ID, validatedUser.ID)

		// 9. 刷新Token
		time.Sleep(time.Second) // 确保时间戳不同
		newToken, err := loginService.RefreshToken(loginToken)
		assert.NoError(t, err)
		assert.NotEmpty(t, newToken)
		assert.NotEqual(t, loginToken, newToken)

		// 10. 登出
		err = loginService.Logout(newToken)
		assert.NoError(t, err)
	})

	t.Run("注册失败后无法登录", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		username := "failuser"
		email := "fail@example.com"
		password := "password123"
		invalidInvitationCode := "invalid"

		// 1. 尝试使用无效邀请码注册
		_, _, err := registerService.Register(username, email, password, invalidInvitationCode)
		assert.Error(t, err)
		assert.Equal(t, "邀请码无效", err.Error())

		// 2. 验证注册失败后无法登录
		_, _, err = loginService.Login(username, password)
		assert.Error(t, err)
		assert.Equal(t, "用户名或密码错误", err.Error())
	})

	t.Run("重复注册失败", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		username := "duplicateuser"
		email := "duplicate@example.com"
		password := "password123"

		// 1. 第一次注册成功
		user1, token1, err := registerService.Register(username, email, password, "")
		assert.NoError(t, err)
		assert.NotNil(t, user1)
		assert.NotEmpty(t, token1)

		// 2. 尝试重复注册相同用户名
		_, _, err = registerService.Register(username, "different@example.com", password, "")
		assert.Error(t, err)
		assert.Equal(t, "用户名已存在", err.Error())

		// 3. 尝试重复注册相同邮箱
		_, _, err = registerService.Register("differentuser", email, password, "")
		assert.Error(t, err)
		assert.Equal(t, "邮箱已存在", err.Error())

		// 4. 验证原用户仍可正常登录
		loginUser, loginToken, err := loginService.Login(username, password)
		assert.NoError(t, err)
		assert.Equal(t, user1.ID, loginUser.ID)
		assert.NotEmpty(t, loginToken)
	})

	t.Run("用户状态对登录的影响", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		username := "statususer"
		email := "status@example.com"
		password := "password123"

		// 1. 注册用户
		registerUser, _, err := registerService.Register(username, email, password, "")
		assert.NoError(t, err)

		// 2. 正常状态下可以登录
		_, _, err = loginService.Login(username, password)
		assert.NoError(t, err)

		// 3. 禁用用户
		registerUser.Status = 2
		err = userService.UpdateUser(registerUser)
		assert.NoError(t, err)

		// 4. 禁用状态下无法登录
		_, _, err = loginService.Login(username, password)
		assert.Error(t, err)
		assert.Equal(t, "用户已被禁用", err.Error())

		// 5. 重新启用用户
		registerUser.Status = 1
		err = userService.UpdateUser(registerUser)
		assert.NoError(t, err)

		// 6. 启用后可以正常登录
		_, _, err = loginService.Login(username, password)
		assert.NoError(t, err)
	})

	t.Run("密码安全性验证", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		username := "securityuser"
		email := "security@example.com"
		plainPassword := "password123"

		// 1. 注册用户
		registerUser, _, err := registerService.Register(username, email, plainPassword, "")
		assert.NoError(t, err)

		// 2. 验证密码已被哈希
		assert.NotEqual(t, plainPassword, registerUser.PasswordHash)
		assert.True(t, len(registerUser.PasswordHash) > 50)
		assert.Contains(t, registerUser.PasswordHash, "$")

		// 3. 验证可以使用原始密码登录
		_, _, err = loginService.Login(username, plainPassword)
		assert.NoError(t, err)

		// 4. 验证无法使用哈希后的密码登录
		_, _, err = loginService.Login(username, registerUser.PasswordHash)
		assert.Error(t, err)
		assert.Equal(t, "用户名或密码错误", err.Error())
	})
}
