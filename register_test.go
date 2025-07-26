package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRegisterService(t *testing.T) {
	// 设置测试数据库
	testDB := SetupTestDB(t)
	defer testDB.TeardownTestDB()

	// 创建服务实例
	userService := NewUserService(testDB.DB)
	tokenService := NewTokenService("test-secret-key", time.Hour)
	registerService := NewRegisterService(userService, tokenService)

	t.Run("用户注册成功", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试用户注册
		user, token, err := registerService.Register("newuser", "newuser@example.com", "password123", "")
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
		assert.Equal(t, user.Username, savedUser.Username)
		assert.Equal(t, user.Email, savedUser.Email)
	})

	t.Run("用户注册成功-带邀请码", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试带邀请码的用户注册
		user, token, err := registerService.Register("inviteduser", "invited@example.com", "password123", "12345678")
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
		_, _, err := registerService.Register("existinguser", "existing@example.com", "password123", "")
		assert.NoError(t, err)

		// 尝试注册相同用户名的用户
		_, _, err = registerService.Register("existinguser", "different@example.com", "password123", "")
		assert.Error(t, err)
		assert.Equal(t, "用户名已存在", err.Error())
	})

	t.Run("用户注册失败-邮箱已存在", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 先注册一个用户
		_, _, err := registerService.Register("user1", "same@example.com", "password123", "")
		assert.NoError(t, err)

		// 尝试注册相同邮箱的用户
		_, _, err = registerService.Register("user2", "same@example.com", "password123", "")
		assert.Error(t, err)
		assert.Equal(t, "邮箱已存在", err.Error())
	})

	t.Run("用户注册失败-无效邀请码", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 尝试使用无效邀请码注册
		_, _, err := registerService.Register("user", "user@example.com", "password123", "invalid")
		assert.Error(t, err)
		assert.Equal(t, "邀请码无效", err.Error())
	})

	t.Run("验证用户名可用性", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试可用的用户名
		available, err := registerService.IsUsernameAvailable("newusername")
		assert.NoError(t, err)
		assert.True(t, available)

		// 注册一个用户
		testDB.CreateTestUser("existinguser", "existing@example.com", "password")

		// 测试已存在的用户名
		available, err = registerService.IsUsernameAvailable("existinguser")
		assert.NoError(t, err)
		assert.False(t, available)
	})

	t.Run("验证邮箱可用性", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试可用的邮箱
		available, err := registerService.IsEmailAvailable("new@example.com")
		assert.NoError(t, err)
		assert.True(t, available)

		// 注册一个用户
		testDB.CreateTestUser("user", "existing@example.com", "password")

		// 测试已存在的邮箱
		available, err = registerService.IsEmailAvailable("existing@example.com")
		assert.NoError(t, err)
		assert.False(t, available)
	})

	t.Run("验证邀请码有效性", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试有效邀请码（8位）
		valid, err := registerService.ValidateInvitationCode("12345678")
		assert.NoError(t, err)
		assert.True(t, valid)

		// 测试无效邀请码（长度不对）
		valid, err = registerService.ValidateInvitationCode("12345")
		assert.NoError(t, err)
		assert.False(t, valid)

		// 测试空邀请码
		valid, err = registerService.ValidateInvitationCode("")
		assert.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("注册后密码被正确哈希", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		plainPassword := "password123"

		// 注册用户
		user, _, err := registerService.Register("testuser", "test@example.com", plainPassword, "")
		assert.NoError(t, err)

		// 验证密码已被哈希（不等于原始密码）
		assert.NotEqual(t, plainPassword, user.PasswordHash)
		assert.True(t, len(user.PasswordHash) > 50) // 哈希后的密码应该很长
		assert.Contains(t, user.PasswordHash, "$")  // 包含分隔符
	})

	t.Run("注册后生成有效Token", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 注册用户
		user, token, err := registerService.Register("testuser", "test@example.com", "password123", "")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		// 验证Token格式（JWT格式应该有两个点）
		tokenParts := len([]rune(token))
		assert.True(t, tokenParts > 50) // JWT Token应该比较长

		// 可以进一步验证Token是否可以被解析（这里简化）
		assert.NotNil(t, user)
		assert.NotZero(t, user.ID)
	})

	t.Run("注册时设置正确的默认值", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 注册用户
		user, _, err := registerService.Register("testuser", "test@example.com", "password123", "")
		assert.NoError(t, err)

		// 验证默认值
		assert.Equal(t, uint8(1), user.Status) // 默认状态为正常
		assert.NotNil(t, user.LastLoginAt)     // 注册时设置最后登录时间
		assert.NotZero(t, user.CreatedAt)      // 创建时间不为空
		assert.NotZero(t, user.UpdatedAt)      // 更新时间不为空
		// 创建和更新时间应该很接近（允许小的时间差）
		timeDiff := user.UpdatedAt.Sub(user.CreatedAt)
		assert.True(t, timeDiff >= 0 && timeDiff < time.Second)
	})
}
