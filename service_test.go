package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestUserService(t *testing.T) {
	// 设置测试数据库
	testDB := SetupTestDB(t)
	defer testDB.TeardownTestDB()

	// 创建用户服务实例
	service := NewUserService(testDB.DB)

	t.Run("创建用户", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := &User{
			Username:     "testuser",
			Email:        "test@example.com",
			PasswordHash: "hashedpassword",
			Status:       1,
		}

		err := service.CreateUser(user)
		assert.NoError(t, err)
		assert.NotZero(t, user.ID)
	})

	t.Run("创建重复用户名的用户", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 先创建一个用户
		user1 := testDB.CreateTestUser("testuser", "test1@example.com", "password1")

		// 尝试创建重复用户名的用户
		duplicateUser := &User{
			Username:     "testuser",
			Email:        "test2@example.com",
			PasswordHash: "password2",
		}

		err := service.CreateUser(duplicateUser)
		assert.Error(t, err)
		assert.Equal(t, "用户名已存在", err.Error())

		// 验证原用户仍然存在
		foundUser, err := service.GetUserByID(user1.ID)
		assert.NoError(t, err)
		assert.Equal(t, "testuser", foundUser.Username)
	})

	t.Run("创建重复邮箱的用户", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 先创建一个用户
		user1 := testDB.CreateTestUser("testuser1", "test@example.com", "password1")

		// 尝试创建重复邮箱的用户
		duplicateEmailUser := &User{
			Username:     "testuser2",
			Email:        "test@example.com",
			PasswordHash: "password2",
		}

		err := service.CreateUser(duplicateEmailUser)
		assert.Error(t, err)
		assert.Equal(t, "邮箱已存在", err.Error())

		// 验证原用户仍然存在
		foundUser, err := service.GetUserByID(user1.ID)
		assert.NoError(t, err)
		assert.Equal(t, "test@example.com", foundUser.Email)
	})

	t.Run("根据ID获取用户", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")

		foundUser, err := service.GetUserByID(user.ID)
		assert.NoError(t, err)
		assert.Equal(t, user.Username, foundUser.Username)
		assert.Equal(t, user.Email, foundUser.Email)
	})

	t.Run("根据用户名获取用户", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")

		foundByUsername, err := service.GetUserByUsername(user.Username)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, foundByUsername.ID)
	})

	t.Run("根据邮箱获取用户", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")

		foundByEmail, err := service.GetUserByEmail(user.Email)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, foundByEmail.ID)
	})

	t.Run("更新用户", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")

		// 更新用户名
		user.Username = "updateduser"
		err := service.UpdateUser(user)
		assert.NoError(t, err)

		// 验证更新结果
		updatedUser, err := service.GetUserByID(user.ID)
		assert.NoError(t, err)
		assert.Equal(t, "updateduser", updatedUser.Username)
	})

	t.Run("删除用户", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")

		// 删除用户
		err := service.DeleteUser(user.ID)
		assert.NoError(t, err)

		// 验证用户已被删除
		_, err = service.GetUserByID(user.ID)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
	})

	t.Run("分页获取用户列表", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 创建15个测试用户
		for i := 0; i < 15; i++ {
			testDB.CreateTestUser(
				fmt.Sprintf("user%d", i),
				fmt.Sprintf("user%d@example.com", i),
				"password",
			)
		}

		// 测试第一页
		users, total, err := service.ListUsers(1, 10)
		assert.NoError(t, err)
		assert.Equal(t, int64(15), total)
		assert.Len(t, users, 10)

		// 测试第二页
		usersPage2, _, err := service.ListUsers(2, 10)
		assert.NoError(t, err)
		assert.Len(t, usersPage2, 5)
	})

	t.Run("邀请码验证", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 测试有效邀请码
		valid, err := service.ValidateInvitationCode("12345678")
		assert.NoError(t, err)
		assert.True(t, valid)

		// 测试无效邀请码
		invalid, err := service.ValidateInvitationCode("12345")
		assert.NoError(t, err)
		assert.False(t, invalid)
	})
}
