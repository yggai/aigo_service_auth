package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserModel(t *testing.T) {
	// 设置测试数据库
	testDB := SetupTestDB(t)
	defer testDB.TeardownTestDB()

	db := testDB.DB

	// 测试表名
	assert.Equal(t, "sys_users", (&User{}).TableName())

	// 测试创建用户
	user := &User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashedpassword",
		Status:       1,
	}

	// 测试BeforeCreate钩子
	err := user.BeforeCreate(db)
	assert.NoError(t, err)

	// 保存用户到数据库
	err = db.Create(user).Error
	assert.NoError(t, err)
	assert.NotZero(t, user.ID)

	// 测试查询用户
	var foundUser User
	err = db.First(&foundUser, user.ID).Error
	assert.NoError(t, err)
	assert.Equal(t, user.Username, foundUser.Username)
	assert.Equal(t, user.Email, foundUser.Email)
	assert.Equal(t, user.PasswordHash, foundUser.PasswordHash)

	// 测试BeforeUpdate钩子
	foundUser.Username = "updateduser"
	err = foundUser.BeforeUpdate(db)
	assert.NoError(t, err)

	// 更新用户
	err = db.Save(&foundUser).Error
	assert.NoError(t, err)

	// 验证更新结果
	var updatedUser User
	err = db.First(&updatedUser, user.ID).Error
	assert.NoError(t, err)
	assert.Equal(t, "updateduser", updatedUser.Username)

	// 测试软删除
	err = db.Delete(&updatedUser).Error
	assert.NoError(t, err)

	// 验证删除结果
	var deletedUser User
	err = db.Unscoped().First(&deletedUser, user.ID).Error
	assert.NoError(t, err)
	assert.NotNil(t, deletedUser.DeletedAt.Time)
}
