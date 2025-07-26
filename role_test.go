package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleService(t *testing.T) {
	// 设置测试数据库
	testDB := SetupTestDB(t)
	defer testDB.TeardownTestDB()

	// 创建服务实例
	roleService := NewRoleService(testDB.DB)

	t.Run("创建角色", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		role := &Role{
			Name:        "admin",
			DisplayName: "管理员",
			Description: "系统管理员",
			Status:      1,
		}
		err := roleService.CreateRole(role)
		assert.NoError(t, err)
		assert.NotZero(t, role.ID)
	})

	t.Run("创建重复角色名", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 先创建一个角色
		role1 := testDB.CreateTestRole("admin", "管理员", "系统管理员")

		// 尝试创建重复角色名
		duplicateRole := &Role{
			Name:        "admin",
			DisplayName: "重复管理员",
			Status:      1,
		}
		err := roleService.CreateRole(duplicateRole)
		assert.Error(t, err)
		assert.Equal(t, "角色名已存在", err.Error())

		// 验证原角色仍然存在
		foundRole, err := roleService.GetRoleByID(role1.ID)
		assert.NoError(t, err)
		assert.Equal(t, "admin", foundRole.Name)
	})

	t.Run("获取角色", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		role := testDB.CreateTestRole("admin", "管理员", "系统管理员")

		// 根据ID获取角色
		foundRole, err := roleService.GetRoleByID(role.ID)
		assert.NoError(t, err)
		assert.Equal(t, role.Name, foundRole.Name)

		// 根据名称获取角色
		foundRoleByName, err := roleService.GetRoleByName("admin")
		assert.NoError(t, err)
		assert.Equal(t, role.ID, foundRoleByName.ID)
	})

	t.Run("创建权限", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		permission := &Permission{
			Name:        "user.create",
			DisplayName: "创建用户",
			Resource:    "user",
			Action:      "create",
			Description: "创建用户权限",
		}
		err := roleService.CreatePermission(permission)
		assert.NoError(t, err)
		assert.NotZero(t, permission.ID)
	})

	t.Run("角色权限分配", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		role := testDB.CreateTestRole("admin", "管理员", "系统管理员")
		permission := testDB.CreateTestPermission("user.create", "创建用户", "user", "create")

		// 为角色分配权限
		err := roleService.AssignPermissionToRole(role.ID, permission.ID)
		assert.NoError(t, err)

		// 测试重复分配权限
		err = roleService.AssignPermissionToRole(role.ID, permission.ID)
		assert.Error(t, err)
		assert.Equal(t, "权限已分配给该角色", err.Error())

		// 获取角色权限
		permissions, err := roleService.GetRolePermissions(role.ID)
		assert.NoError(t, err)
		assert.Len(t, permissions, 1)
		assert.Equal(t, permission.Name, permissions[0].Name)
	})

	t.Run("用户角色分配", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")
		role := testDB.CreateTestRole("admin", "管理员", "系统管理员")

		// 为用户分配角色
		err := roleService.AssignRoleToUser(user.ID, role.ID)
		assert.NoError(t, err)

		// 测试重复分配角色
		err = roleService.AssignRoleToUser(user.ID, role.ID)
		assert.Error(t, err)
		assert.Equal(t, "角色已分配给该用户", err.Error())

		// 获取用户角色
		userRoles, err := roleService.GetUserRoles(user.ID)
		assert.NoError(t, err)
		assert.Len(t, userRoles, 1)
		assert.Equal(t, role.Name, userRoles[0].Name)
	})

	t.Run("权限检查", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")
		role := testDB.CreateTestRole("admin", "管理员", "系统管理员")
		permission := testDB.CreateTestPermission("user.create", "创建用户", "user", "create")

		// 分配权限和角色
		roleService.AssignPermissionToRole(role.ID, permission.ID)
		roleService.AssignRoleToUser(user.ID, role.ID)

		// 测试权限检查
		hasPermission, err := roleService.HasPermission(user.ID, "user", "create")
		assert.NoError(t, err)
		assert.True(t, hasPermission)

		hasPermission, err = roleService.HasPermission(user.ID, "user", "delete")
		assert.NoError(t, err)
		assert.False(t, hasPermission)
	})

	t.Run("角色检查", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")
		role := testDB.CreateTestRole("admin", "管理员", "系统管理员")

		// 分配角色
		roleService.AssignRoleToUser(user.ID, role.ID)

		// 测试角色检查
		hasRole, err := roleService.HasRole(user.ID, "admin")
		assert.NoError(t, err)
		assert.True(t, hasRole)

		hasRole, err = roleService.HasRole(user.ID, "user")
		assert.NoError(t, err)
		assert.False(t, hasRole)
	})

	t.Run("移除用户角色", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		user := testDB.CreateTestUser("testuser", "test@example.com", "password")
		role := testDB.CreateTestRole("admin", "管理员", "系统管理员")

		// 分配角色
		roleService.AssignRoleToUser(user.ID, role.ID)

		// 验证角色已分配
		hasRole, err := roleService.HasRole(user.ID, "admin")
		assert.NoError(t, err)
		assert.True(t, hasRole)

		// 移除用户角色
		err = roleService.RemoveRoleFromUser(user.ID, role.ID)
		assert.NoError(t, err)

		// 验证角色已移除
		hasRole, err = roleService.HasRole(user.ID, "admin")
		assert.NoError(t, err)
		assert.False(t, hasRole)
	})

	t.Run("移除角色权限", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		role := testDB.CreateTestRole("admin", "管理员", "系统管理员")
		permission := testDB.CreateTestPermission("user.create", "创建用户", "user", "create")

		// 分配权限
		roleService.AssignPermissionToRole(role.ID, permission.ID)

		// 验证权限已分配
		permissions, err := roleService.GetRolePermissions(role.ID)
		assert.NoError(t, err)
		assert.Len(t, permissions, 1)

		// 移除角色权限
		err = roleService.RemovePermissionFromRole(role.ID, permission.ID)
		assert.NoError(t, err)

		// 验证权限已移除
		permissions, err = roleService.GetRolePermissions(role.ID)
		assert.NoError(t, err)
		assert.Len(t, permissions, 0)
	})

	t.Run("角色分页列表", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 创建多个角色
		for i := 0; i < 15; i++ {
			testDB.CreateTestRole(
				fmt.Sprintf("role%d", i),
				fmt.Sprintf("角色%d", i),
				fmt.Sprintf("测试角色%d", i),
			)
		}

		// 测试分页
		roles, total, err := roleService.ListRoles(1, 10)
		assert.NoError(t, err)
		assert.Equal(t, int64(15), total)
		assert.Len(t, roles, 10)

		// 测试第二页
		rolesPage2, _, err := roleService.ListRoles(2, 10)
		assert.NoError(t, err)
		assert.Len(t, rolesPage2, 5)
	})

	t.Run("权限分页列表", func(t *testing.T) {
		// 清理数据
		testDB.ClearAllData()

		// 创建多个权限
		for i := 0; i < 12; i++ {
			testDB.CreateTestPermission(
				fmt.Sprintf("permission%d", i),
				fmt.Sprintf("权限%d", i),
				"resource",
				"action",
			)
		}

		// 测试分页
		permissions, total, err := roleService.ListPermissions(1, 10)
		assert.NoError(t, err)
		assert.Equal(t, int64(12), total)
		assert.Len(t, permissions, 10)

		// 测试第二页
		permissionsPage2, _, err := roleService.ListPermissions(2, 10)
		assert.NoError(t, err)
		assert.Len(t, permissionsPage2, 2)
	})
}
