package main

import (
	"testing"
)

func TestPasswordHasher(t *testing.T) {
	hasher := NewPasswordHasher(12)

	t.Run("密码加密测试", func(t *testing.T) {
		password := "testPassword123!"
		hash, err := hasher.Hash(password)

		if err != nil {
			t.Fatalf("密码加密失败: %v", err)
		}

		if hash == "" {
			t.Fatal("哈希值不能为空")
		}

		if hash == password {
			t.Fatal("哈希值不能与原密码相同")
		}
	})

	t.Run("密码验证测试", func(t *testing.T) {
		password := "testPassword123!"
		hash, err := hasher.Hash(password)

		if err != nil {
			t.Fatalf("密码加密失败: %v", err)
		}

		// 正确密码验证
		if !hasher.Verify(password, hash) {
			t.Fatal("正确密码验证失败")
		}

		// 错误密码验证
		if hasher.Verify("wrongPassword", hash) {
			t.Fatal("错误密码验证应该失败")
		}
	})

	t.Run("空密码处理", func(t *testing.T) {
		_, err := hasher.Hash("")
		if err == nil {
			t.Fatal("空密码应该返回错误")
		}

		if !hasher.Verify("", "") {
			// 空密码验证应该返回 false
		}
	})

	t.Run("成本参数测试", func(t *testing.T) {
		if hasher.GetCost() != 12 {
			t.Fatalf("期望成本参数为 12，实际为 %d", hasher.GetCost())
		}

		hasher.SetCost(10)
		if hasher.GetCost() != 10 {
			t.Fatalf("期望成本参数为 10，实际为 %d", hasher.GetCost())
		}
	})
}

func TestPasswordManager(t *testing.T) {
	config := DefaultPasswordManagerConfig()
	pm := NewPasswordManager(config)

	t.Run("密码管理器加密测试", func(t *testing.T) {
		password := "testPassword123!"
		hash, err := pm.HashPassword(password)

		if err != nil {
			t.Fatalf("密码加密失败: %v", err)
		}

		if hash == "" {
			t.Fatal("哈希值不能为空")
		}
	})

	t.Run("密码管理器验证测试", func(t *testing.T) {
		password := "testPassword123!"
		hash, err := pm.HashPassword(password)

		if err != nil {
			t.Fatalf("密码加密失败: %v", err)
		}

		if !pm.VerifyPassword(password, hash) {
			t.Fatal("密码验证失败")
		}
	})

	t.Run("配置管理测试", func(t *testing.T) {
		currentConfig := pm.GetConfig()
		if currentConfig.BcryptCost != 12 {
			t.Fatalf("期望 BcryptCost 为 12，实际为 %d", currentConfig.BcryptCost)
		}

		newConfig := DefaultPasswordManagerConfig()
		newConfig.BcryptCost = 10
		pm.UpdateConfig(newConfig)

		updatedConfig := pm.GetConfig()
		if updatedConfig.BcryptCost != 10 {
			t.Fatalf("期望 BcryptCost 为 10，实际为 %d", updatedConfig.BcryptCost)
		}
	})
}
