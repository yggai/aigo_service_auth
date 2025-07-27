package main

import (
	"testing"
)

func TestPasswordPolicyValidator(t *testing.T) {
	validator := NewPasswordPolicyValidator()

	t.Run("基本策略验证测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MinLength:      8,
			MaxLength:      20,
			RequireLower:   true,
			RequireUpper:   true,
			RequireNumbers: true,
			RequireSymbols: false,
		}

		// 符合策略的密码
		result := validator.ValidatePolicy("MyPassword123", policy)
		if !result.Valid {
			t.Errorf("符合策略的密码应该通过验证，违规信息: %v", result.Violations)
		}
		if result.Score <= 0 {
			t.Errorf("符合策略的密码应该有正分数，实际分数: %d", result.Score)
		}
	})

	t.Run("长度不足测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MinLength: 10,
		}

		result := validator.ValidatePolicy("short", policy)
		if result.Valid {
			t.Error("长度不足的密码不应该通过验证")
		}

		// 检查是否有长度相关的违规信息
		foundLengthViolation := false
		for _, violation := range result.Violations {
			if violation == "密码长度不能少于10个字符" {
				foundLengthViolation = true
				break
			}
		}
		if !foundLengthViolation {
			t.Error("应该有长度不足的违规信息")
		}
	})

	t.Run("长度过长测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MaxLength: 5,
		}

		result := validator.ValidatePolicy("verylongpassword", policy)
		if result.Valid {
			t.Error("长度过长的密码不应该通过验证")
		}

		// 检查是否有长度相关的违规信息
		foundLengthViolation := false
		for _, violation := range result.Violations {
			if violation == "密码长度不能超过5个字符" {
				foundLengthViolation = true
				break
			}
		}
		if !foundLengthViolation {
			t.Error("应该有长度过长的违规信息")
		}
	})

	t.Run("字符要求测试", func(t *testing.T) {
		policy := PasswordPolicy{
			RequireLower:   true,
			RequireUpper:   true,
			RequireNumbers: true,
			RequireSymbols: true,
		}

		// 缺少大写字母
		result := validator.ValidatePolicy("password123!", policy)
		if result.Valid {
			t.Error("缺少大写字母的密码不应该通过验证")
		}

		// 缺少小写字母
		result = validator.ValidatePolicy("PASSWORD123!", policy)
		if result.Valid {
			t.Error("缺少小写字母的密码不应该通过验证")
		}

		// 缺少数字
		result = validator.ValidatePolicy("Password!", policy)
		if result.Valid {
			t.Error("缺少数字的密码不应该通过验证")
		}

		// 缺少特殊字符
		result = validator.ValidatePolicy("Password123", policy)
		if result.Valid {
			t.Error("缺少特殊字符的密码不应该通过验证")
		}

		// 包含所有要求的字符类型
		result = validator.ValidatePolicy("Password123!", policy)
		if !result.Valid {
			t.Errorf("包含所有要求字符类型的密码应该通过验证，违规信息: %v", result.Violations)
		}
	})

	t.Run("唯一字符要求测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MinUniqueChars: 6,
		}

		// 唯一字符不足
		result := validator.ValidatePolicy("aaaaaa", policy)
		if result.Valid {
			t.Error("唯一字符不足的密码不应该通过验证")
		}

		// 唯一字符足够
		result = validator.ValidatePolicy("abcdef", policy)
		if !result.Valid {
			t.Errorf("唯一字符足够的密码应该通过验证，违规信息: %v", result.Violations)
		}
	})

	t.Run("重复字符限制测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MaxRepeatedChars: 2,
		}

		// 重复字符过多
		result := validator.ValidatePolicy("aaabbb", policy)
		if result.Valid {
			t.Error("重复字符过多的密码不应该通过验证")
		}

		// 重复字符在限制内
		result = validator.ValidatePolicy("aabbcc", policy)
		if !result.Valid {
			t.Errorf("重复字符在限制内的密码应该通过验证，违规信息: %v", result.Violations)
		}
	})

	t.Run("禁用模式测试", func(t *testing.T) {
		policy := PasswordPolicy{
			ForbiddenPatterns: []string{"password", "123456", "admin"},
		}

		// 包含禁用模式
		result := validator.ValidatePolicy("mypassword123", policy)
		if result.Valid {
			t.Error("包含禁用模式的密码不应该通过验证")
		}

		result = validator.ValidatePolicy("admin123", policy)
		if result.Valid {
			t.Error("包含禁用模式的密码不应该通过验证")
		}

		// 不包含禁用模式
		result = validator.ValidatePolicy("mysecret789", policy)
		if !result.Valid {
			t.Errorf("不包含禁用模式的密码应该通过验证，违规信息: %v", result.Violations)
		}
	})

	t.Run("复合策略测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MinLength:         12,
			MaxLength:         50,
			RequireLower:      true,
			RequireUpper:      true,
			RequireNumbers:    true,
			RequireSymbols:    true,
			MinUniqueChars:    8,
			MaxRepeatedChars:  2,
			ForbiddenPatterns: []string{"password", "123456"},
		}

		// 不符合多个要求
		result := validator.ValidatePolicy("pass", policy)
		if result.Valid {
			t.Error("不符合多个要求的密码不应该通过验证")
		}
		if len(result.Violations) == 0 {
			t.Error("应该有多个违规信息")
		}

		// 符合所有要求
		result = validator.ValidatePolicy("MySecure@Pass2024!", policy)
		if !result.Valid {
			t.Errorf("符合所有要求的密码应该通过验证，违规信息: %v", result.Violations)
		}
		if len(result.Violations) != 0 {
			t.Errorf("符合所有要求的密码不应该有违规信息，实际违规: %v", result.Violations)
		}
	})

	t.Run("分数计算测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MinLength:      8,
			RequireLower:   true,
			RequireUpper:   true,
			RequireNumbers: true,
			RequireSymbols: true,
		}

		// 完全符合策略的密码应该有高分
		result := validator.ValidatePolicy("MyPassword123!", policy)
		if result.Score < 80 {
			t.Errorf("完全符合策略的密码应该有高分，实际分数: %d", result.Score)
		}

		// 部分违规的密码应该有较低分数
		result = validator.ValidatePolicy("password", policy)
		if result.Score >= 80 {
			t.Errorf("部分违规的密码应该有较低分数，实际分数: %d", result.Score)
		}
	})

	t.Run("边界条件测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MinLength: 0,
			MaxLength: 0, // 0表示无限制
		}

		// 空密码
		result := validator.ValidatePolicy("", policy)
		// 空密码可能通过验证，取决于其他要求

		// 极长密码
		longPassword := ""
		for i := 0; i < 1000; i++ {
			longPassword += "a"
		}
		result = validator.ValidatePolicy(longPassword, policy)
		// 应该能处理极长密码而不崩溃
		_ = result
	})
}

func TestPasswordManagerPolicyIntegration(t *testing.T) {
	config := DefaultPasswordManagerConfig()
	pm := NewPasswordManager(config)

	t.Run("密码管理器策略验证集成", func(t *testing.T) {
		policy := PasswordPolicy{
			MinLength:      10,
			RequireLower:   true,
			RequireUpper:   true,
			RequireNumbers: true,
			RequireSymbols: false,
		}

		// 符合策略的密码
		result := pm.ValidatePolicy("MyPassword123", policy)
		if !result.Valid {
			t.Errorf("符合策略的密码应该通过验证，违规信息: %v", result.Violations)
		}

		// 不符合策略的密码
		result = pm.ValidatePolicy("weak", policy)
		if result.Valid {
			t.Error("不符合策略的密码不应该通过验证")
		}
	})

	t.Run("使用默认策略验证", func(t *testing.T) {
		// 符合默认策略的密码
		result := pm.ValidateWithDefaultPolicy("MySecret123")
		if !result.Valid {
			t.Errorf("符合默认策略的密码应该通过验证，违规信息: %v", result.Violations)
		}

		// 不符合默认策略的密码
		result = pm.ValidateWithDefaultPolicy("weak")
		if result.Valid {
			t.Error("不符合默认策略的密码不应该通过验证")
		}
	})

	t.Run("生成的密码符合默认策略", func(t *testing.T) {
		// 多次生成密码，验证都符合默认策略
		for i := 0; i < 10; i++ {
			password, err := pm.GenerateWithDefaults()
			if err != nil {
				t.Fatalf("生成密码失败: %v", err)
			}

			result := pm.ValidateWithDefaultPolicy(password)
			if !result.Valid {
				t.Errorf("生成的密码应该符合默认策略，密码: %s，违规信息: %v", password, result.Violations)
			}
		}
	})

	t.Run("策略验证与强度检测结合", func(t *testing.T) {
		password := "MySecureSecret2024!"

		// 策略验证
		policyResult := pm.ValidateWithDefaultPolicy(password)
		if !policyResult.Valid {
			t.Errorf("密码应该符合默认策略，违规信息: %v", policyResult.Violations)
		}

		// 强度检测
		strengthResult := pm.CheckStrength(password)
		if strengthResult.Score < 60 {
			t.Errorf("密码强度应该足够，实际分数: %d", strengthResult.Score)
		}

		// 强密码判断
		if !pm.IsPasswordStrong(password) {
			t.Error("密码应该被认为是强密码")
		}
	})

	t.Run("配置更新影响策略验证", func(t *testing.T) {
		// 更新配置，使用更严格的策略
		newConfig := DefaultPasswordManagerConfig()
		newConfig.DefaultPolicy.MinLength = 15
		newConfig.DefaultPolicy.RequireSymbols = true
		pm.UpdateConfig(newConfig)

		// 之前可能通过的密码现在可能不通过
		result := pm.ValidateWithDefaultPolicy("MySecret123")
		// 这个密码长度只有11，不符合新的最小长度15的要求
		if result.Valid {
			t.Error("更新配置后，不符合新策略的密码不应该通过验证")
		}

		// 符合新策略的密码应该通过
		result = pm.ValidateWithDefaultPolicy("MyVerySecureSecret2024!")
		if !result.Valid {
			t.Errorf("符合新策略的密码应该通过验证，违规信息: %v", result.Violations)
		}
	})
}

func TestPasswordPolicyEdgeCases(t *testing.T) {
	validator := NewPasswordPolicyValidator()

	t.Run("极端策略配置", func(t *testing.T) {
		// 极严格的策略
		strictPolicy := PasswordPolicy{
			MinLength:         50,
			MaxLength:         100,
			RequireLower:      true,
			RequireUpper:      true,
			RequireNumbers:    true,
			RequireSymbols:    true,
			MinUniqueChars:    30,
			MaxRepeatedChars:  1,
			ForbiddenPatterns: []string{"password", "123", "abc", "qwe"},
		}

		// 大多数密码都不会通过这个严格的策略
		result := validator.ValidatePolicy("MyPassword123!", strictPolicy)
		if result.Valid {
			t.Error("在极严格策略下，普通密码不应该通过验证")
		}

		// 极宽松的策略
		lenientPolicy := PasswordPolicy{
			MinLength: 1,
			MaxLength: 1000,
		}

		// 大多数密码都会通过这个宽松的策略
		result = validator.ValidatePolicy("a", lenientPolicy)
		if !result.Valid {
			t.Errorf("在极宽松策略下，简单密码应该通过验证，违规信息: %v", result.Violations)
		}
	})

	t.Run("空策略配置", func(t *testing.T) {
		emptyPolicy := PasswordPolicy{}

		// 空策略应该允许任何密码
		result := validator.ValidatePolicy("anything", emptyPolicy)
		if !result.Valid {
			t.Errorf("空策略应该允许任何密码，违规信息: %v", result.Violations)
		}
	})

	t.Run("特殊字符处理", func(t *testing.T) {
		policy := PasswordPolicy{
			RequireSymbols: true,
		}

		// 测试各种特殊字符
		specialChars := []string{"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+", "=", "[", "]", "{", "}", "|", ";", ":", ",", ".", "<", ">", "?"}

		for _, char := range specialChars {
			password := "Password123" + char
			result := validator.ValidatePolicy(password, policy)
			if !result.Valid {
				t.Errorf("包含特殊字符 %s 的密码应该通过验证，违规信息: %v", char, result.Violations)
			}
		}
	})

	t.Run("Unicode字符处理", func(t *testing.T) {
		policy := PasswordPolicy{
			MinLength: 5,
		}

		// 包含Unicode字符的密码
		unicodePassword := "密码123"
		result := validator.ValidatePolicy(unicodePassword, policy)
		// 应该能正确处理Unicode字符而不崩溃
		_ = result
	})

	t.Run("性能测试", func(t *testing.T) {
		policy := PasswordPolicy{
			MinLength:         8,
			MaxLength:         50,
			RequireLower:      true,
			RequireUpper:      true,
			RequireNumbers:    true,
			RequireSymbols:    true,
			MinUniqueChars:    6,
			MaxRepeatedChars:  3,
			ForbiddenPatterns: []string{"password", "123456", "qwerty", "admin"},
		}

		// 验证大量密码，测试性能
		for i := 0; i < 1000; i++ {
			password := "TestPassword" + string(rune(i%26+'A')) + "123!"
			result := validator.ValidatePolicy(password, policy)
			_ = result // 确保不被优化掉
		}
	})
}
