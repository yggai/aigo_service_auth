package main

import (
	"strings"
	"testing"
)

func TestPasswordGenerator(t *testing.T) {
	generator := NewPasswordGenerator()

	t.Run("基本密码生成测试", func(t *testing.T) {
		options := GenerateOptions{
			Length:         12,
			IncludeLower:   true,
			IncludeUpper:   true,
			IncludeNumbers: true,
			IncludeSymbols: true,
		}

		password, err := generator.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		if len(password) != 12 {
			t.Errorf("期望密码长度为 12，实际为 %d", len(password))
		}

		// 验证包含所有要求的字符类型
		hasLower := strings.ContainsAny(password, LowerChars)
		hasUpper := strings.ContainsAny(password, UpperChars)
		hasNumbers := strings.ContainsAny(password, NumberChars)
		hasSymbols := strings.ContainsAny(password, SymbolChars)

		if !hasLower {
			t.Error("密码应该包含小写字母")
		}
		if !hasUpper {
			t.Error("密码应该包含大写字母")
		}
		if !hasNumbers {
			t.Error("密码应该包含数字")
		}
		if !hasSymbols {
			t.Error("密码应该包含特殊字符")
		}
	})

	t.Run("只包含小写字母", func(t *testing.T) {
		options := GenerateOptions{
			Length:         8,
			IncludeLower:   true,
			IncludeUpper:   false,
			IncludeNumbers: false,
			IncludeSymbols: false,
		}

		password, err := generator.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		if len(password) != 8 {
			t.Errorf("期望密码长度为 8，实际为 %d", len(password))
		}

		// 验证只包含小写字母
		for _, char := range password {
			if !strings.ContainsRune(LowerChars, char) {
				t.Errorf("密码包含非小写字母字符: %c", char)
			}
		}
	})

	t.Run("排除易混淆字符", func(t *testing.T) {
		options := GenerateOptions{
			Length:           20,
			IncludeLower:     true,
			IncludeUpper:     true,
			IncludeNumbers:   true,
			IncludeSymbols:   false,
			ExcludeAmbiguous: true,
		}

		password, err := generator.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		// 验证不包含易混淆字符
		for _, char := range password {
			if strings.ContainsRune(AmbiguousChars, char) {
				t.Errorf("密码包含易混淆字符: %c", char)
			}
		}
	})

	t.Run("自定义字符集", func(t *testing.T) {
		customCharset := "ABCDEF123456"
		options := GenerateOptions{
			Length:        10,
			CustomCharset: customCharset,
		}

		password, err := generator.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		if len(password) != 10 {
			t.Errorf("期望密码长度为 10，实际为 %d", len(password))
		}

		// 验证只包含自定义字符集中的字符
		for _, char := range password {
			if !strings.ContainsRune(customCharset, char) {
				t.Errorf("密码包含自定义字符集外的字符: %c", char)
			}
		}
	})

	t.Run("随机性测试", func(t *testing.T) {
		options := GenerateOptions{
			Length:         16,
			IncludeLower:   true,
			IncludeUpper:   true,
			IncludeNumbers: true,
			IncludeSymbols: true,
		}

		// 生成多个密码，验证它们不相同
		passwords := make(map[string]bool)
		for i := 0; i < 100; i++ {
			password, err := generator.GeneratePassword(options)
			if err != nil {
				t.Fatalf("生成密码失败: %v", err)
			}

			if passwords[password] {
				t.Errorf("生成了重复的密码: %s", password)
			}
			passwords[password] = true
		}
	})

	t.Run("无效选项测试", func(t *testing.T) {
		// 长度为0
		options := GenerateOptions{
			Length: 0,
		}
		_, err := generator.GeneratePassword(options)
		if err == nil {
			t.Error("期望长度为0时返回错误")
		}

		// 长度过长
		options = GenerateOptions{
			Length: 300,
		}
		_, err = generator.GeneratePassword(options)
		if err == nil {
			t.Error("期望长度过长时返回错误")
		}

		// 没有选择任何字符类型
		options = GenerateOptions{
			Length:         10,
			IncludeLower:   false,
			IncludeUpper:   false,
			IncludeNumbers: false,
			IncludeSymbols: false,
		}
		_, err = generator.GeneratePassword(options)
		if err == nil {
			t.Error("期望没有选择字符类型时返回错误")
		}
	})

	t.Run("边界长度测试", func(t *testing.T) {
		// 最小长度
		options := GenerateOptions{
			Length:       1,
			IncludeLower: true,
		}
		password, err := generator.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成最小长度密码失败: %v", err)
		}
		if len(password) != 1 {
			t.Errorf("期望密码长度为 1，实际为 %d", len(password))
		}

		// 较大长度
		options = GenerateOptions{
			Length:       100,
			IncludeLower: true,
		}
		password, err = generator.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成较大长度密码失败: %v", err)
		}
		if len(password) != 100 {
			t.Errorf("期望密码长度为 100，实际为 %d", len(password))
		}
	})

	t.Run("字符要求确保测试", func(t *testing.T) {
		options := GenerateOptions{
			Length:         4, // 短密码，更容易测试要求确保
			IncludeLower:   true,
			IncludeUpper:   true,
			IncludeNumbers: true,
			IncludeSymbols: true,
		}

		// 多次生成，验证每次都满足要求
		for i := 0; i < 50; i++ {
			password, err := generator.GeneratePassword(options)
			if err != nil {
				t.Fatalf("生成密码失败: %v", err)
			}

			hasLower := strings.ContainsAny(password, LowerChars)
			hasUpper := strings.ContainsAny(password, UpperChars)
			hasNumbers := strings.ContainsAny(password, NumberChars)
			hasSymbols := strings.ContainsAny(password, SymbolChars)

			if !hasLower || !hasUpper || !hasNumbers || !hasSymbols {
				t.Errorf("密码 %s 不满足所有字符类型要求", password)
			}
		}
	})
}

func TestPasswordManagerGeneratorIntegration(t *testing.T) {
	config := DefaultPasswordManagerConfig()
	pm := NewPasswordManager(config)

	t.Run("密码管理器生成密码", func(t *testing.T) {
		options := GenerateOptions{
			Length:         16,
			IncludeLower:   true,
			IncludeUpper:   true,
			IncludeNumbers: true,
			IncludeSymbols: true,
		}

		password, err := pm.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		if len(password) != 16 {
			t.Errorf("期望密码长度为 16，实际为 %d", len(password))
		}

		// 验证生成的密码强度
		strength := pm.CheckStrength(password)
		if strength.Score < 60 {
			t.Errorf("生成的密码强度过低: %d", strength.Score)
		}
	})

	t.Run("使用默认选项生成密码", func(t *testing.T) {
		password, err := pm.GenerateWithDefaults()
		if err != nil {
			t.Fatalf("使用默认选项生成密码失败: %v", err)
		}

		expectedLength := config.DefaultLength
		if len(password) != expectedLength {
			t.Errorf("期望密码长度为 %d，实际为 %d", expectedLength, len(password))
		}

		// 验证包含所有默认字符类型
		hasLower := strings.ContainsAny(password, LowerChars)
		hasUpper := strings.ContainsAny(password, UpperChars)
		hasNumbers := strings.ContainsAny(password, NumberChars)
		hasSymbols := strings.ContainsAny(password, SymbolChars)

		if !hasLower || !hasUpper || !hasNumbers || !hasSymbols {
			t.Error("默认生成的密码应该包含所有字符类型")
		}

		// 验证不包含易混淆字符
		for _, char := range password {
			if strings.ContainsRune(AmbiguousChars, char) {
				t.Errorf("默认生成的密码不应该包含易混淆字符: %c", char)
			}
		}
	})

	t.Run("生成强密码", func(t *testing.T) {
		// 多次生成密码，验证都是强密码
		for i := 0; i < 10; i++ {
			password, err := pm.GenerateWithDefaults()
			if err != nil {
				t.Fatalf("生成密码失败: %v", err)
			}

			if !pm.IsPasswordStrong(password) {
				t.Errorf("生成的密码应该是强密码: %s (强度: %d)", password, pm.CheckStrength(password).Score)
			}
		}
	})

	t.Run("生成的密码满足默认策略", func(t *testing.T) {
		password, err := pm.GenerateWithDefaults()
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		policyResult := pm.ValidatePolicy(password, config.DefaultPolicy)
		if !policyResult.Valid {
			t.Errorf("生成的密码不满足默认策略: %v", policyResult.Violations)
		}
	})
}

func TestPasswordGeneratorEdgeCases(t *testing.T) {
	generator := NewPasswordGenerator()

	t.Run("自定义字符集排除易混淆字符", func(t *testing.T) {
		customCharset := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		options := GenerateOptions{
			Length:           10,
			CustomCharset:    customCharset,
			ExcludeAmbiguous: true,
		}

		password, err := generator.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		// 验证不包含易混淆字符
		for _, char := range password {
			if strings.ContainsRune(AmbiguousChars, char) {
				t.Errorf("密码包含易混淆字符: %c", char)
			}
		}
	})

	t.Run("只包含特殊字符", func(t *testing.T) {
		options := GenerateOptions{
			Length:         8,
			IncludeLower:   false,
			IncludeUpper:   false,
			IncludeNumbers: false,
			IncludeSymbols: true,
		}

		password, err := generator.GeneratePassword(options)
		if err != nil {
			t.Fatalf("生成密码失败: %v", err)
		}

		// 验证只包含特殊字符
		for _, char := range password {
			if !strings.ContainsRune(SymbolChars, char) {
				t.Errorf("密码包含非特殊字符: %c", char)
			}
		}
	})

	t.Run("空自定义字符集", func(t *testing.T) {
		options := GenerateOptions{
			Length:         10,
			CustomCharset:  "",
			IncludeLower:   false,
			IncludeUpper:   false,
			IncludeNumbers: false,
			IncludeSymbols: false,
		}

		_, err := generator.GeneratePassword(options)
		if err == nil {
			t.Error("期望空自定义字符集时返回错误")
		}
	})

	t.Run("性能测试", func(t *testing.T) {
		options := GenerateOptions{
			Length:         20,
			IncludeLower:   true,
			IncludeUpper:   true,
			IncludeNumbers: true,
			IncludeSymbols: true,
		}

		// 生成大量密码，测试性能
		for i := 0; i < 1000; i++ {
			_, err := generator.GeneratePassword(options)
			if err != nil {
				t.Fatalf("第 %d 次生成密码失败: %v", i, err)
			}
		}
	})
}
