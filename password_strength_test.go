package main

import (
	"testing"
)

func TestPasswordStrengthChecker(t *testing.T) {
	checker := NewPasswordStrengthChecker(true)

	t.Run("空密码测试", func(t *testing.T) {
		result := checker.CheckStrength("")

		if result.Score != 0 {
			t.Errorf("期望分数为 0，实际为 %d", result.Score)
		}

		if result.Level != StrengthWeak {
			t.Errorf("期望强度级别为 %s，实际为 %s", StrengthWeak, result.Level)
		}

		if len(result.Feedback) == 0 {
			t.Error("期望有反馈信息")
		}

		if result.Entropy != 0 {
			t.Errorf("期望熵值为 0，实际为 %f", result.Entropy)
		}
	})

	t.Run("弱密码测试", func(t *testing.T) {
		result := checker.CheckStrength("123")

		if result.Score >= 30 {
			t.Errorf("期望分数小于 30，实际为 %d", result.Score)
		}

		if result.Level != StrengthWeak {
			t.Errorf("期望强度级别为 %s，实际为 %s", StrengthWeak, result.Level)
		}

		if len(result.Feedback) == 0 {
			t.Error("期望有反馈信息")
		}
	})

	t.Run("中等密码测试", func(t *testing.T) {
		result := checker.CheckStrength("Test123")

		if result.Score < 30 || result.Score >= 60 {
			t.Errorf("期望分数在 30-59 之间，实际为 %d", result.Score)
		}

		if result.Level != StrengthMedium {
			t.Errorf("期望强度级别为 %s，实际为 %s", StrengthMedium, result.Level)
		}
	})

	t.Run("强密码测试", func(t *testing.T) {
		result := checker.CheckStrength("MyStr0ngP@ssw0rd!")

		if result.Score < 60 {
			t.Errorf("期望分数至少为 60，实际为 %d", result.Score)
		}

		if result.Level == StrengthWeak {
			t.Errorf("强密码不应该被评为弱密码，实际级别为 %s", result.Level)
		}

		if result.Entropy <= 0 {
			t.Errorf("期望熵值大于 0，实际为 %f", result.Entropy)
		}
	})

	t.Run("字符多样性测试", func(t *testing.T) {
		// 只有小写字母
		result1 := checker.CheckStrength("abcdefghijk")

		// 包含大小写字母、数字和特殊字符
		result2 := checker.CheckStrength("AbC123!@#")

		if result2.Score <= result1.Score {
			t.Error("包含多种字符类型的密码应该有更高的分数")
		}
	})

	t.Run("长度影响测试", func(t *testing.T) {
		// 短密码
		result1 := checker.CheckStrength("Abc1!")

		// 长密码
		result2 := checker.CheckStrength("Abc123!@#DefGhi")

		if result2.Score <= result1.Score {
			t.Error("更长的密码应该有更高的分数")
		}
	})

	t.Run("常见密码检测", func(t *testing.T) {
		result := checker.CheckStrength("password")

		// 检查是否检测到常见密码
		foundCommonPasswordFeedback := false
		for _, feedback := range result.Feedback {
			if feedback == "避免使用常见密码" {
				foundCommonPasswordFeedback = true
				break
			}
		}

		if !foundCommonPasswordFeedback {
			t.Error("应该检测到常见密码")
		}
	})

	t.Run("连续字符检测", func(t *testing.T) {
		result := checker.CheckStrength("abc123XYZ")

		// 检查是否检测到连续字符
		foundSequentialFeedback := false
		for _, feedback := range result.Feedback {
			if feedback == "避免使用连续字符" {
				foundSequentialFeedback = true
				break
			}
		}

		if !foundSequentialFeedback {
			t.Error("应该检测到连续字符")
		}
	})

	t.Run("重复字符检测", func(t *testing.T) {
		result := checker.CheckStrength("aaa123BBB")

		// 检查是否检测到重复字符
		foundRepeatedFeedback := false
		for _, feedback := range result.Feedback {
			if feedback == "避免重复字符" {
				foundRepeatedFeedback = true
				break
			}
		}

		if !foundRepeatedFeedback {
			t.Error("应该检测到重复字符")
		}
	})

	t.Run("键盘模式检测", func(t *testing.T) {
		result := checker.CheckStrength("qwerty123")

		// 检查是否检测到键盘模式
		foundKeyboardFeedback := false
		for _, feedback := range result.Feedback {
			if feedback == "避免使用键盘模式" {
				foundKeyboardFeedback = true
				break
			}
		}

		if !foundKeyboardFeedback {
			t.Error("应该检测到键盘模式")
		}
	})

	t.Run("熵值计算测试", func(t *testing.T) {
		// 只有小写字母的密码
		result1 := checker.CheckStrength("abcdefgh")

		// 包含多种字符类型的密码
		result2 := checker.CheckStrength("AbC123!@")

		if result2.Entropy <= result1.Entropy {
			t.Error("包含更多字符类型的密码应该有更高的熵值")
		}
	})

	t.Run("破解时间估算测试", func(t *testing.T) {
		// 弱密码
		result1 := checker.CheckStrength("123")

		// 强密码
		result2 := checker.CheckStrength("MyVeryStr0ngP@ssw0rd2024!")

		if result1.TimeToCrack == result2.TimeToCrack {
			t.Error("不同强度的密码应该有不同的破解时间估算")
		}

		// 弱密码应该很快被破解
		if result1.TimeToCrack != "几秒钟" && result1.TimeToCrack != "几分钟" {
			t.Errorf("弱密码的破解时间估算不正确: %s", result1.TimeToCrack)
		}
	})
}

func TestPasswordManagerStrengthIntegration(t *testing.T) {
	config := DefaultPasswordManagerConfig()
	pm := NewPasswordManager(config)

	t.Run("密码管理器强度检测集成", func(t *testing.T) {
		// 测试弱密码
		result1 := pm.CheckStrength("123")
		if result1.Level != StrengthWeak {
			t.Errorf("期望弱密码级别为 %s，实际为 %s", StrengthWeak, result1.Level)
		}

		// 测试强密码
		result2 := pm.CheckStrength("MyStr0ngP@ssw0rd!")
		if result2.Level == StrengthWeak {
			t.Error("强密码不应该被评为弱密码")
		}

		// 验证强度检测结果包含所有必要字段
		if result2.Score <= 0 {
			t.Error("密码分数应该大于 0")
		}

		if result2.Entropy <= 0 {
			t.Error("密码熵值应该大于 0")
		}

		if result2.TimeToCrack == "" {
			t.Error("应该有破解时间估算")
		}
	})

	t.Run("配置更新影响强度检测", func(t *testing.T) {
		// 禁用字典检查
		newConfig := DefaultPasswordManagerConfig()
		newConfig.EnableDictionaryCheck = false
		pm.UpdateConfig(newConfig)

		result := pm.CheckStrength("password")

		// 检查是否没有常见密码的反馈（因为字典检查被禁用）
		foundCommonPasswordFeedback := false
		for _, feedback := range result.Feedback {
			if feedback == "避免使用常见密码" {
				foundCommonPasswordFeedback = true
				break
			}
		}

		if foundCommonPasswordFeedback {
			t.Error("禁用字典检查后不应该检测到常见密码")
		}
	})

	t.Run("IsPasswordStrong 方法测试", func(t *testing.T) {
		// 测试弱密码
		if pm.IsPasswordStrong("123") {
			t.Error("弱密码不应该被认为是强密码")
		}

		// 测试强密码
		if !pm.IsPasswordStrong("MyVeryStr0ngP@ssw0rd2024!") {
			t.Error("强密码应该被认为是强密码")
		}
	})
}

func TestPasswordStrengthEdgeCases(t *testing.T) {
	checker := NewPasswordStrengthChecker(true)

	t.Run("极长密码测试", func(t *testing.T) {
		longPassword := "ThisIsAVeryLongPasswordWithManyCharactersIncludingNumbers123AndSymbols!@#"
		result := checker.CheckStrength(longPassword)

		if result.Score <= 60 {
			t.Errorf("极长密码应该有高分数，实际为 %d", result.Score)
		}
	})

	t.Run("只有特殊字符的密码", func(t *testing.T) {
		result := checker.CheckStrength("!@#$%^&*()")

		// 应该有关于缺少其他字符类型的反馈
		if len(result.Feedback) == 0 {
			t.Error("应该有关于字符多样性的反馈")
		}
	})

	t.Run("重复字符边界测试", func(t *testing.T) {
		// 2个重复字符（不应该触发）
		result1 := checker.CheckStrength("aa123")

		// 3个重复字符（应该触发）
		result2 := checker.CheckStrength("aaa123")

		// result2 应该有更多的负面反馈
		if len(result2.Feedback) <= len(result1.Feedback) {
			t.Error("更多重复字符的密码应该有更多反馈")
		}
	})

	t.Run("字典检查开关测试", func(t *testing.T) {
		// 启用字典检查
		checkerEnabled := NewPasswordStrengthChecker(true)
		result1 := checkerEnabled.CheckStrength("password")

		// 禁用字典检查
		checkerDisabled := NewPasswordStrengthChecker(false)
		result2 := checkerDisabled.CheckStrength("password")

		// 启用字典检查的结果应该有更低的分数
		if result1.Score >= result2.Score {
			t.Error("启用字典检查时，常见密码应该有更低的分数")
		}
	})
}
