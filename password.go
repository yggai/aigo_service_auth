package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// 默认生成选项
func DefaultGenerateOptions() GenerateOptions {
	return GenerateOptions{
		Length:           12,
		IncludeLower:     true,
		IncludeUpper:     true,
		IncludeNumbers:   true,
		IncludeSymbols:   true,
		ExcludeAmbiguous: true,
		CustomCharset:    "",
	}
}

// 字符集常量
const (
	LowerChars     = "abcdefghijklmnopqrstuvwxyz"
	UpperChars     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	NumberChars    = "0123456789"
	SymbolChars    = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	AmbiguousChars = "0O1lI|`"
)

// 强度级别常量
const (
	StrengthWeak       = "Weak"
	StrengthMedium     = "Medium"
	StrengthStrong     = "Strong"
	StrengthVeryStrong = "VeryStrong"
)

// 常见密码列表（简化版，实际应用中应该使用更完整的列表）
var commonPasswords = map[string]bool{
	"password":    true,
	"123456":      true,
	"123456789":   true,
	"qwerty":      true,
	"abc123":      true,
	"password123": true,
	"admin":       true,
	"letmein":     true,
	"welcome":     true,
	"monkey":      true,
	"dragon":      true,
	"master":      true,
	"shadow":      true,
	"superman":    true,
	"michael":     true,
	"football":    true,
	"baseball":    true,
	"liverpool":   true,
}

// 模式检测正则表达式
var (
	sequentialPattern = regexp.MustCompile(`(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)`)
	keyboardPattern   = regexp.MustCompile(`(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)`)
)

// PasswordStrengthChecker 密码强度检测器
type PasswordStrengthChecker struct {
	enableDictionaryCheck bool
}

// NewPasswordStrengthChecker 创建密码强度检测器
func NewPasswordStrengthChecker(enableDictionaryCheck bool) *PasswordStrengthChecker {
	return &PasswordStrengthChecker{
		enableDictionaryCheck: enableDictionaryCheck,
	}
}

// CheckStrength 检测密码强度
func (c *PasswordStrengthChecker) CheckStrength(password string) PasswordStrength {
	if password == "" {
		return PasswordStrength{
			Score:       0,
			Level:       StrengthWeak,
			Feedback:    []string{"密码不能为空"},
			Entropy:     0,
			TimeToCrack: "立即",
		}
	}

	score := 0
	feedback := []string{}

	// 长度检查
	length := len(password)
	if length < 8 {
		feedback = append(feedback, "密码长度至少需要8个字符")
	} else if length >= 8 && length < 12 {
		score += 20
	} else if length >= 12 && length < 16 {
		score += 30
	} else {
		score += 40
	}

	// 字符多样性检查
	hasLower := strings.ContainsAny(password, LowerChars)
	hasUpper := strings.ContainsAny(password, UpperChars)
	hasNumbers := strings.ContainsAny(password, NumberChars)
	hasSymbols := strings.ContainsAny(password, SymbolChars)

	charTypeCount := 0
	if hasLower {
		charTypeCount++
	} else {
		feedback = append(feedback, "建议包含小写字母")
	}

	if hasUpper {
		charTypeCount++
	} else {
		feedback = append(feedback, "建议包含大写字母")
	}

	if hasNumbers {
		charTypeCount++
	} else {
		feedback = append(feedback, "建议包含数字")
	}

	if hasSymbols {
		charTypeCount++
	} else {
		feedback = append(feedback, "建议包含特殊字符")
	}

	// 根据字符类型数量加分
	score += charTypeCount * 10

	// 唯一字符检查
	uniqueChars := c.countUniqueChars(password)
	if uniqueChars < length/2 {
		feedback = append(feedback, "密码中重复字符过多")
	} else {
		score += 10
	}

	// 模式检查
	if c.hasSequentialPattern(password) {
		score -= 10
		feedback = append(feedback, "避免使用连续字符")
	}

	if c.hasRepeatedPattern(password) {
		score -= 10
		feedback = append(feedback, "避免重复字符")
	}

	if c.hasKeyboardPattern(password) {
		score -= 10
		feedback = append(feedback, "避免使用键盘模式")
	}

	// 字典检查
	if c.enableDictionaryCheck && c.isCommonPassword(password) {
		score -= 20
		feedback = append(feedback, "避免使用常见密码")
	}

	// 确保分数在0-100范围内
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	// 计算熵值
	entropy := c.calculateEntropy(password)

	// 确定强度级别
	level := c.getStrengthLevel(score)

	// 估算破解时间
	timeToCrack := c.estimateTimeToCrack(entropy)

	return PasswordStrength{
		Score:       score,
		Level:       level,
		Feedback:    feedback,
		Entropy:     entropy,
		TimeToCrack: timeToCrack,
	}
}

// countUniqueChars 计算唯一字符数量
func (c *PasswordStrengthChecker) countUniqueChars(password string) int {
	charSet := make(map[rune]bool)
	for _, char := range password {
		charSet[char] = true
	}
	return len(charSet)
}

// hasSequentialPattern 检查是否包含连续字符模式
func (c *PasswordStrengthChecker) hasSequentialPattern(password string) bool {
	return sequentialPattern.MatchString(strings.ToLower(password))
}

// hasRepeatedPattern 检查是否包含重复字符模式
func (c *PasswordStrengthChecker) hasRepeatedPattern(password string) bool {
	return hasRepeatedChars(password)
}

// hasKeyboardPattern 检查是否包含键盘模式
func (c *PasswordStrengthChecker) hasKeyboardPattern(password string) bool {
	return keyboardPattern.MatchString(strings.ToLower(password))
}

// isCommonPassword 检查是否为常见密码
func (c *PasswordStrengthChecker) isCommonPassword(password string) bool {
	return commonPasswords[strings.ToLower(password)]
}

// calculateEntropy 计算密码熵值
func (c *PasswordStrengthChecker) calculateEntropy(password string) float64 {
	if password == "" {
		return 0
	}

	// 计算字符集大小
	charsetSize := 0
	if strings.ContainsAny(password, LowerChars) {
		charsetSize += len(LowerChars)
	}
	if strings.ContainsAny(password, UpperChars) {
		charsetSize += len(UpperChars)
	}
	if strings.ContainsAny(password, NumberChars) {
		charsetSize += len(NumberChars)
	}
	if strings.ContainsAny(password, SymbolChars) {
		charsetSize += len(SymbolChars)
	}

	if charsetSize == 0 {
		return 0
	}

	// 熵 = 长度 * log2(字符集大小)
	return float64(len(password)) * math.Log2(float64(charsetSize))
}

// getStrengthLevel 根据分数确定强度级别
func (c *PasswordStrengthChecker) getStrengthLevel(score int) string {
	if score < 30 {
		return StrengthWeak
	} else if score < 60 {
		return StrengthMedium
	} else if score < 80 {
		return StrengthStrong
	} else {
		return StrengthVeryStrong
	}
}

// estimateTimeToCrack 估算破解时间
func (c *PasswordStrengthChecker) estimateTimeToCrack(entropy float64) string {
	if entropy < 20 {
		return "几秒钟"
	} else if entropy < 30 {
		return "几分钟"
	} else if entropy < 40 {
		return "几小时"
	} else if entropy < 50 {
		return "几天"
	} else if entropy < 60 {
		return "几个月"
	} else if entropy < 70 {
		return "几年"
	} else {
		return "几个世纪"
	}
}

// PasswordGenerator 密码生成器
type PasswordGenerator struct {
}

// NewPasswordGenerator 创建密码生成器
func NewPasswordGenerator() *PasswordGenerator {
	return &PasswordGenerator{}
}

// GeneratePassword 生成随机密码
func (g *PasswordGenerator) GeneratePassword(options GenerateOptions) (string, error) {
	// 验证选项
	if err := g.validateOptions(options); err != nil {
		return "", err
	}

	// 构建字符集
	charset := g.buildCharset(options)
	if charset == "" {
		return "", ErrInvalidOptions
	}

	// 生成密码
	password := make([]byte, options.Length)
	for i := 0; i < options.Length; i++ {
		randomIndex, err := g.secureRandomInt(len(charset))
		if err != nil {
			return "", err
		}
		password[i] = charset[randomIndex]
	}

	result := string(password)

	// 确保密码满足所有要求
	if !g.meetsRequirements(result, options) {
		// 如果不满足要求，重新生成（最多尝试10次）
		for attempts := 0; attempts < 10; attempts++ {
			result, err := g.GeneratePassword(options)
			if err != nil {
				return "", err
			}
			if g.meetsRequirements(result, options) {
				return result, nil
			}
		}
		// 如果多次尝试仍不满足，手动调整
		result = g.ensureRequirements(result, options)
	}

	return result, nil
}

// validateOptions 验证生成选项
func (g *PasswordGenerator) validateOptions(options GenerateOptions) error {
	if options.Length <= 0 {
		return ErrInvalidOptions
	}

	if options.Length > 256 {
		return ErrInvalidOptions
	}

	// 如果没有选择任何字符类型且没有自定义字符集
	if !options.IncludeLower && !options.IncludeUpper &&
		!options.IncludeNumbers && !options.IncludeSymbols &&
		options.CustomCharset == "" {
		return ErrInvalidOptions
	}

	return nil
}

// buildCharset 构建字符集
func (g *PasswordGenerator) buildCharset(options GenerateOptions) string {
	if options.CustomCharset != "" {
		charset := options.CustomCharset
		if options.ExcludeAmbiguous {
			charset = g.removeAmbiguousChars(charset)
		}
		return charset
	}

	var charset strings.Builder

	if options.IncludeLower {
		charset.WriteString(LowerChars)
	}

	if options.IncludeUpper {
		charset.WriteString(UpperChars)
	}

	if options.IncludeNumbers {
		charset.WriteString(NumberChars)
	}

	if options.IncludeSymbols {
		charset.WriteString(SymbolChars)
	}

	result := charset.String()
	if options.ExcludeAmbiguous {
		result = g.removeAmbiguousChars(result)
	}

	return result
}

// removeAmbiguousChars 移除易混淆字符
func (g *PasswordGenerator) removeAmbiguousChars(charset string) string {
	var result strings.Builder
	for _, char := range charset {
		if !strings.ContainsRune(AmbiguousChars, char) {
			result.WriteRune(char)
		}
	}
	return result.String()
}

// secureRandomInt 生成安全的随机整数
func (g *PasswordGenerator) secureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, ErrInvalidOptions
	}

	// 使用加密安全的随机数生成器
	randomBytes := make([]byte, 4)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return 0, err
	}

	// 转换为整数并取模
	randomInt := int(randomBytes[0])<<24 | int(randomBytes[1])<<16 | int(randomBytes[2])<<8 | int(randomBytes[3])
	if randomInt < 0 {
		randomInt = -randomInt
	}

	return randomInt % max, nil
}

// meetsRequirements 检查密码是否满足要求
func (g *PasswordGenerator) meetsRequirements(password string, options GenerateOptions) bool {
	if options.CustomCharset != "" {
		return true // 自定义字符集不需要额外检查
	}

	if options.IncludeLower && !strings.ContainsAny(password, LowerChars) {
		return false
	}

	if options.IncludeUpper && !strings.ContainsAny(password, UpperChars) {
		return false
	}

	if options.IncludeNumbers && !strings.ContainsAny(password, NumberChars) {
		return false
	}

	if options.IncludeSymbols && !strings.ContainsAny(password, SymbolChars) {
		return false
	}

	return true
}

// ensureRequirements 确保密码满足要求
func (g *PasswordGenerator) ensureRequirements(password string, options GenerateOptions) string {
	if options.CustomCharset != "" {
		return password // 自定义字符集不需要调整
	}

	result := []rune(password)
	position := 0

	if options.IncludeLower && !strings.ContainsAny(password, LowerChars) {
		if position < len(result) {
			randomIndex, _ := g.secureRandomInt(len(LowerChars))
			result[position] = rune(LowerChars[randomIndex])
			position++
		}
	}

	if options.IncludeUpper && !strings.ContainsAny(password, UpperChars) {
		if position < len(result) {
			randomIndex, _ := g.secureRandomInt(len(UpperChars))
			result[position] = rune(UpperChars[randomIndex])
			position++
		}
	}

	if options.IncludeNumbers && !strings.ContainsAny(password, NumberChars) {
		if position < len(result) {
			randomIndex, _ := g.secureRandomInt(len(NumberChars))
			result[position] = rune(NumberChars[randomIndex])
			position++
		}
	}

	if options.IncludeSymbols && !strings.ContainsAny(password, SymbolChars) {
		if position < len(result) {
			randomIndex, _ := g.secureRandomInt(len(SymbolChars))
			result[position] = rune(SymbolChars[randomIndex])
			position++
		}
	}

	return string(result)
}

// PasswordPolicyValidator 密码策略验证器
type PasswordPolicyValidator struct {
}

// NewPasswordPolicyValidator 创建密码策略验证器
func NewPasswordPolicyValidator() *PasswordPolicyValidator {
	return &PasswordPolicyValidator{}
}

// ValidatePolicy 验证密码策略
func (v *PasswordPolicyValidator) ValidatePolicy(password string, policy PasswordPolicy) PolicyResult {
	violations := []string{}
	score := 100

	// 长度检查
	length := len(password)
	if length < policy.MinLength {
		violations = append(violations, fmt.Sprintf("密码长度不能少于%d个字符", policy.MinLength))
		score -= 20
	}

	if policy.MaxLength > 0 && length > policy.MaxLength {
		violations = append(violations, fmt.Sprintf("密码长度不能超过%d个字符", policy.MaxLength))
		score -= 10
	}

	// 字符要求检查
	if policy.RequireLower && !strings.ContainsAny(password, LowerChars) {
		violations = append(violations, "密码必须包含小写字母")
		score -= 15
	}

	if policy.RequireUpper && !strings.ContainsAny(password, UpperChars) {
		violations = append(violations, "密码必须包含大写字母")
		score -= 15
	}

	if policy.RequireNumbers && !strings.ContainsAny(password, NumberChars) {
		violations = append(violations, "密码必须包含数字")
		score -= 15
	}

	if policy.RequireSymbols && !strings.ContainsAny(password, SymbolChars) {
		violations = append(violations, "密码必须包含特殊字符")
		score -= 15
	}

	// 唯一字符检查
	if policy.MinUniqueChars > 0 {
		uniqueChars := v.countUniqueChars(password)
		if uniqueChars < policy.MinUniqueChars {
			violations = append(violations, fmt.Sprintf("密码至少需要%d个不同的字符", policy.MinUniqueChars))
			score -= 10
		}
	}

	// 重复字符检查
	if policy.MaxRepeatedChars > 0 {
		maxRepeated := v.getMaxRepeatedChars(password)
		if maxRepeated > policy.MaxRepeatedChars {
			violations = append(violations, fmt.Sprintf("连续重复字符不能超过%d个", policy.MaxRepeatedChars))
			score -= 15
		}
	}

	// 禁用模式检查
	for _, pattern := range policy.ForbiddenPatterns {
		if strings.Contains(strings.ToLower(password), strings.ToLower(pattern)) {
			violations = append(violations, fmt.Sprintf("密码不能包含禁用模式: %s", pattern))
			score -= 20
		}
	}

	// 确保分数不为负数
	if score < 0 {
		score = 0
	}

	return PolicyResult{
		Valid:      len(violations) == 0,
		Violations: violations,
		Score:      score,
	}
}

// countUniqueChars 计算唯一字符数量
func (v *PasswordPolicyValidator) countUniqueChars(password string) int {
	charSet := make(map[rune]bool)
	for _, char := range password {
		charSet[char] = true
	}
	return len(charSet)
}

// getMaxRepeatedChars 获取最大连续重复字符数
func (v *PasswordPolicyValidator) getMaxRepeatedChars(password string) int {
	if len(password) == 0 {
		return 0
	}

	maxRepeated := 1
	currentRepeated := 1

	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			currentRepeated++
			if currentRepeated > maxRepeated {
				maxRepeated = currentRepeated
			}
		} else {
			currentRepeated = 1
		}
	}

	return maxRepeated
}

// MemoryHistoryStorage 内存密码历史存储实现
type MemoryHistoryStorage struct {
	histories map[uint][]PasswordHistory
	mutex     sync.RWMutex
}

// NewMemoryHistoryStorage 创建内存历史存储
func NewMemoryHistoryStorage() *MemoryHistoryStorage {
	return &MemoryHistoryStorage{
		histories: make(map[uint][]PasswordHistory),
	}
}

// Add 添加密码历史记录
func (s *MemoryHistoryStorage) Add(userID uint, hash string) error {
	if userID == 0 {
		return ErrInvalidUserID
	}

	if hash == "" {
		return ErrInvalidHash
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	history := PasswordHistory{
		UserID:       userID,
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}

	s.histories[userID] = append(s.histories[userID], history)
	return nil
}

// GetHistory 获取密码历史记录
func (s *MemoryHistoryStorage) GetHistory(userID uint, limit int) ([]PasswordHistory, error) {
	if userID == 0 {
		return nil, ErrInvalidUserID
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	histories, exists := s.histories[userID]
	if !exists {
		return []PasswordHistory{}, nil
	}

	// 按时间倒序排列，返回最新的记录
	result := make([]PasswordHistory, len(histories))
	copy(result, histories)

	// 简单的倒序排列
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}

	return result, nil
}

// Cleanup 清理历史记录
func (s *MemoryHistoryStorage) Cleanup(userID uint, keepCount int) error {
	if userID == 0 {
		return ErrInvalidUserID
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	histories, exists := s.histories[userID]
	if !exists {
		return nil
	}

	if len(histories) <= keepCount {
		return nil
	}

	// 保留最新的keepCount条记录
	// 按时间倒序排列
	for i, j := 0, len(histories)-1; i < j; i, j = i+1, j-1 {
		histories[i], histories[j] = histories[j], histories[i]
	}

	s.histories[userID] = histories[:keepCount]
	return nil
}

// PasswordHistoryManager 密码历史管理器
type PasswordHistoryManager struct {
	storage HistoryStorage
	hasher  *PasswordHasher
}

// NewPasswordHistoryManager 创建密码历史管理器
func NewPasswordHistoryManager(storage HistoryStorage, hasher *PasswordHasher) *PasswordHistoryManager {
	return &PasswordHistoryManager{
		storage: storage,
		hasher:  hasher,
	}
}

// AddToHistory 添加密码到历史记录
func (m *PasswordHistoryManager) AddToHistory(userID uint, passwordHash string) error {
	return m.storage.Add(userID, passwordHash)
}

// CheckHistory 检查密码是否在历史记录中
func (m *PasswordHistoryManager) CheckHistory(userID uint, password string) (bool, error) {
	if password == "" {
		return false, ErrPasswordEmpty
	}

	histories, err := m.storage.GetHistory(userID, 0) // 获取所有历史记录
	if err != nil {
		return false, err
	}

	// 检查密码是否与历史记录中的任何一个匹配
	for _, history := range histories {
		if m.hasher.Verify(password, history.PasswordHash) {
			return true, nil
		}
	}

	return false, nil
}

// CleanupHistory 清理历史记录
func (m *PasswordHistoryManager) CleanupHistory(userID uint, keepCount int) error {
	return m.storage.Cleanup(userID, keepCount)
}

// PasswordManager 密码管理器接口
type PasswordManager interface {
	// 密码加密和校验
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) bool

	// 密码强度检测
	CheckStrength(password string) PasswordStrength
	IsPasswordStrong(password string) bool

	// 随机密码生成
	GeneratePassword(options GenerateOptions) (string, error)
	GenerateWithDefaults() (string, error)

	// 密码策略验证
	ValidatePolicy(password string, policy PasswordPolicy) PolicyResult
	ValidateWithDefaultPolicy(password string) PolicyResult

	// 密码历史管理
	AddToHistory(userID uint, passwordHash string) error
	CheckHistory(userID uint, password string) (bool, error)
	CleanupHistory(userID uint, keepCount int) error
	GetPasswordHistory(userID uint, limit int) ([]PasswordHistory, error)

	// 配置管理
	GetConfig() *PasswordManagerConfig
	UpdateConfig(config *PasswordManagerConfig)
}

// PasswordStrength 密码强度结果
type PasswordStrength struct {
	Score       int      `json:"score"`         // 0-100 分数
	Level       string   `json:"level"`         // Weak/Medium/Strong/VeryStrong
	Feedback    []string `json:"feedback"`      // 改进建议
	Entropy     float64  `json:"entropy"`       // 熵值
	TimeToCrack string   `json:"time_to_crack"` // 预估破解时间
}

// GenerateOptions 密码生成选项
type GenerateOptions struct {
	Length           int    `json:"length"`
	IncludeLower     bool   `json:"include_lower"`
	IncludeUpper     bool   `json:"include_upper"`
	IncludeNumbers   bool   `json:"include_numbers"`
	IncludeSymbols   bool   `json:"include_symbols"`
	ExcludeAmbiguous bool   `json:"exclude_ambiguous"` // 排除易混淆字符
	CustomCharset    string `json:"custom_charset"`
}

// PasswordPolicy 密码策略
type PasswordPolicy struct {
	MinLength         int      `json:"min_length"`
	MaxLength         int      `json:"max_length"`
	RequireLower      bool     `json:"require_lower"`
	RequireUpper      bool     `json:"require_upper"`
	RequireNumbers    bool     `json:"require_numbers"`
	RequireSymbols    bool     `json:"require_symbols"`
	MinUniqueChars    int      `json:"min_unique_chars"`
	ForbiddenPatterns []string `json:"forbidden_patterns"`
	MaxRepeatedChars  int      `json:"max_repeated_chars"`
}

// PolicyResult 策略验证结果
type PolicyResult struct {
	Valid      bool     `json:"valid"`
	Violations []string `json:"violations"`
	Score      int      `json:"score"`
}

// PasswordHistory 密码历史记录
type PasswordHistory struct {
	UserID       uint      `json:"user_id"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// PasswordManagerConfig 密码管理配置
type PasswordManagerConfig struct {
	// 加密配置
	BcryptCost int `json:"bcrypt_cost"`

	// 强度检测配置
	MinStrengthScore      int  `json:"min_strength_score"`
	EnableDictionaryCheck bool `json:"enable_dictionary_check"`

	// 生成配置
	DefaultLength   int      `json:"default_length"`
	DefaultCharsets []string `json:"default_charsets"`

	// 策略配置
	DefaultPolicy PasswordPolicy `json:"default_policy"`

	// 历史配置
	HistoryCount           int           `json:"history_count"`
	HistoryCleanupInterval time.Duration `json:"history_cleanup_interval"`
}

// HistoryStorage 密码历史存储接口
type HistoryStorage interface {
	Add(userID uint, hash string) error
	GetHistory(userID uint, limit int) ([]PasswordHistory, error)
	Cleanup(userID uint, keepCount int) error
}

// 错误定义
var (
	ErrPasswordEmpty     = errors.New("密码不能为空")
	ErrPasswordTooShort  = errors.New("密码长度不足")
	ErrPasswordTooLong   = errors.New("密码长度过长")
	ErrPasswordTooWeak   = errors.New("密码强度不足")
	ErrPasswordInHistory = errors.New("密码与历史密码重复")
	ErrInvalidOptions    = errors.New("生成选项无效")
	ErrHashingFailed     = errors.New("密码加密失败")
	ErrInvalidHash       = errors.New("无效的密码哈希")
	ErrInvalidUserID     = errors.New("无效的用户ID")
	ErrStorageError      = errors.New("存储操作失败")
)

// 默认配置
func DefaultPasswordManagerConfig() *PasswordManagerConfig {
	return &PasswordManagerConfig{
		BcryptCost:            12,
		MinStrengthScore:      60,
		EnableDictionaryCheck: true,
		DefaultLength:         12,
		DefaultCharsets:       []string{"lower", "upper", "numbers", "symbols"},
		DefaultPolicy: PasswordPolicy{
			MinLength:        8,
			MaxLength:        128,
			RequireLower:     true,
			RequireUpper:     true,
			RequireNumbers:   true,
			RequireSymbols:   false,
			MinUniqueChars:   6,
			MaxRepeatedChars: 3,
			ForbiddenPatterns: []string{
				"password", "123456", "qwerty", "admin",
			},
		},
		HistoryCount:           5,
		HistoryCleanupInterval: 24 * time.Hour,
	}
}

// PasswordHasher 密码哈希器
type PasswordHasher struct {
	cost int
}

// NewPasswordHasher 创建密码哈希器
func NewPasswordHasher(cost int) *PasswordHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return &PasswordHasher{cost: cost}
}

// Hash 加密密码
func (h *PasswordHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", ErrPasswordEmpty
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrHashingFailed, err)
	}

	return string(hash), nil
}

// Verify 验证密码
func (h *PasswordHasher) Verify(password, hash string) bool {
	if password == "" || hash == "" {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GetCost 获取当前成本参数
func (h *PasswordHasher) GetCost() int {
	return h.cost
}

// SetCost 设置成本参数
func (h *PasswordHasher) SetCost(cost int) {
	if cost >= bcrypt.MinCost && cost <= bcrypt.MaxCost {
		h.cost = cost
	}
}

// passwordManager 密码管理器实现
type passwordManager struct {
	config          *PasswordManagerConfig
	hasher          *PasswordHasher
	strengthChecker *PasswordStrengthChecker
	generator       *PasswordGenerator
	policyValidator *PasswordPolicyValidator
	historyManager  *PasswordHistoryManager
}

// NewPasswordManager 创建密码管理器
func NewPasswordManager(config *PasswordManagerConfig) PasswordManager {
	if config == nil {
		config = DefaultPasswordManagerConfig()
	}

	hasher := NewPasswordHasher(config.BcryptCost)
	strengthChecker := NewPasswordStrengthChecker(config.EnableDictionaryCheck)
	generator := NewPasswordGenerator()
	policyValidator := NewPasswordPolicyValidator()

	// 创建历史存储和管理器
	historyStorage := NewMemoryHistoryStorage()
	historyManager := NewPasswordHistoryManager(historyStorage, hasher)

	return &passwordManager{
		config:          config,
		hasher:          hasher,
		strengthChecker: strengthChecker,
		generator:       generator,
		policyValidator: policyValidator,
		historyManager:  historyManager,
	}
}

// HashPassword 加密密码
func (pm *passwordManager) HashPassword(password string) (string, error) {
	return pm.hasher.Hash(password)
}

// VerifyPassword 验证密码
func (pm *passwordManager) VerifyPassword(password, hash string) bool {
	return pm.hasher.Verify(password, hash)
}

// CheckStrength 检测密码强度
func (pm *passwordManager) CheckStrength(password string) PasswordStrength {
	return pm.strengthChecker.CheckStrength(password)
}

// GeneratePassword 生成随机密码
func (pm *passwordManager) GeneratePassword(options GenerateOptions) (string, error) {
	return pm.generator.GeneratePassword(options)
}

// GenerateWithDefaults 使用默认选项生成密码
func (pm *passwordManager) GenerateWithDefaults() (string, error) {
	options := GenerateOptions{
		Length:           pm.config.DefaultLength,
		IncludeLower:     true,
		IncludeUpper:     true,
		IncludeNumbers:   true,
		IncludeSymbols:   true,
		ExcludeAmbiguous: true,
	}
	return pm.GeneratePassword(options)
}

// ValidatePolicy 验证密码策略
func (pm *passwordManager) ValidatePolicy(password string, policy PasswordPolicy) PolicyResult {
	return pm.policyValidator.ValidatePolicy(password, policy)
}

// ValidateWithDefaultPolicy 使用默认策略验证密码
func (pm *passwordManager) ValidateWithDefaultPolicy(password string) PolicyResult {
	return pm.ValidatePolicy(password, pm.config.DefaultPolicy)
}

// AddToHistory 添加密码到历史记录
func (pm *passwordManager) AddToHistory(userID uint, passwordHash string) error {
	return pm.historyManager.AddToHistory(userID, passwordHash)
}

// CheckHistory 检查密码是否在历史记录中
func (pm *passwordManager) CheckHistory(userID uint, password string) (bool, error) {
	return pm.historyManager.CheckHistory(userID, password)
}

// CleanupHistory 清理历史记录
func (pm *passwordManager) CleanupHistory(userID uint, keepCount int) error {
	return pm.historyManager.CleanupHistory(userID, keepCount)
}

// GetConfig 获取配置
func (pm *passwordManager) GetConfig() *PasswordManagerConfig {
	return pm.config
}

// UpdateConfig 更新配置
func (pm *passwordManager) UpdateConfig(config *PasswordManagerConfig) {
	if config != nil {
		pm.config = config
		pm.hasher.SetCost(config.BcryptCost)
		pm.strengthChecker = NewPasswordStrengthChecker(config.EnableDictionaryCheck)
	}
}

// IsPasswordStrong 检查密码是否足够强
func (pm *passwordManager) IsPasswordStrong(password string) bool {
	strength := pm.CheckStrength(password)
	return strength.Score >= pm.config.MinStrengthScore
}

// ChangePassword 更改密码（包含历史检查）
func (pm *passwordManager) ChangePassword(userID uint, newPassword string) (string, error) {
	// 检查密码强度
	if !pm.IsPasswordStrong(newPassword) {
		return "", ErrPasswordTooWeak
	}

	// 检查历史记录
	inHistory, err := pm.CheckHistory(userID, newPassword)
	if err != nil {
		return "", err
	}
	if inHistory {
		return "", ErrPasswordInHistory
	}

	// 加密新密码
	hash, err := pm.HashPassword(newPassword)
	if err != nil {
		return "", err
	}

	// 添加到历史记录
	err = pm.AddToHistory(userID, hash)
	if err != nil {
		return "", err
	}

	// 清理旧的历史记录
	err = pm.CleanupHistory(userID, pm.config.HistoryCount)
	if err != nil {
		// 清理失败不影响密码更改
		// 可以记录日志
	}

	return hash, nil
}

// hasRepeatedChars 检查是否有连续重复字符（3个或更多）
func hasRepeatedChars(password string) bool {
	if len(password) < 3 {
		return false
	}

	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count >= 3 {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}
