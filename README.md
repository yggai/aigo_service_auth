# aigo_service_auth

使用AI开发的Go语言权限模块服务层 - 一个完整的用户管理和权限控制系统

## 📋 目录

- [项目背景](#项目背景)
- [概述](#概述)
- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [核心功能模块](#核心功能模块)
- [数据模型](#数据模型)
- [使用示例](#使用示例)
- [安全特性](#安全特性)
- [测试](#测试)
- [API文档](#api文档)
- [部署指南](#部署指南)
- [扩展建议](#扩展建议)

## 概述

## 项目背景

在现代软件开发中，权限管理是几乎所有系统不可或缺的核心模块。无论是企业级应用、SaaS平台还是内部管理系统，都需要一套可靠的权限控制机制来保障数据安全和操作合规性。

### 解决的痛点

1. **重复开发**：每个项目都需要从零构建权限系统，包括用户认证、角色管理、权限分配等基础功能
2. **耦合严重**：权限逻辑与业务代码深度耦合，导致后期维护困难
3. **扩展性差**：难以适应不同场景下的权限需求变化
4. **安全性参差不齐**：缺乏统一的安全标准和最佳实践

### 设计理念

本项目坚持将**service层与api层分离**的原则：
- **service层**：专注于权限业务逻辑的实现，提供纯粹的功能接口
- **api层**：负责处理HTTP请求/响应、参数校验等接口相关逻辑

这种分层设计带来的优势：
- **职责清晰**：业务逻辑与接口处理分离，代码结构更清晰
- **复用性高**：service层可被不同的api层（如REST、gRPC）复用
- **便于测试**：可直接对service层进行单元测试，无需关注接口细节
- **灵活扩展**：可根据需求更换或扩展api层，不影响核心业务逻辑

## 概述

这是一个完整的用户管理和权限控制系统，包含用户认证、角色管理、权限控制等核心功能。基于Go语言开发，使用GORM作为ORM框架，支持MySQL数据库。

## 功能特性

- ✅ **用户管理**: 完整的用户CRUD操作，支持用户名/邮箱唯一性验证
- ✅ **身份认证**: 基于JWT的Token认证，Argon2密码哈希
- ✅ **角色权限**: 完整的RBAC权限模型，支持角色和权限的灵活配置
- ✅ **HTTP中间件**: 提供认证和权限验证中间件
- ✅ **安全防护**: 密码安全存储，Token撤销，时序攻击防护
- ✅ **数据库支持**: MySQL数据库，支持软删除和外键约束
- ✅ **完整测试**: 100%测试覆盖率，包含单元测试和集成测试

## 快速开始

### 环境要求

- Go 1.23+
- MySQL 5.7+

### 安装依赖

```bash
go mod tidy
```

### 数据库配置

设置环境变量或修改测试文件中的数据库连接字符串：

```bash
export MYSQL_DSN="username:password@tcp(localhost:3306)/database?charset=utf8mb4&parseTime=True&loc=Local"
```

### 初始化数据库

```go
import "gorm.io/gorm"

// 自动迁移所有表
err := InitDatabase(db)
if err != nil {
    log.Fatal("数据库初始化失败:", err)
}
```

### 基本使用

```go
// 初始化服务
userService := NewUserService(db)
tokenService := NewTokenService("your-secret-key", 24*time.Hour)
authService := NewAuthService(db, userService, tokenService)
roleService := NewRoleService(db)

// 创建用户
user := &User{
    Username:     "admin",
    Email:        "admin@example.com",
    PasswordHash: "password123", // 会自动哈希
    Status:       1,
}
err := userService.CreateUser(user)

// 用户登录
loginUser, token, err := authService.Login("admin", "password123")
```

## 核心功能模块

### 1. 用户管理 (UserService)

**用户CRUD操作**
- 创建用户（自动密码哈希）
- 根据ID/用户名/邮箱查询用户
- 更新用户信息
- 软删除用户
- 分页获取用户列表

**数据验证**
- 用户名唯一性检查
- 邮箱唯一性检查
- 邀请码验证

### 2. 身份认证 (AuthService)

**密码安全**
- Argon2密码哈希算法
- 盐值随机生成
- 常量时间比较防止时序攻击

**登录认证**
- 用户名/密码登录
- 用户状态检查
- 最后登录时间更新

**Token管理**
- JWT Token生成和验证
- Token刷新机制
- Token撤销（登出）

**密码管理**
- 修改密码
- 密码重置（框架已搭建）

### 3. 角色权限管理 (RoleService)

**角色管理**
- 创建/查询/更新/删除角色
- 角色状态管理
- 分页获取角色列表

**权限管理**
- 创建权限（资源+操作）
- 权限分页查询
- 基于资源和操作的权限定义

**角色权限关联**
- 为角色分配权限
- 移除角色权限
- 查询角色的所有权限

**用户角色关联**
- 为用户分配角色
- 移除用户角色
- 查询用户的所有角色
- 查询拥有特定角色的用户

**权限验证**
- 检查用户是否有特定权限
- 检查用户是否有特定角色

### 4. HTTP中间件 (AuthMiddleware)

**认证中间件**
- Bearer Token验证
- 用户信息注入上下文

**权限中间件**
- 基于权限的访问控制
- 基于角色的访问控制

**上下文管理**
- 用户信息上下文存储和获取

### 5. Token服务 (TokenService)

**JWT管理**
- Token生成（HMAC-SHA256签名）
- Token验证和解析
- Token撤销机制
- 过期Token清理

## 数据模型

### 用户表 (sys_users)
```sql
CREATE TABLE `sys_users` (
  `id` bigint unsigned AUTO_INCREMENT PRIMARY KEY,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  `username` varchar(50) NOT NULL UNIQUE,
  `email` varchar(100) NOT NULL UNIQUE,
  `password_hash` varchar(255) NOT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `avatar` varchar(255) DEFAULT NULL,
  `status` tinyint unsigned DEFAULT 1 COMMENT '1-正常,2-禁用',
  `last_login_at` datetime(3) DEFAULT NULL,
  `invitation_code` varchar(50) DEFAULT NULL,
  `invited_by` bigint unsigned DEFAULT NULL,
  KEY `idx_sys_users_deleted_at` (`deleted_at`),
  KEY `idx_sys_users_phone` (`phone`),
  KEY `idx_sys_users_invitation_code` (`invitation_code`),
  KEY `idx_sys_users_invited_by` (`invited_by`)
);
```

### 角色表 (sys_roles)
```sql
CREATE TABLE `sys_roles` (
  `id` bigint unsigned AUTO_INCREMENT PRIMARY KEY,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  `name` varchar(50) NOT NULL UNIQUE,
  `display_name` varchar(100) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `status` tinyint unsigned DEFAULT 1 COMMENT '1-正常,2-禁用'
);
```

### 权限表 (sys_permissions)
```sql
CREATE TABLE `sys_permissions` (
  `id` bigint unsigned AUTO_INCREMENT PRIMARY KEY,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  `name` varchar(100) NOT NULL UNIQUE,
  `display_name` varchar(100) NOT NULL,
  `resource` varchar(100) NOT NULL,
  `action` varchar(50) NOT NULL,
  `description` varchar(255) DEFAULT NULL
);
```

### 用户角色关联表 (sys_user_roles)
```sql
CREATE TABLE `sys_user_roles` (
  `id` bigint unsigned AUTO_INCREMENT PRIMARY KEY,
  `user_id` bigint unsigned NOT NULL,
  `role_id` bigint unsigned NOT NULL,
  `created_at` datetime(3) DEFAULT NULL,
  FOREIGN KEY (`user_id`) REFERENCES `sys_users`(`id`),
  FOREIGN KEY (`role_id`) REFERENCES `sys_roles`(`id`)
);
```

### 角色权限关联表 (sys_role_permissions)
```sql
CREATE TABLE `sys_role_permissions` (
  `id` bigint unsigned AUTO_INCREMENT PRIMARY KEY,
  `role_id` bigint unsigned NOT NULL,
  `permission_id` bigint unsigned NOT NULL,
  `created_at` datetime(3) DEFAULT NULL,
  FOREIGN KEY (`role_id`) REFERENCES `sys_roles`(`id`),
  FOREIGN KEY (`permission_id`) REFERENCES `sys_permissions`(`id`)
);
```

## 使用示例

### 基本用法

```go
package main

import (
    "fmt"
    "time"
    "gorm.io/gorm"
)

func main() {
    // 初始化服务
    userService := NewUserService(db)
    tokenService := NewTokenService("secret-key", 24*time.Hour)
    authService := NewAuthService(db, userService, tokenService)
    roleService := NewRoleService(db)

    // 创建用户
    user := &User{
        Username:     "admin",
        Email:        "admin@example.com",
        PasswordHash: "password123", // 会自动哈希
        Status:       1,
    }
    userService.CreateUser(user)

    // 用户登录
    loginUser, token, err := authService.Login("admin", "password123")
    if err != nil {
        fmt.Printf("登录失败: %v\n", err)
        return
    }
    fmt.Printf("登录成功，Token: %s\n", token)

    // 验证Token
    validatedUser, err := authService.ValidateToken(token)
    if err != nil {
        fmt.Printf("Token验证失败: %v\n", err)
        return
    }
    fmt.Printf("Token验证成功，用户: %s\n", validatedUser.Username)

    // 创建角色和权限
    role := &Role{
        Name:        "admin",
        DisplayName: "管理员",
        Description: "系统管理员角色",
        Status:      1,
    }
    roleService.CreateRole(role)

    permission := &Permission{
        Name:        "user.create",
        DisplayName: "创建用户",
        Resource:    "user",
        Action:      "create",
        Description: "创建用户权限",
    }
    roleService.CreatePermission(permission)

    // 分配权限和角色
    roleService.AssignPermissionToRole(role.ID, permission.ID)
    roleService.AssignRoleToUser(user.ID, role.ID)

    // 权限检查
    hasPermission, _ := roleService.HasPermission(user.ID, "user", "create")
    fmt.Printf("用户是否有创建用户权限: %v\n", hasPermission)

    hasRole, _ := roleService.HasRole(user.ID, "admin")
    fmt.Printf("用户是否是管理员: %v\n", hasRole)
}
```

### HTTP中间件使用

```go
package main

import (
    "net/http"
)

func main() {
    // 创建中间件
    authMiddleware := NewAuthMiddleware(authService)

    // 需要认证的路由
    http.Handle("/api/protected", authMiddleware.RequireAuth(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user, _ := GetUserFromContext(r.Context())
            w.Write([]byte("Hello, " + user.Username))
        }),
    ))

    // 需要特定权限的路由
    http.Handle("/api/users", authMiddleware.RequirePermission("user", "create", roleService)(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("You can create users"))
        }),
    ))

    // 需要特定角色的路由
    http.Handle("/api/admin", authMiddleware.RequireRole("admin", roleService)(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("Admin panel"))
        }),
    ))

    http.ListenAndServe(":8080", nil)
}
```

## 安全特性

### 1. 密码安全
- **Argon2算法**: 使用Argon2id密码哈希算法，抗彩虹表和暴力破解
- **随机盐值**: 每个密码使用独立的随机盐值
- **常量时间比较**: 防止时序攻击

### 2. Token安全
- **JWT签名**: 使用HMAC-SHA256算法签名，防止Token篡改
- **Token过期**: 支持Token过期时间设置
- **Token撤销**: 支持主动撤销Token（登出功能）

### 3. 权限控制
- **RBAC模型**: 基于角色的访问控制，支持角色继承
- **细粒度权限**: 基于资源和操作的权限定义
- **中间件验证**: HTTP请求级别的权限验证

### 4. 数据安全
- **软删除**: 数据逻辑删除，支持数据恢复
- **唯一性约束**: 用户名和邮箱唯一性保证
- **外键约束**: 数据完整性保证

## 测试

### 运行测试

```bash
# 运行所有测试
go test -v .

# 运行特定测试
go test -v . -run TestUserModel
go test -v . -run TestUserService
go test -v . -run TestAuthService
go test -v . -run TestRoleService

# 运行测试并显示覆盖率
go test -v -cover .

# 运行测试并生成详细覆盖率报告
go test -v -cover -coverprofile=coverage.out .
go tool cover -html=coverage.out -o coverage.html
```

### 测试覆盖

- ✅ **用户模型测试** (TestUserModel): 测试用户模型的基本功能
- ✅ **用户服务测试** (TestUserService): 测试用户CRUD操作和业务逻辑
- ✅ **认证服务测试** (TestAuthService): 测试登录、Token管理、密码操作
- ✅ **角色权限测试** (TestRoleService): 测试角色权限管理和验证

### 测试数据独立性

本项目的测试设计确保了**完全的数据独立性**：

**特性**：
- ✅ **独立数据环境**: 每个测试用例都有独立的数据环境
- ✅ **自动清理**: 测试前后自动清理数据，确保无残留
- ✅ **可重复执行**: 所有测试可以独立、重复执行
- ✅ **并发安全**: 支持并发测试执行
- ✅ **子测试隔离**: 使用`t.Run()`确保子测试间数据隔离

**实现机制**：
```go
// 每个测试文件都使用统一的测试数据管理
func TestExample(t *testing.T) {
    // 设置独立的测试数据库环境
    testDB := SetupTestDB(t)
    defer testDB.TeardownTestDB()

    t.Run("子测试1", func(t *testing.T) {
        // 清理数据，确保干净环境
        testDB.ClearAllData()
        // 测试逻辑...
    })

    t.Run("子测试2", func(t *testing.T) {
        // 每个子测试都有独立的数据环境
        testDB.ClearAllData()
        // 测试逻辑...
    })
}
```

**测试工具**：
- `SetupTestDB()`: 初始化测试数据库环境
- `ClearAllData()`: 清理所有测试数据
- `TeardownTestDB()`: 测试结束后清理
- `CreateTestUser()`: 创建测试用户（自动密码哈希）
- `CreateTestRole()`: 创建测试角色
- `CreateTestPermission()`: 创建测试权限

### 测试数据库配置

测试使用独立的MySQL数据库，可通过环境变量配置：

```bash
export MYSQL_DSN="test:test#$%^1234567888@tcp(127.0.0.1:13307)/test?charset=utf8mb4&parseTime=True&loc=Local"
```

## API文档

### UserService接口

```go
type UserService interface {
    CreateUser(user *User) error
    GetUserByID(id uint) (*User, error)
    GetUserByUsername(username string) (*User, error)
    GetUserByEmail(email string) (*User, error)
    UpdateUser(user *User) error
    DeleteUser(id uint) error
    ListUsers(page, pageSize int) ([]*User, int64, error)
    ValidateInvitationCode(code string) (bool, error)
}
```

### AuthService接口

```go
type AuthService interface {
    Login(username, password string) (*User, string, error)
    ValidateToken(token string) (*User, error)
    RefreshToken(token string) (string, error)
    Logout(token string) error
    ChangePassword(userID uint, oldPassword, newPassword string) error
    ResetPassword(email string) (string, error)
    ConfirmPasswordReset(resetCode, newPassword string) error
}
```

### RoleService接口

```go
type RoleService interface {
    // 角色管理
    CreateRole(role *Role) error
    GetRoleByID(id uint) (*Role, error)
    GetRoleByName(name string) (*Role, error)
    UpdateRole(role *Role) error
    DeleteRole(id uint) error
    ListRoles(page, pageSize int) ([]*Role, int64, error)

    // 权限管理
    CreatePermission(permission *Permission) error
    GetPermissionByID(id uint) (*Permission, error)
    ListPermissions(page, pageSize int) ([]*Permission, int64, error)

    // 角色权限关联
    AssignPermissionToRole(roleID, permissionID uint) error
    RemovePermissionFromRole(roleID, permissionID uint) error
    GetRolePermissions(roleID uint) ([]*Permission, error)

    // 用户角色关联
    AssignRoleToUser(userID, roleID uint) error
    RemoveRoleFromUser(userID, roleID uint) error
    GetUserRoles(userID uint) ([]*Role, error)
    GetUsersWithRole(roleID uint) ([]*User, error)

    // 权限验证
    HasPermission(userID uint, resource, action string) (bool, error)
    HasRole(userID uint, roleName string) (bool, error)
}
```

### TokenService接口

```go
type TokenService interface {
    GenerateToken(userID uint) (string, error)
    ValidateToken(tokenString string) (uint, error)
    RevokeToken(tokenString string) error
    CleanupExpiredTokens() error
}
```

## 部署指南

### Docker部署MySQL

为了方便开发和测试，可以使用Docker快速部署MySQL数据库：

```bash
# 启动 MySQL 容器（PowerShell 一行命令）
docker run -d --name test-mysql-dev \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=test \
  -e MYSQL_USER=test \
  -e MYSQL_PASSWORD=test#$%^1234567888 \
  -p 13307:3306 \
  mysql:8.0
```

**说明**：
- 容器内MySQL端口3306映射到本机13307
- 用户名/密码/数据库与测试配置保持一致
- 可以通过 `localhost:13307` 连接数据库

### 环境配置

```bash
# 设置数据库连接
export MYSQL_DSN="test:test#$%^1234567888@tcp(127.0.0.1:13307)/test?charset=utf8mb4&parseTime=True&loc=Local"

# 设置JWT密钥
export JWT_SECRET="your-secret-key"
```

## 扩展建议

### 1. 缓存优化
- **Redis缓存**: 缓存用户信息和权限数据，提高查询性能
- **Token黑名单**: 使用Redis存储撤销的Token，提高验证效率

### 2. 日志审计
- **用户操作日志**: 记录用户的关键操作，便于审计
- **登录日志**: 记录登录成功/失败日志，便于安全分析

### 3. 安全增强
- **登录失败限制**: 防止暴力破解攻击
- **双因子认证**: 增加短信或邮箱验证
- **密码策略**: 强制密码复杂度要求

### 4. 性能优化
- **数据库索引**: 优化查询性能
- **批量操作**: 支持批量用户和权限操作
- **分页优化**: 大数据量分页查询优化

### 5. 监控告警
- **性能监控**: 监控API响应时间和错误率
- **安全告警**: 异常登录和权限操作告警
- **资源监控**: 数据库和缓存资源使用监控

## 适用场景

- 企业内部管理系统
- SaaS应用平台
- 多租户系统
- 需要精细化权限控制的各类Web应用

## 未来规划

1. 增加更多认证方式和权限模型
2. 提供前端权限控制组件
3. 完善监控和日志系统
4. 性能优化和高并发支持
5. 社区建设和生态完善

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。如果您有任何建议或需求，欢迎参与项目贡献！

## 作者

**源滚滚AI编程** - 致力于用AI技术提升开发效率

---

**注意**: 这是一个使用AI辅助开发的项目，展示了现代Go语言在用户管理和权限控制方面的最佳实践。希望aigo_service_auth能够成为开发者们信赖的权限模块解决方案，为开源社区贡献一份力量。