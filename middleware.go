package main

import (
	"context"
	"net/http"
	"strings"
)

// ContextKey 上下文键类型
type ContextKey string

const (
	// UserContextKey 用户上下文键
	UserContextKey ContextKey = "user"
)

// AuthMiddleware 认证中间件
type AuthMiddleware struct {
	authService AuthService
}

// NewAuthMiddleware 创建认证中间件
func NewAuthMiddleware(authService AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}

// RequireAuth 需要认证的中间件
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 从请求头获取Token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "缺少认证信息", http.StatusUnauthorized)
			return
		}

		// 解析Bearer Token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "无效的认证格式", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// 验证Token
		user, err := m.authService.ValidateToken(token)
		if err != nil {
			http.Error(w, "认证失败: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// 将用户信息添加到上下文
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission 需要特定权限的中间件
func (m *AuthMiddleware) RequirePermission(resource, action string, roleService RoleService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 先进行认证
			m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 从上下文获取用户
				user, ok := r.Context().Value(UserContextKey).(*User)
				if !ok {
					http.Error(w, "用户信息获取失败", http.StatusInternalServerError)
					return
				}

				// 检查权限
				hasPermission, err := roleService.HasPermission(user.ID, resource, action)
				if err != nil {
					http.Error(w, "权限检查失败", http.StatusInternalServerError)
					return
				}

				if !hasPermission {
					http.Error(w, "权限不足", http.StatusForbidden)
					return
				}

				next.ServeHTTP(w, r)
			})).ServeHTTP(w, r)
		})
	}
}

// RequireRole 需要特定角色的中间件
func (m *AuthMiddleware) RequireRole(roleName string, roleService RoleService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 先进行认证
			m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 从上下文获取用户
				user, ok := r.Context().Value(UserContextKey).(*User)
				if !ok {
					http.Error(w, "用户信息获取失败", http.StatusInternalServerError)
					return
				}

				// 检查角色
				hasRole, err := roleService.HasRole(user.ID, roleName)
				if err != nil {
					http.Error(w, "角色检查失败", http.StatusInternalServerError)
					return
				}

				if !hasRole {
					http.Error(w, "角色权限不足", http.StatusForbidden)
					return
				}

				next.ServeHTTP(w, r)
			})).ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext 从上下文获取用户信息
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(UserContextKey).(*User)
	return user, ok
}
