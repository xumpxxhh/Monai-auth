package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"monai-auth/internal/auth"
	"monai-auth/internal/domain"
)

// Handler 结构体包含对业务服务的依赖
type Handler struct {
	AuthService auth.Service
}

func NewHandler(authService auth.Service) *Handler {
	return &Handler{AuthService: authService}
}

// LoginHandler 处理 /login 请求
func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.AuthService.Login(r.Context(), req)
	if err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, domain.ErrInvalidCredentials) {
			http.Error(w, "Invalid credentials", code)
		} else {
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// ValidateHandler 处理 /validate 请求 (用于其他服务验证JWT)
func (h *Handler) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	user, err := h.AuthService.Validate(r.Context(), token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Token validation failed: %v", err), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// 返回验证成功的用户ID和角色，供调用方使用
	json.NewEncoder(w).Encode(map[string]string{
		"user_id": user.ID,
		"role":    user.Role,
	})
}
