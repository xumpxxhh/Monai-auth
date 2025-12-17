package inmemory

import (
	"context"
	"sync"
	"time"

	"monai-auth/internal/domain"
)

// InMemoryUserRepo 内存实现，仅用于演示接口
type InMemoryUserRepo struct {
	users map[string]*domain.User
	mu    sync.RWMutex
}

func NewInMemoryUserRepo() *InMemoryUserRepo {
	// 预设一个测试用户
	initialUser := &domain.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		PasswordHash: "$2a$10$w1qZ3gKz0gL8b/Q/hXjU0.Q/hXjU0.Q/hXjU0.Q/hXjU0.Q/hXjU0.Q/hXjU0.Q/hXjU0.Q", // 密码: password123
		Role:         "admin",
		CreatedAt:    time.Now().Unix(),
	}
	return &InMemoryUserRepo{
		users: map[string]*domain.User{
			initialUser.Email: initialUser,
		},
	}
}

func (r *InMemoryUserRepo) FindByID(ctx context.Context, id string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, user := range r.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *InMemoryUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.users[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

func (r *InMemoryUserRepo) CreateUser(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[user.Email]; ok {
		return domain.ErrEmailExists
	}
	r.users[user.Email] = user
	return nil
}
