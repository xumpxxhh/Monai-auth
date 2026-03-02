package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// StateStore 用于 SSO 流程：服务端生成 serverState，绑定 (clientID, redirectURI, clientState)，一次性使用
type StateStore interface {
	// Save 生成 serverState 并绑定 clientID、redirectURI、clientState（子应用传来的 state，回调时原样带回）
	Save(clientID, redirectURI, clientState string) (serverState string, err error)
	// GetAndConsume 用 serverState 取出并删除，返回 clientID、redirectURI、clientState
	GetAndConsume(serverState string) (clientID, redirectURI, clientState string, ok bool)
}

type stateEntry struct {
	clientID    string
	redirectURI string
	clientState string
	expiresAt   time.Time
}

// MemoryStateStore 内存实现，带 TTL 与一次性消费
type MemoryStateStore struct {
	ttl   time.Duration
	mu    sync.Mutex
	store map[string]*stateEntry
}

// NewMemoryStateStore 默认 TTL 10 分钟
func NewMemoryStateStore(ttl time.Duration) *MemoryStateStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	s := &MemoryStateStore{ttl: ttl, store: make(map[string]*stateEntry)}
	go s.cleanup()
	return s
}

func (s *MemoryStateStore) Save(clientID, redirectURI, clientState string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	serverState := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[serverState] = &stateEntry{clientID: clientID, redirectURI: redirectURI, clientState: clientState, expiresAt: time.Now().Add(s.ttl)}
	return serverState, nil
}

func (s *MemoryStateStore) GetAndConsume(serverState string) (clientID, redirectURI, clientState string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.store[serverState]
	if !ok || e == nil || time.Now().After(e.expiresAt) {
		return "", "", "", false
	}
	delete(s.store, serverState)
	return e.clientID, e.redirectURI, e.clientState, true
}

func (s *MemoryStateStore) cleanup() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, e := range s.store {
			if e != nil && now.After(e.expiresAt) {
				delete(s.store, k)
			}
		}
		s.mu.Unlock()
	}
}
