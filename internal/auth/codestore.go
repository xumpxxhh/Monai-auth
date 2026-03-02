package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// CodeStore 授权码存储：code -> (userID, clientID, redirectURI)，一次性使用，短 TTL（如 5 分钟）
type CodeStore interface {
	Save(userID int64, clientID, redirectURI string) (code string, err error)
	GetAndConsume(code string) (userID int64, clientID, redirectURI string, ok bool)
}

type codeEntry struct {
	userID      int64
	clientID    string
	redirectURI string
	expiresAt   time.Time
}

// NewMemoryCodeStore 授权码内存存储，默认 TTL 5 分钟
func NewMemoryCodeStore(ttl time.Duration) *MemoryCodeStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c := &MemoryCodeStore{ttl: ttl, store: make(map[string]*codeEntry)}
	go c.cleanup()
	return c
}

// MemoryCodeStore 实现 CodeStore
type MemoryCodeStore struct {
	ttl   time.Duration
	mu    sync.Mutex
	store map[string]*codeEntry
}

func (c *MemoryCodeStore) Save(userID int64, clientID, redirectURI string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[code] = &codeEntry{userID: userID, clientID: clientID, redirectURI: redirectURI, expiresAt: time.Now().Add(c.ttl)}
	return code, nil
}

func (c *MemoryCodeStore) GetAndConsume(code string) (userID int64, clientID, redirectURI string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.store[code]
	if !ok || e == nil || time.Now().After(e.expiresAt) {
		return 0, "", "", false
	}
	delete(c.store, code)
	return e.userID, e.clientID, e.redirectURI, true
}

func (c *MemoryCodeStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, e := range c.store {
			if e != nil && now.After(e.expiresAt) {
				delete(c.store, k)
			}
		}
		c.mu.Unlock()
	}
}
