package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashRefreshToken 对明文 refresh token 做 SHA256，以 hex 入库；不明文落库。
func hashRefreshToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
