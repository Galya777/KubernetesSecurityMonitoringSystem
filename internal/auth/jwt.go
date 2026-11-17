package auth

import (
	"crypto/rand"
	"log"
	"os"
	"sync"

	"KubernetesSecurityMonitoringSystem/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtKeyOnce sync.Once
	jwtKey     []byte
)

// JwtKey returns the HMAC signing key. It is loaded once from the JWT_SECRET
// environment variable; when unset a random per-process key is generated so
// tokens are never signed with a publicly known secret.
func JwtKey() []byte {
	jwtKeyOnce.Do(func() {
		if secret := os.Getenv("JWT_SECRET"); secret != "" {
			jwtKey = []byte(secret)
			return
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("failed to generate JWT secret: %v", err)
		}
		jwtKey = b
		log.Println("WARNING: JWT_SECRET is not set; using a random per-process signing key (all sessions invalidated on restart)")
	})
	return jwtKey
}

func init() {
	_ = JwtKey()
}

type Claims struct {
	UserID string      `json:"user_id"`
	Role   models.Role `json:"role"`
	jwt.RegisteredClaims
}
