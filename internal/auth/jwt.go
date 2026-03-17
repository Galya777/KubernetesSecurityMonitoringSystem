package auth

import (
	"KubernetesSecurityMonitoringSystem/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

var JwtKey = []byte("your_secret_key")

type Claims struct {
	UserID string      `json:"user_id"`
	Role   models.Role `json:"role"`
	jwt.RegisteredClaims
}
