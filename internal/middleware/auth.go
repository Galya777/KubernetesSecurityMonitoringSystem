package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/auth"
	"KubernetesSecurityMonitoringSystem/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserContextKey contextKey = "user"

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		var tokenString string
		if err == nil {
			tokenString = cookie.Value
		} else {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if tokenString == "" {
			next.ServeHTTP(w, r)
			return
		}

		claims := &auth.Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return auth.JwtKey(), nil
		})

		if err == nil && token.Valid {
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// RequireAuth rejects requests that do not carry a valid JWT.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(UserContextKey).(*auth.Claims); !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders sets baseline HTTP security headers on every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// LoginRateLimit throttles login attempts per client IP to slow down
// brute-force attacks. It allows burst attempts and then enforces a fixed
// window per IP.
func LoginRateLimit(maxAttempts int, window time.Duration) func(http.Handler) http.Handler {
	type entry struct {
		count int
		reset time.Time
	}
	var mu sync.Mutex
	attempts := make(map[string]*entry)

	go func() {
		for range time.Tick(window) {
			mu.Lock()
			now := time.Now()
			for ip, e := range attempts {
				if now.After(e.reset) {
					delete(attempts, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}

			mu.Lock()
			now := time.Now()
			e, ok := attempts[ip]
			if !ok || now.After(e.reset) {
				e = &entry{reset: now.Add(window)}
				attempts[ip] = e
			}
			e.count++
			allowed := e.count <= maxAttempts
			mu.Unlock()

			if !allowed {
				http.Error(w, "Too many login attempts, try again later", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireRole(roles ...models.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			authorized := false
			for _, role := range roles {
				if claims.Role == role {
					authorized = true
					break
				}
			}

			if !authorized {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
