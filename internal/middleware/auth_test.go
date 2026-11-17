package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/auth"
	"KubernetesSecurityMonitoringSystem/internal/models"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func reqWithClaims(claims *auth.Claims) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	return r.WithContext(context.WithValue(r.Context(), UserContextKey, claims))
}

func TestRequireAuthRejectsAnonymous(t *testing.T) {
	h := RequireAuth(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuthAcceptsClaims(t *testing.T) {
	h := RequireAuth(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithClaims(&auth.Claims{UserID: "u1", Role: models.RoleStudent}))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequireRole(t *testing.T) {
	admin := &auth.Claims{UserID: "u1", Role: models.RoleAdmin}
	student := &auth.Claims{UserID: "u2", Role: models.RoleStudent}

	h := RequireRole(models.RoleAdmin)(okHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: expected 401, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithClaims(student))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("student: expected 403, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqWithClaims(admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin: expected 200, got %d", rec.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	h := LoginRateLimit(3, time.Minute)(okHandler())

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/login", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/login", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after limit, got %d", rec.Code)
	}
}
