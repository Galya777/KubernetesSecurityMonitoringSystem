package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/storage"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var JwtKey = []byte("your_secret_key")

type Claims struct {
	UserID string      `json:"user_id"`
	Role   models.Role `json:"role"`
	jwt.RegisteredClaims
}

type AuthHandler struct {
	Storage storage.Storage
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var u models.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	u.Password = string(hashedPassword)
	u.ID = time.Now().Format("20060102150405")
	if u.Role == "" {
		u.Role = models.RoleStudent
	}
	u.CreatedAt = time.Now()

	if err := h.Storage.AddUser(u); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(u)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.Storage.GetUserByEmail(creds.Email)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.ID,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
		Path:    "/",
	})

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
		Path:    "/",
	})
	w.WriteHeader(http.StatusOK)
}
