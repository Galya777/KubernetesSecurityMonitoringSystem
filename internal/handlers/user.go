package handlers

import (
	"encoding/json"
	"net/http"

	"KubernetesSecurityMonitoringSystem/internal/auth"
	"KubernetesSecurityMonitoringSystem/internal/middleware"
	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/storage"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type UserHandler struct {
	Storage storage.Storage
}

func claimsFrom(r *http.Request) (*auth.Claims, bool) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	return claims, ok
}

func (h *UserHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	users := h.Storage.GetAllUsers()
	json.NewEncoder(w).Encode(users)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFrom(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := mux.Vars(r)["userId"]
	if claims.UserID != id && claims.Role != models.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	user, err := h.Storage.GetUser(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}

// UpdateUser merges the request body into the stored user. Non-admin users may
// only edit their own profile fields (name, token keys); role, email and
// password are always preserved unless the caller is an administrator.
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFrom(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := mux.Vars(r)["userId"]
	isAdmin := claims.Role == models.RoleAdmin
	if claims.UserID != id && !isAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	existing, err := h.Storage.GetUser(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var req models.User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Fields every user may update on their own profile.
	existing.FirstName = req.FirstName
	existing.LastName = req.LastName
	existing.TokenKeys = req.TokenKeys

	// Privileged fields are only changeable by an administrator.
	if isAdmin {
		if req.Email != "" {
			existing.Email = req.Email
		}
		if req.Role != "" {
			existing.Role = req.Role
		}
	}
	// Password is never taken from the request body (json:"-"); use
	// ChangePassword instead.

	if err := h.Storage.UpdateUser(existing); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(existing)
}

// ChangePassword verifies the current password (unless an administrator is
// resetting another user's password) and stores a new hash.
func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFrom(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := mux.Vars(r)["userId"]
	isAdmin := claims.Role == models.RoleAdmin
	if claims.UserID != id && !isAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 8 {
		http.Error(w, "new password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	existing, err := h.Storage.GetUser(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if !isAdmin || claims.UserID == id {
		if bcrypt.CompareHashAndPassword([]byte(existing.Password), []byte(req.OldPassword)) != nil {
			http.Error(w, "current password is incorrect", http.StatusForbidden)
			return
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}
	existing.Password = string(hashed)

	if err := h.Storage.UpdateUser(existing); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFrom(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if claims.Role != models.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	id := mux.Vars(r)["userId"]
	if claims.UserID == id {
		http.Error(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}

	if err := h.Storage.DeleteUser(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
