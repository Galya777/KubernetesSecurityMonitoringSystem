package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/auth"
	"KubernetesSecurityMonitoringSystem/internal/middleware"
	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/storage"

	"github.com/gorilla/mux"
)

type ContainerHandler struct {
	Storage storage.Storage
}

func roleDisallowedToManageContainers(role models.Role) bool {
	return role == models.RoleStudent || role == models.RoleAnonymous || role == ""
}

func (h *ContainerHandler) CreateContainer(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if roleDisallowedToManageContainers(claims.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		ClusterID     string `json:"cluster_id"`
		Namespace     string `json:"namespace"`
		PodName       string `json:"pod_name"`
		ContainerName string `json:"container_name"`
		Image         string `json:"image"`
		Status        string `json:"status"`
		AttachToUser  string `json:"attach_to_user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.ClusterID == "" || req.Namespace == "" || req.PodName == "" || req.ContainerName == "" {
		http.Error(w, "cluster_id, namespace, pod_name and container_name are required", http.StatusBadRequest)
		return
	}

	c := models.Container{
		ID:            fmt.Sprintf("%d", time.Now().UnixNano()),
		ClusterID:     req.ClusterID,
		Namespace:     req.Namespace,
		PodName:       req.PodName,
		ContainerName: req.ContainerName,
		Image:         req.Image,
		Status:        req.Status,
		CreatedAt:     time.Now(),
	}

	if err := h.Storage.AddContainer(c); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	attachUserID := claims.UserID
	if claims.Role == models.RoleAdmin && req.AttachToUser != "" {
		attachUserID = req.AttachToUser
	}
	_ = h.Storage.AttachContainerToUser(attachUserID, c.ID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(c)
}

func (h *ContainerHandler) GetContainersByUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID := mux.Vars(r)["userId"]
	if userID == "" {
		http.Error(w, "userId is required", http.StatusBadRequest)
		return
	}

	if claims.UserID != userID && claims.Role != models.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	containers, err := h.Storage.GetContainersByUser(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(containers)
}

func (h *ContainerHandler) AttachContainerToUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if roleDisallowedToManageContainers(claims.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID := vars["userId"]
	containerID := vars["containerId"]
	if userID == "" || containerID == "" {
		http.Error(w, "userId and containerId are required", http.StatusBadRequest)
		return
	}

	if claims.UserID != userID && claims.Role != models.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := h.Storage.AttachContainerToUser(userID, containerID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ContainerHandler) DetachContainerFromUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if roleDisallowedToManageContainers(claims.Role) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID := vars["userId"]
	containerID := vars["containerId"]
	if userID == "" || containerID == "" {
		http.Error(w, "userId and containerId are required", http.StatusBadRequest)
		return
	}

	if claims.UserID != userID && claims.Role != models.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := h.Storage.DetachContainerFromUser(userID, containerID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ContainerHandler) DeleteContainer(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if claims.Role != models.RoleAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	containerID := mux.Vars(r)["containerId"]
	if containerID == "" {
		http.Error(w, "containerId is required", http.StatusBadRequest)
		return
	}
	if err := h.Storage.DeleteContainer(containerID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
