package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/kubernetes"
	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/storage"

	"github.com/gorilla/mux"
)

type ResourceHandler struct {
	Storage *storage.MemoryStorage
	K8s     *kubernetes.ClusterManager
}

// Cluster Handlers
func (h *ResourceHandler) GetClusters(w http.ResponseWriter, r *http.Request) {
	clusters := h.Storage.GetClusters()
	json.NewEncoder(w).Encode(clusters)
}

func (h *ResourceHandler) CreateCluster(w http.ResponseWriter, r *http.Request) {
	var c models.Cluster
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate KubeConfig and verify connection
	client, err := kubernetes.NewClientFromConfig(c.KubeConfig)
	if err != nil {
		http.Error(w, "Invalid KubeConfig: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := kubernetes.VerifyConnection(client); err != nil {
		http.Error(w, "Could not connect to cluster: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Fetch initial real metrics (Pod count)
	if podCount, err := kubernetes.GetPodCount(client); err == nil {
		c.Metrics.PodCount = podCount
		c.Status = "Connected"
	} else {
		c.Status = "Error"
	}

	c.ID = time.Now().Format("20060102150405")
	c.CreatedAt = time.Now()
	h.Storage.AddCluster(c)
	json.NewEncoder(w).Encode(c)
}

func (h *ResourceHandler) DeleteCluster(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["clusterId"]
	h.Storage.DeleteCluster(id)
	w.WriteHeader(http.StatusNoContent)
}

// Policy Handlers
func (h *ResourceHandler) GetPolicies(w http.ResponseWriter, r *http.Request) {
	policies := h.Storage.GetPolicies()
	json.NewEncoder(w).Encode(policies)
}

func (h *ResourceHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var p models.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.ID = time.Now().Format("20060102150405")
	p.CreatedAt = time.Now()
	h.Storage.AddPolicy(p)
	json.NewEncoder(w).Encode(p)
}

// Alert Handlers (SSE placeholder)
func (h *ResourceHandler) GetAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			alerts := h.Storage.GetAlerts()
			data, _ := json.Marshal(alerts)
			w.Write([]byte("data: " + string(data) + "\n\n"))
			flusher.Flush()
		}
	}
}

// Incident Reports
func (h *ResourceHandler) GetReports(w http.ResponseWriter, r *http.Request) {
	reports := h.Storage.GetReports()
	json.NewEncoder(w).Encode(reports)
}
