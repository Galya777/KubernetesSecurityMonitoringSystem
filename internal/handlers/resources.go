package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/kubernetes"
	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/storage"

	"github.com/gorilla/mux"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ResourceHandler struct {
	Storage storage.Storage
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

	// Fetch initial real metrics (Pod count, CPU, Memory)
	if podCount, err := kubernetes.GetPodCount(client); err == nil {
		c.Metrics.PodCount = podCount
		c.Status = "Connected"

		// Try to get CPU/Memory if Metrics Server is available
		if mClient, err := h.K8s.GetMetricsClient(c.ID, c.KubeConfig); err == nil {
			if cpu, mem, err := kubernetes.GetClusterMetrics(mClient); err == nil {
				c.Metrics.CPUUsage = cpu
				c.Metrics.MemoryUsage = mem
			}
		}
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

	severityFilter := r.URL.Query().Get("severity")
	clusterFilter := r.URL.Query().Get("clusterId")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			alerts := h.Storage.GetAlerts()
			var filteredAlerts []models.Alert
			for _, a := range alerts {
				if (severityFilter == "" || a.Severity == severityFilter) &&
					(clusterFilter == "" || a.ClusterID == clusterFilter) {
					filteredAlerts = append(filteredAlerts, a)
				}
			}
			data, _ := json.Marshal(filteredAlerts)
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

// Action handlers for Incident Response
func (h *ResourceHandler) HandleAction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	action := vars["action"] // isolate, delete, evaluate
	clusterID := r.URL.Query().Get("clusterId")
	namespace := r.URL.Query().Get("namespace")
	podName := r.URL.Query().Get("podName")

	cluster, err := h.Storage.GetCluster(clusterID)
	if err != nil {
		http.Error(w, "Cluster not found", http.StatusNotFound)
		return
	}

	switch action {
	case "isolate":
		err = h.K8s.IsolatePod(clusterID, cluster.KubeConfig, namespace, podName)
	case "delete":
		err = h.K8s.DeletePod(clusterID, cluster.KubeConfig, namespace, podName)
	case "evaluate":
		// Example of policy evaluation
		client, _ := h.K8s.GetClient(clusterID, cluster.KubeConfig)
		pod, _ := client.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
		policies := h.Storage.GetPolicies()
		var allViolations []string
		for _, p := range policies {
			if p.Namespace == "" || p.Namespace == namespace {
				violations := kubernetes.EvaluatePolicy(pod, p)
				allViolations = append(allViolations, violations...)
			}
		}
		json.NewEncoder(w).Encode(allViolations)
		return
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Action failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Action %s completed for %s", action, podName)
}
