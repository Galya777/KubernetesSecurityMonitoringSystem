package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/auth"
	"KubernetesSecurityMonitoringSystem/internal/kubernetes"
	"KubernetesSecurityMonitoringSystem/internal/middleware"
	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/storage"
	"strings"

	"github.com/gorilla/mux"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ResourceHandler struct {
	Storage storage.Storage
	K8s     *kubernetes.ClusterManager
}

func isAdminRequest(r *http.Request) bool {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	return ok && claims.Role == models.RoleAdmin
}

func isDemoID(id string) bool {
	return strings.HasPrefix(id, "demo-")
}

func (h *ResourceHandler) GetAlertsJSON(w http.ResponseWriter, r *http.Request) {
	alerts := h.Storage.GetAlerts()
	filtered := make([]models.Alert, 0, len(alerts))
	for _, a := range alerts {
		if !isAdminRequest(r) && isDemoID(a.ID) {
			continue
		}
		filtered = append(filtered, a)
	}
	json.NewEncoder(w).Encode(filtered)
}

// Cluster Handlers
func (h *ResourceHandler) GetClusters(w http.ResponseWriter, r *http.Request) {
	clusters := h.Storage.GetClusters()
	if !isAdminRequest(r) {
		filtered := make([]models.Cluster, 0, len(clusters))
		for _, c := range clusters {
			if isDemoID(c.ID) {
				continue
			}
			filtered = append(filtered, c)
		}
		clusters = filtered
	}
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
	if !isAdminRequest(r) {
		filtered := make([]models.Policy, 0, len(policies))
		for _, p := range policies {
			if isDemoID(p.ID) {
				continue
			}
			filtered = append(filtered, p)
		}
		policies = filtered
	}
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
				if !isAdminRequest(r) && isDemoID(a.ID) {
					continue
				}
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
	if !isAdminRequest(r) {
		filtered := make([]models.IncidentReport, 0, len(reports))
		for _, rep := range reports {
			if isDemoID(rep.ID) {
				continue
			}
			filtered = append(filtered, rep)
		}
		reports = filtered
	}
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

// DiscoverContainers lists containers from pods in a cluster (optionally filtered by namespace)
// and returns them as models.Container records (discovery only; not persisted).
func (h *ResourceHandler) DiscoverContainers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clusterID := vars["clusterId"]
	if clusterID == "" {
		http.Error(w, "clusterId is required", http.StatusBadRequest)
		return
	}

	cluster, err := h.Storage.GetCluster(clusterID)
	if err != nil {
		http.Error(w, "Cluster not found", http.StatusNotFound)
		return
	}

	client, err := h.K8s.GetClient(clusterID, cluster.KubeConfig)
	if err != nil {
		http.Error(w, "Failed to create Kubernetes client: "+err.Error(), http.StatusBadRequest)
		return
	}

	ns := r.URL.Query().Get("namespace")
	pods, err := client.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, "Failed to list pods: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := make([]models.Container, 0)
	for _, pod := range pods.Items {
		for _, c := range pod.Spec.Containers {
			result = append(result, models.Container{
				ID:            fmt.Sprintf("%s:%s:%s:%s", clusterID, pod.Namespace, pod.Name, c.Name),
				ClusterID:     clusterID,
				Namespace:     pod.Namespace,
				PodName:       pod.Name,
				ContainerName: c.Name,
				Image:         c.Image,
				Status:        string(pod.Status.Phase),
				CreatedAt:     time.Now(),
			})
		}
	}

	json.NewEncoder(w).Encode(result)
}
