package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/auth"
	"KubernetesSecurityMonitoringSystem/internal/kubernetes"
	"KubernetesSecurityMonitoringSystem/internal/middleware"
	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/monitor"
	"KubernetesSecurityMonitoringSystem/internal/storage"

	"github.com/gorilla/mux"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ResourceHandler struct {
	Storage storage.Storage
	K8s     *kubernetes.ClusterManager
	Monitor *monitor.Monitor
}

func isAdminRequest(r *http.Request) bool {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	return ok && claims.Role == models.RoleAdmin
}

// canManageCluster returns true for roles allowed to mutate clusters, policies
// and execute incident-response actions.
func canManageCluster(r *http.Request) bool {
	claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
	if !ok {
		return false
	}
	switch claims.Role {
	case models.RoleAdmin, models.RoleSecurityAnalyst, models.RoleInstructor:
		return true
	}
	return false
}

func requireManager(w http.ResponseWriter, r *http.Request) bool {
	if !canManageCluster(r) {
		http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
		return false
	}
	return true
}

// sanitizeCluster removes sensitive connection data before a cluster is sent
// to API clients. The kubeconfig stays in storage for server-side use only.
func sanitizeCluster(c models.Cluster) models.Cluster {
	c.KubeConfig = ""
	return c
}

func sanitizeClusters(in []models.Cluster) []models.Cluster {
	out := make([]models.Cluster, len(in))
	for i, c := range in {
		out[i] = sanitizeCluster(c)
	}
	return out
}

func isDemoID(id string) bool {
	return strings.HasPrefix(id, "demo-")
}

// validateRule performs a lightweight sanity check on a policy rule. Static
// pod-spec rules are matched by name; "log_pattern:<regex>" rules must compile.
func validateRule(rule string) error {
	trimmed := strings.TrimSpace(rule)
	if trimmed == "" {
		return fmt.Errorf("rule is empty")
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "log_pattern:") {
		expr := strings.TrimSpace(trimmed[len("log_pattern:"):])
		if expr == "" {
			return fmt.Errorf("log_pattern rule has no expression")
		}
		if _, err := regexp.Compile(expr); err != nil {
			return fmt.Errorf("invalid log_pattern regex: %w", err)
		}
	}
	return nil
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
	clusters = sanitizeClusters(clusters)
	json.NewEncoder(w).Encode(clusters)
}

func (h *ResourceHandler) CreateCluster(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, r) {
		return
	}
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

	c.ID = models.NewID("cluster")
	c.CreatedAt = time.Now()
	h.Storage.AddCluster(c)
	if h.Monitor != nil {
		h.Monitor.StartCluster(c.ID, c.KubeConfig)
	}
	json.NewEncoder(w).Encode(sanitizeCluster(c))
}

func (h *ResourceHandler) DeleteCluster(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, r) {
		return
	}
	vars := mux.Vars(r)
	id := vars["clusterId"]
	if h.Monitor != nil {
		h.Monitor.StopCluster(id)
	}
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
	policies = sanitizePolicies(policies)
	json.NewEncoder(w).Encode(policies)
}

// sanitizePolicies strips nothing today but keeps a single place to redact
// sensitive policy fields if they are added later.
func sanitizePolicies(in []models.Policy) []models.Policy { return in }

func (h *ResourceHandler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, r) {
		return
	}
	var p models.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if p.Name == "" {
		http.Error(w, "policy name is required", http.StatusBadRequest)
		return
	}
	for _, rule := range p.Rules {
		if err := validateRule(rule); err != nil {
			http.Error(w, fmt.Sprintf("invalid rule %q: %v", rule, err), http.StatusBadRequest)
			return
		}
	}
	p.ID = models.NewID("policy")
	p.CreatedAt = time.Now()
	h.Storage.AddPolicy(p)
	json.NewEncoder(w).Encode(p)
}

func (h *ResourceHandler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, r) {
		return
	}
	id := mux.Vars(r)["policyId"]
	if err := h.Storage.DeletePolicy(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

// CreateReport records an incident-response action taken on an alert.
func (h *ResourceHandler) CreateReport(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, r) {
		return
	}
	var rep models.IncidentReport
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if rep.AlertID == "" || rep.Details == "" {
		http.Error(w, "alert_id and details are required", http.StatusBadRequest)
		return
	}
	rep.ID = models.NewID("report")
	rep.Timestamp = time.Now()
	h.Storage.AddReport(rep)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rep)
}

// Action handlers for Incident Response
func (h *ResourceHandler) HandleAction(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, r) {
		return
	}
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
	case "release":
		err = h.K8s.ReleasePod(clusterID, cluster.KubeConfig, namespace, podName)
	case "delete":
		err = h.K8s.DeletePod(clusterID, cluster.KubeConfig, namespace, podName)
	case "evaluate":
		// Example of policy evaluation
		client, err := h.K8s.GetClient(clusterID, cluster.KubeConfig)
		if err != nil {
			http.Error(w, "Failed to create Kubernetes client: "+err.Error(), http.StatusBadRequest)
			return
		}
		pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			http.Error(w, "Failed to get pod: "+err.Error(), http.StatusNotFound)
			return
		}
		policies := h.Storage.GetPolicies()
		var allViolations []string
		for _, p := range policies {
			if p.Namespace == "" || p.Namespace == namespace {
				for _, v := range kubernetes.EvaluatePolicy(pod, p) {
					allViolations = append(allViolations, v.Message)
				}
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

// GetContainerLogs streams the real logs of a container running in a pod.
// Query params: namespace, pod, container (required), tail (default 200), follow.
func (h *ResourceHandler) GetContainerLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clusterID := vars["clusterId"]

	cluster, err := h.Storage.GetCluster(clusterID)
	if err != nil {
		http.Error(w, "Cluster not found", http.StatusNotFound)
		return
	}

	namespace := r.URL.Query().Get("namespace")
	podName := r.URL.Query().Get("pod")
	containerName := r.URL.Query().Get("container")
	if namespace == "" || podName == "" || containerName == "" {
		http.Error(w, "namespace, pod and container query params are required", http.StatusBadRequest)
		return
	}

	var tail int64 = 200
	if t := r.URL.Query().Get("tail"); t != "" {
		if _, err := fmt.Sscanf(t, "%d", &tail); err != nil || tail <= 0 {
			tail = 200
		}
	}
	follow := r.URL.Query().Get("follow") == "true"

	client, err := h.K8s.GetClient(clusterID, cluster.KubeConfig)
	if err != nil {
		http.Error(w, "Failed to create Kubernetes client: "+err.Error(), http.StatusBadRequest)
		return
	}

	logs, err := kubernetes.GetContainerLogs(client, namespace, podName, containerName, tail, follow)
	if err != nil {
		http.Error(w, "Failed to get logs: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(logs)
}

// StreamContainerLogs proxies a live (follow=true) container log stream to the
// client, flushing each chunk as it arrives.
func (h *ResourceHandler) StreamContainerLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clusterID := vars["clusterId"]

	cluster, err := h.Storage.GetCluster(clusterID)
	if err != nil {
		http.Error(w, "Cluster not found", http.StatusNotFound)
		return
	}

	namespace := r.URL.Query().Get("namespace")
	podName := r.URL.Query().Get("pod")
	containerName := r.URL.Query().Get("container")
	if namespace == "" || podName == "" || containerName == "" {
		http.Error(w, "namespace, pod and container query params are required", http.StatusBadRequest)
		return
	}

	var tail int64 = 100
	if t := r.URL.Query().Get("tail"); t != "" {
		if _, err := fmt.Sscanf(t, "%d", &tail); err != nil || tail <= 0 {
			tail = 100
		}
	}

	client, err := h.K8s.GetClient(clusterID, cluster.KubeConfig)
	if err != nil {
		http.Error(w, "Failed to create Kubernetes client: "+err.Error(), http.StatusBadRequest)
		return
	}

	stream, err := kubernetes.StreamContainerLogs(r.Context(), client, namespace, podName, containerName, tail, true)
	if err != nil {
		http.Error(w, "Failed to open log stream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer stream.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			flusher.Flush()
		}
		if err != nil {
			return
		}
	}
}
