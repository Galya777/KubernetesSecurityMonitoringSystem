package kubernetes

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/models"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	metrics "k8s.io/metrics/pkg/client/clientset/versioned"
)

func init() {
	_ = v1.Pod{}
}

// ClusterManager manages active Kubernetes clients
type ClusterManager struct {
	clients        map[string]*kubernetes.Clientset
	metricsClients map[string]*metrics.Clientset
	mu             sync.RWMutex
}

func NewClusterManager() *ClusterManager {
	return &ClusterManager{
		clients:        make(map[string]*kubernetes.Clientset),
		metricsClients: make(map[string]*metrics.Clientset),
	}
}

// GetClient returns a clientset for a cluster, creating it if necessary
func (m *ClusterManager) GetClient(clusterID, kubeConfigData string) (*kubernetes.Clientset, error) {
	m.mu.RLock()
	client, ok := m.clients[clusterID]
	m.mu.RUnlock()
	if ok {
		return client, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if client, ok := m.clients[clusterID]; ok {
		return client, nil
	}

	newClient, err := NewClientFromConfig(kubeConfigData)
	if err != nil {
		return nil, err
	}

	m.clients[clusterID] = newClient
	return newClient, nil
}

// GetMetricsClient returns a metrics clientset for a cluster
func (m *ClusterManager) GetMetricsClient(clusterID, kubeConfigData string) (*metrics.Clientset, error) {
	m.mu.RLock()
	client, ok := m.metricsClients[clusterID]
	m.mu.RUnlock()
	if ok {
		return client, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if client, ok := m.metricsClients[clusterID]; ok {
		return client, nil
	}

	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeConfigData))
	if err != nil {
		return nil, err
	}

	newClient, err := metrics.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	m.metricsClients[clusterID] = newClient
	return newClient, nil
}

// NewClientFromConfig creates a K8s clientset from a raw KubeConfig string
func NewClientFromConfig(kubeConfigData string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeConfigData))
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

// VerifyConnection checks if the client can connect to the cluster
func VerifyConnection(client *kubernetes.Clientset) error {
	_, err := client.Discovery().ServerVersion()
	return err
}

// GetPodCount returns the total number of pods in all namespaces
func GetPodCount(client *kubernetes.Clientset) (int, error) {
	pods, err := client.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	return len(pods.Items), nil
}

// GetClusterMetrics returns CPU and Memory usage for all nodes
func GetClusterMetrics(mClient *metrics.Clientset) (float64, float64, error) {
	nodeMetrics, err := mClient.MetricsV1beta1().NodeMetricses().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return 0, 0, err
	}

	var totalCPU, totalMem float64
	for _, nm := range nodeMetrics.Items {
		totalCPU += float64(nm.Usage.Cpu().MilliValue())
		totalMem += float64(nm.Usage.Memory().Value()) / (1024 * 1024) // MB
	}

	return totalCPU, totalMem, nil
}

// WatchEvents watches Kubernetes Warning events and converts them into alerts.
// The watch runs until ctx is cancelled or the watcher channel closes.
func (m *ClusterManager) WatchEvents(ctx context.Context, clusterID, kubeConfigData string, alertChan chan<- models.Alert) error {
	client, err := m.GetClient(clusterID, kubeConfigData)
	if err != nil {
		return err
	}

	watcher, err := client.CoreV1().Events("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	go func() {
		defer watcher.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.ResultChan():
				if !ok {
					return
				}

				e, ok := event.Object.(*v1.Event)
				if !ok || e.Type != v1.EventTypeWarning {
					continue
				}

				involved := ""
				if e.InvolvedObject.Name != "" {
					involved = fmt.Sprintf(" on %s/%s", e.InvolvedObject.Kind, e.InvolvedObject.Name)
				}

				ts := e.LastTimestamp.Time
				if ts.IsZero() {
					ts = e.FirstTimestamp.Time
				}
				if ts.IsZero() {
					ts = time.Now()
				}

				alert := models.Alert{
					ID:        fmt.Sprintf("evt-%d", time.Now().UnixNano()),
					ClusterID: clusterID,
					Severity:  "Medium",
					Message:   fmt.Sprintf("%s%s (x%d): %s", e.Reason, involved, e.Count, e.Message),
					Timestamp: ts,
				}

				select {
				case alertChan <- alert:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return nil
}

const (
	isolationLabelKey   = "security.ksms.io/isolated"
	isolationPolicyName = "ksms-deny-all"
)

// IsolatePod isolates a pod by labeling it and enforcing a deny-all
// NetworkPolicy that selects all pods carrying the isolation label.
// The label alone is kept as a fallback for clusters without NetworkPolicy
// enforcement.
func (m *ClusterManager) IsolatePod(clusterID, kubeConfigData, namespace, podName string) error {
	client, err := m.GetClient(clusterID, kubeConfigData)
	if err != nil {
		return err
	}

	pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	pod.Labels[isolationLabelKey] = "true"

	if _, err = client.CoreV1().Pods(namespace).Update(context.TODO(), pod, metav1.UpdateOptions{}); err != nil {
		return err
	}

	return ensureIsolationPolicy(client, namespace)
}

// ReleasePod removes the isolation label from a pod, restoring its network
// connectivity (the shared deny-all policy simply stops selecting it).
func (m *ClusterManager) ReleasePod(clusterID, kubeConfigData, namespace, podName string) error {
	client, err := m.GetClient(clusterID, kubeConfigData)
	if err != nil {
		return err
	}

	pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if pod.Labels == nil {
		return nil
	}
	if _, ok := pod.Labels[isolationLabelKey]; !ok {
		return nil
	}
	delete(pod.Labels, isolationLabelKey)

	_, err = client.CoreV1().Pods(namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
	return err
}

// ensureIsolationPolicy creates the namespace-wide deny-all NetworkPolicy used
// for pod isolation. It is idempotent.
func ensureIsolationPolicy(client *kubernetes.Clientset, namespace string) error {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      isolationPolicyName,
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{isolationLabelKey: "true"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			// Empty ingress/egress rule lists deny all traffic.
		},
	}

	_, err := client.NetworkingV1().NetworkPolicies(namespace).Create(context.TODO(), policy, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

// GetContainerLogs returns the logs of a single container in a pod.
func GetContainerLogs(client *kubernetes.Clientset, namespace, podName, containerName string, tailLines int64, follow bool) ([]byte, error) {
	opts := &v1.PodLogOptions{
		Container: containerName,
		TailLines: &tailLines,
		Follow:    follow,
	}
	req := client.CoreV1().Pods(namespace).GetLogs(podName, opts)
	return req.Do(context.TODO()).Raw()
}

// StreamContainerLogs opens a streaming log request for a container. The
// returned reader stays open while follow is true; close it or cancel ctx to
// terminate.
func StreamContainerLogs(ctx context.Context, client *kubernetes.Clientset, namespace, podName, containerName string, tailLines int64, follow bool) (io.ReadCloser, error) {
	opts := &v1.PodLogOptions{
		Container: containerName,
		TailLines: &tailLines,
		Follow:    follow,
	}
	return client.CoreV1().Pods(namespace).GetLogs(podName, opts).Stream(ctx)
}

// DeletePod deletes a pod
func (m *ClusterManager) DeletePod(clusterID, kubeConfigData, namespace, podName string) error {
	client, err := m.GetClient(clusterID, kubeConfigData)
	if err != nil {
		return err
	}

	return client.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
}

// Violation describes a single policy rule violation found on a pod.
type Violation struct {
	Rule     string
	Message  string
	Severity string
}

// EvaluatePolicy checks a pod against all rules of a policy.
func EvaluatePolicy(pod *v1.Pod, policy models.Policy) []Violation {
	var violations []Violation
	for _, rule := range policy.Rules {
		violations = append(violations, evaluateRule(pod, rule)...)
	}
	return violations
}

func evaluateRule(pod *v1.Pod, rule string) []Violation {
	switch normalizeRule(rule) {
	case "privileged: false", "no_privileged=true", "no-privileged", "privileged=false":
		return checkPrivileged(pod)
	case "runasnonroot: true", "run_as_non_root", "runasnonroot=true":
		return checkRunAsNonRoot(pod)
	case "hostnetwork: false", "no_host_network", "hostnetwork=false":
		return checkPodBool(pod, "hostNetwork", pod.Spec.HostNetwork, "Host network is enabled")
	case "hostpid: false", "no_host_pid", "hostpid=false":
		return checkPodBool(pod, "hostPID", pod.Spec.HostPID, "Host PID namespace is shared")
	case "hostipc: false", "no_host_ipc", "hostipc=false":
		return checkPodBool(pod, "hostIPC", pod.Spec.HostIPC, "Host IPC namespace is shared")
	case "readonlyrootfilesystem: true", "read_only_root_filesystem":
		return checkReadOnlyRootFilesystem(pod)
	case "allowprivilegeescalation: false", "no_privilege_escalation":
		return checkAllowPrivilegeEscalation(pod)
	default:
		// Unknown or runtime-only rules (e.g. "disallow_exec=true") cannot be
		// evaluated statically from the pod spec.
		return nil
	}
}

func normalizeRule(rule string) string {
	return strings.ToLower(strings.TrimSpace(rule))
}

func checkPrivileged(pod *v1.Pod) []Violation {
	var out []Violation
	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			out = append(out, Violation{
				Rule:     "privileged",
				Message:  fmt.Sprintf("Container %s runs as privileged", c.Name),
				Severity: "High",
			})
		}
	}
	return out
}

func checkRunAsNonRoot(pod *v1.Pod) []Violation {
	var out []Violation
	podNonRoot := pod.Spec.SecurityContext != nil &&
		pod.Spec.SecurityContext.RunAsNonRoot != nil &&
		*pod.Spec.SecurityContext.RunAsNonRoot

	for _, c := range pod.Spec.Containers {
		containerNonRoot := c.SecurityContext != nil &&
			c.SecurityContext.RunAsNonRoot != nil &&
			*c.SecurityContext.RunAsNonRoot
		if !containerNonRoot && !podNonRoot {
			out = append(out, Violation{
				Rule:     "runAsNonRoot",
				Message:  fmt.Sprintf("Container %s may run as root (runAsNonRoot not enforced)", c.Name),
				Severity: "Medium",
			})
		}
	}
	return out
}

func checkPodBool(pod *v1.Pod, rule string, enabled bool, message string) []Violation {
	if !enabled {
		return nil
	}
	return []Violation{{Rule: rule, Message: message, Severity: "High"}}
}

func checkReadOnlyRootFilesystem(pod *v1.Pod) []Violation {
	var out []Violation
	for _, c := range pod.Spec.Containers {
		if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
			out = append(out, Violation{
				Rule:     "readOnlyRootFilesystem",
				Message:  fmt.Sprintf("Container %s does not use a read-only root filesystem", c.Name),
				Severity: "Low",
			})
		}
	}
	return out
}

func checkAllowPrivilegeEscalation(pod *v1.Pod) []Violation {
	var out []Violation
	for _, c := range pod.Spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
			out = append(out, Violation{
				Rule:     "allowPrivilegeEscalation",
				Message:  fmt.Sprintf("Container %s allows privilege escalation", c.Name),
				Severity: "Medium",
			})
		}
	}
	return out
}
