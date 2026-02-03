package kubernetes

import (
	"context"
	"fmt"
	"sync"

	"KubernetesSecurityMonitoringSystem/internal/models"

	v1 "k8s.io/api/core/v1"
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

// WatchEvents watches for Kubernetes events and sends them to a channel
func (m *ClusterManager) WatchEvents(clusterID, kubeConfigData string, alertChan chan<- models.Alert) error {
	client, err := m.GetClient(clusterID, kubeConfigData)
	if err != nil {
		return err
	}

	watcher, err := client.CoreV1().Events("").Watch(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	go func() {
		for event := range watcher.ResultChan() {
			e, ok := event.Object.(*metav1.Status) // Could be error status
			if ok && e.Status == "Failure" {
				continue
			}

			// In real implementation we would convert K8s Event to models.Alert
			// For now just logging that we received something
		}
	}()

	return nil
}

// IsolatePod isolates a pod by adding a special label
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
	pod.Labels["security.ksms.io/isolated"] = "true"

	_, err = client.CoreV1().Pods(namespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
	return err
}

// DeletePod deletes a pod
func (m *ClusterManager) DeletePod(clusterID, kubeConfigData, namespace, podName string) error {
	client, err := m.GetClient(clusterID, kubeConfigData)
	if err != nil {
		return err
	}

	return client.CoreV1().Pods(namespace).Delete(context.TODO(), podName, metav1.DeleteOptions{})
}

// EvaluatePolicy checks a pod against a policy
func EvaluatePolicy(pod *v1.Pod, policy models.Policy) []string {
	var violations []string

	for _, rule := range policy.Rules {
		switch rule {
		case "runAsNonRoot: true":
			if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.RunAsNonRoot == nil || !*pod.Spec.SecurityContext.RunAsNonRoot {
				violations = append(violations, "Container should run as non-root")
			}
		case "privileged: false":
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					violations = append(violations, fmt.Sprintf("Container %s is privileged", container.Name))
				}
			}
		}
	}

	return violations
}
