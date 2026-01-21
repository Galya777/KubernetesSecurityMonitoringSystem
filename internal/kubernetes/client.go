package kubernetes

import (
	"context"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// ClusterManager manages active Kubernetes clients
type ClusterManager struct {
	clients map[string]*kubernetes.Clientset
	mu      sync.RWMutex
}

func NewClusterManager() *ClusterManager {
	return &ClusterManager{
		clients: make(map[string]*kubernetes.Clientset),
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
