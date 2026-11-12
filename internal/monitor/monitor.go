package monitor

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/kubernetes"
	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/storage"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	kubecore "k8s.io/client-go/kubernetes"
)

const (
	watchReconnectDelay = 5 * time.Second
	eventAlertBuffer    = 256
)

type logPattern struct {
	rule string
	re   *regexp.Regexp
}

// Monitor watches connected clusters, evaluates security policies against pods
// and turns Kubernetes Warning events into alerts.
type Monitor struct {
	store storage.Storage
	k8s   *kubernetes.ClusterManager

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
	ctxs    map[string]context.Context
	active  map[string]map[string]struct{} // clusterID -> active dedup keys

	logWatchers map[string]context.CancelFunc // clusterID|ns|pod -> cancel
	logPatterns map[string][]logPattern       // clusterID|ns|pod -> patterns

	alertSeq int64
}

func New(store storage.Storage, k8s *kubernetes.ClusterManager) *Monitor {
	return &Monitor{
		store:       store,
		k8s:         k8s,
		cancels:     make(map[string]context.CancelFunc),
		ctxs:        make(map[string]context.Context),
		active:      make(map[string]map[string]struct{}),
		logWatchers: make(map[string]context.CancelFunc),
		logPatterns: make(map[string][]logPattern),
	}
}

// StartCluster begins monitoring a cluster. It is a no-op if the cluster is
// already monitored or has no kubeconfig.
func (m *Monitor) StartCluster(clusterID, kubeConfig string) {
	if strings.TrimSpace(kubeConfig) == "" {
		log.Printf("[monitor] skipping cluster %s: no kubeconfig", clusterID)
		return
	}

	m.mu.Lock()
	if _, ok := m.cancels[clusterID]; ok {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancels[clusterID] = cancel
	m.ctxs[clusterID] = ctx
	m.mu.Unlock()

	go m.run(ctx, clusterID, kubeConfig)
}

// StopCluster stops monitoring a cluster and clears its dedup state.
func (m *Monitor) StopCluster(clusterID string) {
	m.mu.Lock()
	cancel, ok := m.cancels[clusterID]
	if ok {
		delete(m.cancels, clusterID)
		delete(m.ctxs, clusterID)
	}
	delete(m.active, clusterID)
	for key, wcancel := range m.logWatchers {
		if strings.HasPrefix(key, clusterID+"|") {
			wcancel()
			delete(m.logWatchers, key)
			delete(m.logPatterns, key)
		}
	}
	m.mu.Unlock()

	if ok {
		cancel()
	}
}

func (m *Monitor) run(ctx context.Context, clusterID, kubeConfig string) {
	defer m.finish(clusterID)

	client, err := m.k8s.GetClient(clusterID, kubeConfig)
	if err != nil {
		log.Printf("[monitor] cluster %s: failed to create client: %v", clusterID, err)
		return
	}

	// Initial evaluation of all existing pods.
	resourceVersion := ""
	if pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{}); err == nil {
		resourceVersion = pods.ResourceVersion
		policies := m.store.GetPolicies()
		for i := range pods.Items {
			m.evaluatePod(clusterID, client, &pods.Items[i], policies)
		}
	} else {
		log.Printf("[monitor] cluster %s: failed to list pods: %v", clusterID, err)
	}

	go m.watchPods(ctx, clusterID, client, resourceVersion)
	m.watchEvents(ctx, clusterID, kubeConfig)

	<-ctx.Done()
	log.Printf("[monitor] cluster %s: monitoring stopped", clusterID)
}

func (m *Monitor) finish(clusterID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cancels, clusterID)
	delete(m.ctxs, clusterID)
	delete(m.active, clusterID)
	for key, wcancel := range m.logWatchers {
		if strings.HasPrefix(key, clusterID+"|") {
			wcancel()
			delete(m.logWatchers, key)
			delete(m.logPatterns, key)
		}
	}
}

// watchPods keeps a watch on all pods, re-evaluating policies on changes and
// reconnecting with backoff when the watch drops.
func (m *Monitor) watchPods(ctx context.Context, clusterID string, client *kubecore.Clientset, resourceVersion string) {
	for {
		if ctx.Err() != nil {
			return
		}

		watcher, err := client.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{ResourceVersion: resourceVersion})
		if err != nil {
			log.Printf("[monitor] cluster %s: pod watch failed: %v", clusterID, err)
			if !sleepCtx(ctx, watchReconnectDelay) {
				return
			}
			continue
		}

		for event := range watcher.ResultChan() {
			pod, ok := event.Object.(*v1.Pod)
			if !ok {
				continue
			}
			switch event.Type {
			case watch.Added, watch.Modified:
				m.evaluatePod(clusterID, client, pod, m.store.GetPolicies())
			case watch.Deleted:
				m.clearPod(clusterID, pod)
			}
		}
		watcher.Stop()

		// Refresh resourceVersion before reconnecting.
		if list, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{}); err == nil {
			resourceVersion = list.ResourceVersion
		}
		if !sleepCtx(ctx, watchReconnectDelay) {
			return
		}
	}
}

// watchEvents streams Kubernetes Warning events into alerts.
func (m *Monitor) watchEvents(ctx context.Context, clusterID, kubeConfig string) {
	alertChan := make(chan models.Alert, eventAlertBuffer)
	if err := m.k8s.WatchEvents(ctx, clusterID, kubeConfig, alertChan); err != nil {
		log.Printf("[monitor] cluster %s: event watch failed to start: %v", clusterID, err)
		return
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case alert := <-alertChan:
				m.emitEventAlert(clusterID, alert)
			}
		}
	}()
}

// evaluatePod checks a pod against all policies and emits alerts for new
// violations. Violations that disappeared are cleared so they can alert again.
// It also syncs log-pattern watchers for policies containing "log_pattern:" rules.
func (m *Monitor) evaluatePod(clusterID string, client *kubecore.Clientset, pod *v1.Pod, policies []models.Policy) {
	current := make(map[string]struct{})

	for _, p := range policies {
		if p.Namespace != "" && p.Namespace != pod.Namespace {
			continue
		}
		for _, v := range kubernetes.EvaluatePolicy(pod, p) {
			key := fmt.Sprintf("%s|%s|%s|%s", pod.Namespace, pod.Name, v.Rule, v.Message)
			current[key] = struct{}{}
			if m.markNew(clusterID, key) {
				m.store.AddAlert(models.Alert{
					ID:        m.nextAlertID(),
					ClusterID: clusterID,
					Severity:  v.Severity,
					Message:   fmt.Sprintf("[%s] %s in %s/%s", p.Name, v.Message, pod.Namespace, pod.Name),
					Timestamp: time.Now(),
				})
			}
		}
	}

	m.prunePodKeys(clusterID, pod, current)
	m.syncLogWatcher(clusterID, client, pod, policies)
}

// syncLogWatcher starts, restarts or stops the log tailer for a pod based on
// the "log_pattern:<regex>" rules of the policies that apply to it.
func (m *Monitor) syncLogWatcher(clusterID string, client *kubecore.Clientset, pod *v1.Pod, policies []models.Policy) {
	key := clusterID + "|" + pod.Namespace + "|" + pod.Name

	var pats []logPattern
	for _, p := range policies {
		if p.Namespace != "" && p.Namespace != pod.Namespace {
			continue
		}
		for _, rule := range p.Rules {
			trimmed := strings.TrimSpace(rule)
			if !strings.HasPrefix(strings.ToLower(trimmed), "log_pattern:") {
				continue
			}
			expr := strings.TrimSpace(trimmed[len("log_pattern:"):])
			re, err := regexp.Compile(expr)
			if err != nil {
				log.Printf("[monitor] invalid log_pattern %q: %v", expr, err)
				continue
			}
			pats = append(pats, logPattern{rule: expr, re: re})
		}
	}

	m.mu.Lock()
	existing := m.logPatterns[key]
	same := len(existing) == len(pats)
	if same {
		for i := range pats {
			if existing[i].rule != pats[i].rule {
				same = false
				break
			}
		}
	}
	if len(pats) == 0 {
		if cancel, ok := m.logWatchers[key]; ok {
			cancel()
			delete(m.logWatchers, key)
		}
		delete(m.logPatterns, key)
		m.mu.Unlock()
		return
	}
	if same {
		if _, ok := m.logWatchers[key]; ok {
			m.mu.Unlock()
			return
		}
	}
	if cancel, ok := m.logWatchers[key]; ok {
		cancel()
	}
	clusterCtx, ok := m.ctxs[clusterID]
	if !ok {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(clusterCtx)
	m.logWatchers[key] = cancel
	m.logPatterns[key] = pats
	m.mu.Unlock()

	podCopy := pod.DeepCopy()
	go m.watchPodLogs(ctx, clusterID, client, podCopy, pats)
}

// watchPodLogs tails the logs of every container in a pod and alerts on
// lines matching the configured patterns.
func (m *Monitor) watchPodLogs(ctx context.Context, clusterID string, client *kubecore.Clientset, pod *v1.Pod, pats []logPattern) {
	for _, container := range pod.Spec.Containers {
		go m.tailContainerLogs(ctx, clusterID, client, pod.Namespace, pod.Name, container.Name, pats)
	}
}

func (m *Monitor) tailContainerLogs(ctx context.Context, clusterID string, client *kubecore.Clientset, namespace, podName, containerName string, pats []logPattern) {
	for {
		if ctx.Err() != nil {
			return
		}

		stream, err := kubernetes.StreamContainerLogs(ctx, client, namespace, podName, containerName, 0, true)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[monitor] log stream %s/%s/%s failed: %v", namespace, podName, containerName, err)
			if !sleepCtx(ctx, watchReconnectDelay) {
				return
			}
			continue
		}

		scanner := bufio.NewScanner(stream)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			for _, p := range pats {
				if p.re.MatchString(line) {
					key := fmt.Sprintf("log|%s|%s|%s|%s|%s", namespace, podName, containerName, p.rule, line)
					if m.markNew(clusterID, key) {
						truncated := line
						if len(truncated) > 300 {
							truncated = truncated[:300] + "..."
						}
						m.store.AddAlert(models.Alert{
							ID:        m.nextAlertID(),
							ClusterID: clusterID,
							Severity:  "High",
							Message:   fmt.Sprintf("[log_pattern] %q matched in %s/%s/%s: %s", p.rule, namespace, podName, containerName, truncated),
							Timestamp: time.Now(),
						})
					}
				}
			}
		}
		stream.Close()

		if ctx.Err() != nil {
			return
		}
		if !sleepCtx(ctx, watchReconnectDelay) {
			return
		}
	}
}

// clearPod removes all dedup keys and stops log watchers for a deleted pod.
func (m *Monitor) clearPod(clusterID string, pod *v1.Pod) {
	prefix := fmt.Sprintf("%s|%s|", pod.Namespace, pod.Name)
	m.mu.Lock()
	for key := range m.active[clusterID] {
		if strings.HasPrefix(key, prefix) {
			delete(m.active[clusterID], key)
		}
	}
	logKey := clusterID + "|" + pod.Namespace + "|" + pod.Name
	if cancel, ok := m.logWatchers[logKey]; ok {
		cancel()
		delete(m.logWatchers, logKey)
		delete(m.logPatterns, logKey)
	}
	m.mu.Unlock()
}

// prunePodKeys removes dedup keys for this pod that are no longer violated.
func (m *Monitor) prunePodKeys(clusterID string, pod *v1.Pod, current map[string]struct{}) {
	prefix := fmt.Sprintf("%s|%s|", pod.Namespace, pod.Name)
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.active[clusterID] {
		if strings.HasPrefix(key, prefix) {
			if _, ok := current[key]; !ok {
				delete(m.active[clusterID], key)
			}
		}
	}
}

// emitEventAlert stores a Kubernetes event as an alert, deduplicated by its
// message (which includes the event count, so repeats alert once per count).
func (m *Monitor) emitEventAlert(clusterID string, alert models.Alert) {
	key := "event|" + alert.Message
	if m.markNew(clusterID, key) {
		alert.ID = m.nextAlertID()
		m.store.AddAlert(alert)
	}
}

// markNew records key for clusterID and reports whether it was not present.
func (m *Monitor) markNew(clusterID, key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active[clusterID] == nil {
		m.active[clusterID] = make(map[string]struct{})
	}
	if _, ok := m.active[clusterID][key]; ok {
		return false
	}
	m.active[clusterID][key] = struct{}{}
	return true
}

func (m *Monitor) nextAlertID() string {
	return fmt.Sprintf("alert-%d-%d", time.Now().UnixNano(), atomic.AddInt64(&m.alertSeq, 1))
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
