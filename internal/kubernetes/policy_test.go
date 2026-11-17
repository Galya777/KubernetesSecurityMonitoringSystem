package kubernetes

import (
	"testing"

	"KubernetesSecurityMonitoringSystem/internal/models"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func boolPtr(b bool) *bool { return &b }

func podWithContainers(containers ...v1.Container) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-pod"},
		Spec:       v1.PodSpec{Containers: containers},
	}
}

func TestEvaluatePolicyPrivileged(t *testing.T) {
	pod := podWithContainers(v1.Container{
		Name: "app",
		SecurityContext: &v1.SecurityContext{
			Privileged: boolPtr(true),
		},
	})
	policy := models.Policy{Name: "p", Rules: []string{"no_privileged=true"}}

	violations := EvaluatePolicy(pod, policy)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Severity != "High" {
		t.Errorf("expected High severity, got %s", violations[0].Severity)
	}
}

func TestEvaluatePolicyCleanPod(t *testing.T) {
	pod := podWithContainers(v1.Container{
		Name: "app",
		SecurityContext: &v1.SecurityContext{
			Privileged:             boolPtr(false),
			RunAsNonRoot:           boolPtr(true),
			ReadOnlyRootFilesystem: boolPtr(true),
		},
	})
	policy := models.Policy{Name: "p", Rules: []string{
		"no_privileged=true",
		"runasnonroot: true",
		"hostnetwork: false",
		"readonlyrootfilesystem: true",
	}}

	if violations := EvaluatePolicy(pod, policy); len(violations) != 0 {
		t.Fatalf("expected no violations, got %v", violations)
	}
}

func TestEvaluatePolicyHostNetwork(t *testing.T) {
	pod := podWithContainers(v1.Container{Name: "app"})
	pod.Spec.HostNetwork = true

	policy := models.Policy{Name: "p", Rules: []string{"hostnetwork: false"}}
	violations := EvaluatePolicy(pod, policy)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
}

func TestEvaluatePolicyUnknownRuleIgnored(t *testing.T) {
	pod := podWithContainers(v1.Container{Name: "app"})
	policy := models.Policy{Name: "p", Rules: []string{"disallow_exec=true", "log_pattern:foo"}}
	if violations := EvaluatePolicy(pod, policy); len(violations) != 0 {
		t.Fatalf("expected no violations for runtime rules, got %v", violations)
	}
}
