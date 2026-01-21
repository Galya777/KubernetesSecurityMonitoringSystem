package models

import "time"

type Role string

const (
	RoleAnonymous       Role = "Anonymous"
	RoleStudent         Role = "Student"
	RoleInstructor      Role = "Instructor"
	RoleAdmin           Role = "Administrator"
	RoleSecurityAnalyst Role = "Security Analyst"
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      Role      `json:"role"`
	TokenKeys []string  `json:"token_keys"`
	CreatedAt time.Time `json:"created_at"`
}

type Cluster struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	KubeConfig string    `json:"kube_config"` // Base64 or path
	Status     string    `json:"status"`
	Metrics    Metrics   `json:"metrics"`
	CreatedAt  time.Time `json:"created_at"`
}

type Metrics struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	PodCount    int     `json:"pod_count"`
}

type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Rules       []string  `json:"rules"`
	Namespace   string    `json:"namespace"`
	CreatedAt   time.Time `json:"created_at"`
}

type Alert struct {
	ID        string    `json:"id"`
	ClusterID string    `json:"cluster_id"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type IncidentReport struct {
	ID        string    `json:"id"`
	AlertID   string    `json:"alert_id"`
	Details   string    `json:"details"`
	Action    string    `json:"action_taken"`
	Timestamp time.Time `json:"timestamp"`
}
