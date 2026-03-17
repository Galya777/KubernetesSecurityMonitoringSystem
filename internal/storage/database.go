package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/models"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type DatabaseStorage struct {
	db *sql.DB
}

func NewDatabaseStorage() (*DatabaseStorage, error) {
	host := getEnvFirst([]string{"POSTGRES_HOST", "DB_HOST"}, "localhost")
	port := getEnvFirst([]string{"POSTGRES_PORT", "DB_PORT"}, "5433")
	user := getEnvFirst([]string{"POSTGRES_USER", "DB_USER"}, "postgres")
	password := getEnvFirst([]string{"POSTGRES_PASSWORD", "DB_PASSWORD"}, "admin123")
	dbname := getEnvFirst([]string{"POSTGRES_DATABASE_NAME", "POSTGRES_DB", "DB_NAME"}, "ksms")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	log.Printf("Connecting to database at %s:%s as user %s...", host, port, user)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	s := &DatabaseStorage{db: db}
	if err := s.initSchema(); err != nil {
		return nil, err
	}
	if err := s.ensureDefaultAdmin(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *DatabaseStorage) ensureDefaultAdmin() error {
	adminEmail := getEnvFirst([]string{"DEFAULT_ADMIN_EMAIL", "ADMIN_EMAIL"}, "admin@ksms.io")
	adminPassword := getEnvFirst([]string{"DEFAULT_ADMIN_PASSWORD", "ADMIN_PASSWORD"}, "admin123")

	var exists bool
	if err := s.db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", adminEmail).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash default admin password: %w", err)
	}

	u := models.User{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Email:     adminEmail,
		Password:  string(hashedPassword),
		FirstName: "Admin",
		LastName:  "KSMS",
		Role:      models.RoleAdmin,
		TokenKeys: []string{},
		CreatedAt: time.Now(),
	}

	if err := s.AddUser(u); err != nil {
		return err
	}

	log.Printf("Seeded default admin user %s", adminEmail)
	return nil
}

// Container methods
func (s *DatabaseStorage) AddContainer(c models.Container) error {
	_, err := s.db.Exec("INSERT INTO containers (id, cluster_id, namespace, pod_name, container_name, image, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
		c.ID, c.ClusterID, c.Namespace, c.PodName, c.ContainerName, c.Image, c.Status, c.CreatedAt)
	return err
}

func (s *DatabaseStorage) GetContainer(id string) (models.Container, error) {
	var c models.Container
	err := s.db.QueryRow("SELECT id, cluster_id, namespace, pod_name, container_name, image, status, created_at FROM containers WHERE id = $1", id).
		Scan(&c.ID, &c.ClusterID, &c.Namespace, &c.PodName, &c.ContainerName, &c.Image, &c.Status, &c.CreatedAt)
	if err != nil {
		return models.Container{}, err
	}
	return c, nil
}

func (s *DatabaseStorage) GetAllContainers() []models.Container {
	rows, err := s.db.Query("SELECT id, cluster_id, namespace, pod_name, container_name, image, status, created_at FROM containers")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var containers []models.Container
	for rows.Next() {
		var c models.Container
		if err := rows.Scan(&c.ID, &c.ClusterID, &c.Namespace, &c.PodName, &c.ContainerName, &c.Image, &c.Status, &c.CreatedAt); err != nil {
			continue
		}
		containers = append(containers, c)
	}
	return containers
}

func (s *DatabaseStorage) DeleteContainer(id string) error {
	if _, err := s.db.Exec("DELETE FROM user_containers WHERE container_id=$1", id); err != nil {
		return err
	}
	_, err := s.db.Exec("DELETE FROM containers WHERE id=$1", id)
	return err
}

func (s *DatabaseStorage) AttachContainerToUser(userID, containerID string) error {
	_, err := s.db.Exec("INSERT INTO user_containers (user_id, container_id, created_at) VALUES ($1,$2,$3) ON CONFLICT (user_id, container_id) DO NOTHING",
		userID, containerID, time.Now())
	return err
}

func (s *DatabaseStorage) DetachContainerFromUser(userID, containerID string) error {
	_, err := s.db.Exec("DELETE FROM user_containers WHERE user_id=$1 AND container_id=$2", userID, containerID)
	return err
}

func (s *DatabaseStorage) GetContainersByUser(userID string) ([]models.Container, error) {
	rows, err := s.db.Query(`SELECT c.id, c.cluster_id, c.namespace, c.pod_name, c.container_name, c.image, c.status, c.created_at
		FROM containers c
		JOIN user_containers uc ON uc.container_id = c.id
		WHERE uc.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	containers := make([]models.Container, 0)
	for rows.Next() {
		var c models.Container
		if err := rows.Scan(&c.ID, &c.ClusterID, &c.Namespace, &c.PodName, &c.ContainerName, &c.Image, &c.Status, &c.CreatedAt); err != nil {
			continue
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func (s *DatabaseStorage) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			first_name TEXT,
			last_name TEXT,
			role TEXT,
			token_keys JSONB,
			created_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE TABLE IF NOT EXISTS containers (
			id TEXT PRIMARY KEY,
			cluster_id TEXT,
			namespace TEXT,
			pod_name TEXT,
			container_name TEXT,
			image TEXT,
			status TEXT,
			created_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE TABLE IF NOT EXISTS user_containers (
			user_id TEXT NOT NULL,
			container_id TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE,
			PRIMARY KEY (user_id, container_id)
		)`,
		`CREATE TABLE IF NOT EXISTS clusters (
			id TEXT PRIMARY KEY,
			name TEXT,
			kube_config TEXT,
			status TEXT,
			metrics JSONB,
			created_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE TABLE IF NOT EXISTS policies (
			id TEXT PRIMARY KEY,
			name TEXT,
			description TEXT,
			rules JSONB,
			namespace TEXT,
			created_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id TEXT PRIMARY KEY,
			cluster_id TEXT,
			severity TEXT,
			message TEXT,
			timestamp TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE TABLE IF NOT EXISTS reports (
			id TEXT PRIMARY KEY,
			alert_id TEXT,
			details TEXT,
			action_taken TEXT,
			timestamp TIMESTAMP WITH TIME ZONE
		)`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// User methods
func (s *DatabaseStorage) AddUser(u models.User) error {
	tokenKeys, _ := json.Marshal(u.TokenKeys)
	_, err := s.db.Exec("INSERT INTO users (id, email, password, first_name, last_name, role, token_keys, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		u.ID, u.Email, u.Password, u.FirstName, u.LastName, u.Role, tokenKeys, u.CreatedAt)
	return err
}

func (s *DatabaseStorage) GetUser(id string) (models.User, error) {
	var u models.User
	var tokenKeys []byte
	err := s.db.QueryRow("SELECT id, email, password, first_name, last_name, role, token_keys, created_at FROM users WHERE id = $1", id).
		Scan(&u.ID, &u.Email, &u.Password, &u.FirstName, &u.LastName, &u.Role, &tokenKeys, &u.CreatedAt)
	if err != nil {
		return models.User{}, err
	}
	json.Unmarshal(tokenKeys, &u.TokenKeys)
	return u, nil
}

func (s *DatabaseStorage) GetUserByEmail(email string) (models.User, error) {
	var u models.User
	var tokenKeys []byte
	err := s.db.QueryRow("SELECT id, email, password, first_name, last_name, role, token_keys, created_at FROM users WHERE email = $1", email).
		Scan(&u.ID, &u.Email, &u.Password, &u.FirstName, &u.LastName, &u.Role, &tokenKeys, &u.CreatedAt)
	if err != nil {
		return models.User{}, err
	}
	json.Unmarshal(tokenKeys, &u.TokenKeys)
	return u, nil
}

func (s *DatabaseStorage) GetAllUsers() []models.User {
	rows, err := s.db.Query("SELECT id, email, password, first_name, last_name, role, token_keys, created_at FROM users")
	if err != nil {
		log.Println("Error querying users:", err)
		return nil
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		var tokenKeys []byte
		if err := rows.Scan(&u.ID, &u.Email, &u.Password, &u.FirstName, &u.LastName, &u.Role, &tokenKeys, &u.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal(tokenKeys, &u.TokenKeys)
		users = append(users, u)
	}
	return users
}

func (s *DatabaseStorage) UpdateUser(u models.User) error {
	tokenKeys, _ := json.Marshal(u.TokenKeys)
	_, err := s.db.Exec("UPDATE users SET email=$1, password=$2, first_name=$3, last_name=$4, role=$5, token_keys=$6 WHERE id=$7",
		u.Email, u.Password, u.FirstName, u.LastName, u.Role, tokenKeys, u.ID)
	return err
}

func (s *DatabaseStorage) DeleteUser(id string) error {
	_, err := s.db.Exec("DELETE FROM users WHERE id=$1", id)
	return err
}

// Cluster methods
func (s *DatabaseStorage) AddCluster(c models.Cluster) error {
	metrics, _ := json.Marshal(c.Metrics)
	_, err := s.db.Exec("INSERT INTO clusters (id, name, kube_config, status, metrics, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		c.ID, c.Name, c.KubeConfig, c.Status, metrics, c.CreatedAt)
	return err
}

func (s *DatabaseStorage) GetClusters() []models.Cluster {
	rows, err := s.db.Query("SELECT id, name, kube_config, status, metrics, created_at FROM clusters")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var clusters []models.Cluster
	for rows.Next() {
		var c models.Cluster
		var metrics []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.KubeConfig, &c.Status, &metrics, &c.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal(metrics, &c.Metrics)
		clusters = append(clusters, c)
	}
	return clusters
}

func (s *DatabaseStorage) GetCluster(id string) (models.Cluster, error) {
	var c models.Cluster
	var metrics []byte
	err := s.db.QueryRow("SELECT id, name, kube_config, status, metrics, created_at FROM clusters WHERE id = $1", id).
		Scan(&c.ID, &c.Name, &c.KubeConfig, &c.Status, &metrics, &c.CreatedAt)
	if err != nil {
		return models.Cluster{}, err
	}
	json.Unmarshal(metrics, &c.Metrics)
	return c, nil
}

func (s *DatabaseStorage) DeleteCluster(id string) error {
	_, err := s.db.Exec("DELETE FROM clusters WHERE id=$1", id)
	return err
}

// Policy methods
func (s *DatabaseStorage) AddPolicy(p models.Policy) error {
	rules, _ := json.Marshal(p.Rules)
	_, err := s.db.Exec("INSERT INTO policies (id, name, description, rules, namespace, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		p.ID, p.Name, p.Description, rules, p.Namespace, p.CreatedAt)
	return err
}

func (s *DatabaseStorage) GetPolicies() []models.Policy {
	rows, err := s.db.Query("SELECT id, name, description, rules, namespace, created_at FROM policies")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var policies []models.Policy
	for rows.Next() {
		var p models.Policy
		var rules []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &rules, &p.Namespace, &p.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal(rules, &p.Rules)
		policies = append(policies, p)
	}
	return policies
}

func (s *DatabaseStorage) GetPolicy(id string) (models.Policy, error) {
	var p models.Policy
	var rules []byte
	err := s.db.QueryRow("SELECT id, name, description, rules, namespace, created_at FROM policies WHERE id = $1", id).
		Scan(&p.ID, &p.Name, &p.Description, &rules, &p.Namespace, &p.CreatedAt)
	if err != nil {
		return models.Policy{}, err
	}
	json.Unmarshal(rules, &p.Rules)
	return p, nil
}

func (s *DatabaseStorage) DeletePolicy(id string) error {
	_, err := s.db.Exec("DELETE FROM policies WHERE id=$1", id)
	return err
}

// Alert and Report methods
func (s *DatabaseStorage) AddAlert(a models.Alert) {
	s.db.Exec("INSERT INTO alerts (id, cluster_id, severity, message, timestamp) VALUES ($1, $2, $3, $4, $5)",
		a.ID, a.ClusterID, a.Severity, a.Message, a.Timestamp)
}

func (s *DatabaseStorage) GetAlerts() []models.Alert {
	rows, err := s.db.Query("SELECT id, cluster_id, severity, message, timestamp FROM alerts ORDER BY timestamp DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		if err := rows.Scan(&a.ID, &a.ClusterID, &a.Severity, &a.Message, &a.Timestamp); err != nil {
			continue
		}
		alerts = append(alerts, a)
	}
	return alerts
}

func (s *DatabaseStorage) AddReport(r models.IncidentReport) {
	s.db.Exec("INSERT INTO reports (id, alert_id, details, action_taken, timestamp) VALUES ($1, $2, $3, $4, $5)",
		r.ID, r.AlertID, r.Details, r.Action, r.Timestamp)
}

func (s *DatabaseStorage) GetReports() []models.IncidentReport {
	rows, err := s.db.Query("SELECT id, alert_id, details, action_taken, timestamp FROM reports ORDER BY timestamp DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reports []models.IncidentReport
	for rows.Next() {
		var r models.IncidentReport
		if err := rows.Scan(&r.ID, &r.AlertID, &r.Details, &r.Action, &r.Timestamp); err != nil {
			continue
		}
		reports = append(reports, r)
	}
	return reports
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvFirst(keys []string, fallback string) string {
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			return value
		}
	}
	return fallback
}
