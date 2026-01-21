package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"KubernetesSecurityMonitoringSystem/internal/models"

	_ "github.com/lib/pq"
)

type DatabaseStorage struct {
	db *sql.DB
}

func NewDatabaseStorage() (*DatabaseStorage, error) {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "postgres")
	password := getEnv("DB_PASSWORD", "password")
	dbname := getEnv("DB_NAME", "ksms")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	s := &DatabaseStorage{db: db}
	if err := s.initSchema(); err != nil {
		return nil, err
	}

	return s, nil
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
