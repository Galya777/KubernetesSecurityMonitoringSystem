package storage

import (
	"errors"
	"sync"

	"KubernetesSecurityMonitoringSystem/internal/models"
)

type MemoryStorage struct {
	users    map[string]models.User
	clusters map[string]models.Cluster
	policies map[string]models.Policy
	alerts   []models.Alert
	reports  []models.IncidentReport
	mu       sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		users:    make(map[string]models.User),
		clusters: make(map[string]models.Cluster),
		policies: make(map[string]models.Policy),
		alerts:   make([]models.Alert, 0),
		reports:  make([]models.IncidentReport, 0),
	}
}

// User methods
func (s *MemoryStorage) AddUser(u models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; ok {
		return errors.New("user already exists")
	}
	s.users[u.ID] = u
	return nil
}

func (s *MemoryStorage) GetUser(id string) (models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return models.User{}, errors.New("user not found")
	}
	return u, nil
}

func (s *MemoryStorage) GetUserByEmail(email string) (models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return models.User{}, errors.New("user not found")
}

func (s *MemoryStorage) GetAllUsers() []models.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]models.User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	return users
}

func (s *MemoryStorage) UpdateUser(u models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; !ok {
		return errors.New("user not found")
	}
	s.users[u.ID] = u
	return nil
}

func (s *MemoryStorage) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
	return nil
}

// Cluster methods
func (s *MemoryStorage) AddCluster(c models.Cluster) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clusters[c.ID] = c
	return nil
}

func (s *MemoryStorage) GetClusters() []models.Cluster {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clusters := make([]models.Cluster, 0, len(s.clusters))
	for _, c := range s.clusters {
		clusters = append(clusters, c)
	}
	return clusters
}

func (s *MemoryStorage) GetCluster(id string) (models.Cluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clusters[id]
	if !ok {
		return models.Cluster{}, errors.New("cluster not found")
	}
	return c, nil
}

func (s *MemoryStorage) DeleteCluster(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clusters, id)
	return nil
}

// Policy methods
func (s *MemoryStorage) AddPolicy(p models.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = p
	return nil
}

func (s *MemoryStorage) GetPolicies() []models.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policies := make([]models.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		policies = append(policies, p)
	}
	return policies
}

func (s *MemoryStorage) GetPolicy(id string) (models.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	if !ok {
		return models.Policy{}, errors.New("policy not found")
	}
	return p, nil
}

func (s *MemoryStorage) DeletePolicy(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
	return nil
}

// Alert and Report methods
func (s *MemoryStorage) AddAlert(a models.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, a)
}

func (s *MemoryStorage) GetAlerts() []models.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.alerts
}

func (s *MemoryStorage) AddReport(r models.IncidentReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, r)
}

func (s *MemoryStorage) GetReports() []models.IncidentReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reports
}
