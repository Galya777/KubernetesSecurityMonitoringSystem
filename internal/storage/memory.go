package storage

import (
	"errors"
	"sync"

	"KubernetesSecurityMonitoringSystem/internal/models"
)

type Storage interface {
	AddUser(u models.User) error
	GetUser(id string) (models.User, error)
	GetUserByEmail(email string) (models.User, error)
	GetAllUsers() []models.User
	UpdateUser(u models.User) error
	DeleteUser(id string) error

	AddCluster(c models.Cluster) error
	GetClusters() []models.Cluster
	GetCluster(id string) (models.Cluster, error)
	DeleteCluster(id string) error

	AddPolicy(p models.Policy) error
	GetPolicies() []models.Policy
	GetPolicy(id string) (models.Policy, error)
	DeletePolicy(id string) error

	AddAlert(a models.Alert)
	GetAlerts() []models.Alert
	AddReport(r models.IncidentReport)
	GetReports() []models.IncidentReport

	AddContainer(c models.Container) error
	GetContainer(id string) (models.Container, error)
	GetAllContainers() []models.Container
	DeleteContainer(id string) error
	AttachContainerToUser(userID, containerID string) error
	DetachContainerFromUser(userID, containerID string) error
	GetContainersByUser(userID string) ([]models.Container, error)
}

type MemoryStorage struct {
	users          map[string]models.User
	clusters       map[string]models.Cluster
	policies       map[string]models.Policy
	containers     map[string]models.Container
	userContainers map[string]map[string]bool
	alerts         []models.Alert
	reports        []models.IncidentReport
	mu             sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		users:          make(map[string]models.User),
		clusters:       make(map[string]models.Cluster),
		policies:       make(map[string]models.Policy),
		containers:     make(map[string]models.Container),
		userContainers: make(map[string]map[string]bool),
		alerts:         make([]models.Alert, 0),
		reports:        make([]models.IncidentReport, 0),
	}
}

// User methods
func (s *MemoryStorage) AddUser(u models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.users {
		if existing.Email == u.Email {
			return errors.New("email already in use")
		}
	}
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

// Container methods
func (s *MemoryStorage) AddContainer(c models.Container) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.containers[c.ID]; ok {
		return errors.New("container already exists")
	}
	s.containers[c.ID] = c
	return nil
}

func (s *MemoryStorage) GetContainer(id string) (models.Container, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.containers[id]
	if !ok {
		return models.Container{}, errors.New("container not found")
	}
	return c, nil
}

func (s *MemoryStorage) GetAllContainers() []models.Container {
	s.mu.RLock()
	defer s.mu.RUnlock()
	containers := make([]models.Container, 0, len(s.containers))
	for _, c := range s.containers {
		containers = append(containers, c)
	}
	return containers
}

func (s *MemoryStorage) DeleteContainer(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.containers[id]; !ok {
		return errors.New("container not found")
	}
	delete(s.containers, id)
	for uid, set := range s.userContainers {
		delete(set, id)
		if len(set) == 0 {
			delete(s.userContainers, uid)
		}
	}
	return nil
}

func (s *MemoryStorage) AttachContainerToUser(userID, containerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return errors.New("user not found")
	}
	if _, ok := s.containers[containerID]; !ok {
		return errors.New("container not found")
	}
	if _, ok := s.userContainers[userID]; !ok {
		s.userContainers[userID] = make(map[string]bool)
	}
	s.userContainers[userID][containerID] = true
	return nil
}

func (s *MemoryStorage) DetachContainerFromUser(userID, containerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set, ok := s.userContainers[userID]
	if !ok {
		return nil
	}
	delete(set, containerID)
	if len(set) == 0 {
		delete(s.userContainers, userID)
	}
	return nil
}

func (s *MemoryStorage) GetContainersByUser(userID string) ([]models.Container, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.users[userID]; !ok {
		return nil, errors.New("user not found")
	}
	set := s.userContainers[userID]
	containers := make([]models.Container, 0, len(set))
	for cid := range set {
		if c, ok := s.containers[cid]; ok {
			containers = append(containers, c)
		}
	}
	return containers, nil
}
