package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/models"
)

// FileStorage provides a simple file-backed user store for temporary local credentials.
// It delegates in-memory behavior to MemoryStorage and persists users to a JSON file on changes.
type FileStorage struct {
	mem      *MemoryStorage
	filePath string
	mu       sync.Mutex
}

// fileUser is the on-disk representation (includes Password) - models.User has `json:"-"` for Password
// so we can't marshal models.User directly.
type fileUser struct {
	ID        string      `json:"id"`
	Email     string      `json:"email"`
	Password  string      `json:"password"`
	FirstName string      `json:"first_name"`
	LastName  string      `json:"last_name"`
	Role      models.Role `json:"role"`
	TokenKeys []string    `json:"token_keys"`
	CreatedAt time.Time   `json:"created_at"`
}

// NewFileStorage initializes a FileStorage, loading any existing users from the given file.
func NewFileStorage(path string) (Storage, error) {
	fs := &FileStorage{
		mem:      NewMemoryStorage(),
		filePath: path,
	}

	if _, err := os.Stat(path); err == nil {
		// file exists - load users
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read local auth file: %w", err)
		}
		var fus []fileUser
		if len(b) > 0 {
			if err := json.Unmarshal(b, &fus); err != nil {
				return nil, fmt.Errorf("failed to parse local auth file: %w", err)
			}
			for _, fu := range fus {
				u := models.User{
					ID:        fu.ID,
					Email:     fu.Email,
					Password:  fu.Password,
					FirstName: fu.FirstName,
					LastName:  fu.LastName,
					Role:      fu.Role,
					TokenKeys: fu.TokenKeys,
					CreatedAt: fu.CreatedAt,
				}
				_ = fs.mem.AddUser(u)
			}
		}
	}
	return fs, nil
}

func (fs *FileStorage) persistUsers() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	users := fs.mem.GetAllUsers()
	fus := make([]fileUser, 0, len(users))
	for _, u := range users {
		fus = append(fus, fileUser{
			ID:        u.ID,
			Email:     u.Email,
			Password:  u.Password,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			Role:      u.Role,
			TokenKeys: u.TokenKeys,
			CreatedAt: u.CreatedAt,
		})
	}
	b, err := json.MarshalIndent(fus, "", "  ")
	if err != nil {
		return err
	}
	// write file with 0600 to keep credentials locally private
	return os.WriteFile(fs.filePath, b, 0o600)
}

// User methods (persist on mutating ops)
func (fs *FileStorage) AddUser(u models.User) error {
	if err := fs.mem.AddUser(u); err != nil {
		return err
	}
	return fs.persistUsers()
}

func (fs *FileStorage) GetUser(id string) (models.User, error) {
	return fs.mem.GetUser(id)
}

func (fs *FileStorage) GetUserByEmail(email string) (models.User, error) {
	return fs.mem.GetUserByEmail(email)
}

func (fs *FileStorage) GetAllUsers() []models.User {
	return fs.mem.GetAllUsers()
}

func (fs *FileStorage) UpdateUser(u models.User) error {
	if err := fs.mem.UpdateUser(u); err != nil {
		return err
	}
	return fs.persistUsers()
}

func (fs *FileStorage) DeleteUser(id string) error {
	if err := fs.mem.DeleteUser(id); err != nil {
		return err
	}
	return fs.persistUsers()
}

// Cluster/Policy/Alert/Report methods delegated to memory (not persisted)
func (fs *FileStorage) AddCluster(c models.Cluster) error            { return fs.mem.AddCluster(c) }
func (fs *FileStorage) GetClusters() []models.Cluster                { return fs.mem.GetClusters() }
func (fs *FileStorage) GetCluster(id string) (models.Cluster, error) { return fs.mem.GetCluster(id) }
func (fs *FileStorage) DeleteCluster(id string) error                { return fs.mem.DeleteCluster(id) }

func (fs *FileStorage) AddPolicy(p models.Policy) error            { return fs.mem.AddPolicy(p) }
func (fs *FileStorage) GetPolicies() []models.Policy               { return fs.mem.GetPolicies() }
func (fs *FileStorage) GetPolicy(id string) (models.Policy, error) { return fs.mem.GetPolicy(id) }
func (fs *FileStorage) DeletePolicy(id string) error               { return fs.mem.DeletePolicy(id) }

func (fs *FileStorage) AddAlert(a models.Alert)             { fs.mem.AddAlert(a) }
func (fs *FileStorage) GetAlerts() []models.Alert           { return fs.mem.GetAlerts() }
func (fs *FileStorage) AddReport(r models.IncidentReport)   { fs.mem.AddReport(r) }
func (fs *FileStorage) GetReports() []models.IncidentReport { return fs.mem.GetReports() }
