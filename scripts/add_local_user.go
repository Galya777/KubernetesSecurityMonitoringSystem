package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"KubernetesSecurityMonitoringSystem/internal/models"
)

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

func main() {
	email := flag.String("email", "demo-admin@local", "email")
	password := flag.String("password", "demoPass123", "password")
	file := flag.String("file", ".local_users_demo.json", "path to local users file")
	flag.Parse()

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("failed to hash password:", err)
		os.Exit(1)
	}

	u := fileUser{
		ID:        time.Now().Format("20060102150405"),
		Email:     *email,
		Password:  string(hash),
		FirstName: "Demo",
		LastName:  "Admin",
		Role:      models.RoleAdmin,
		TokenKeys: nil,
		CreatedAt: time.Now(),
	}

	var users []fileUser
	if b, err := os.ReadFile(*file); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &users) // ignore errors and append
	}

	// remove any existing with same email
	filtered := make([]fileUser, 0, len(users))
	for _, ex := range users {
		if ex.Email == u.Email {
			continue
		}
		filtered = append(filtered, ex)
	}
	filtered = append(filtered, u)

	out, _ := json.MarshalIndent(filtered, "", "  ")
	if err := os.WriteFile(*file, out, 0o600); err != nil {
		fmt.Println("failed to write file:", err)
		os.Exit(1)
	}
	fmt.Println("wrote user to", *file)
}
