package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/auth"
	"KubernetesSecurityMonitoringSystem/internal/handlers"
	"KubernetesSecurityMonitoringSystem/internal/kubernetes"
	"KubernetesSecurityMonitoringSystem/internal/middleware"
	"KubernetesSecurityMonitoringSystem/internal/models"
	"KubernetesSecurityMonitoringSystem/internal/storage"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	var store storage.Storage
	var err error
	dbConnected := false

	store, err = storage.NewDatabaseStorage()
	if err != nil {
		log.Printf("Failed to connect to database: %v. Falling back to local file storage.", err)
		// attempt to use file-backed storage in the current working directory
		localPath := os.Getenv("LOCAL_AUTH_FILE")
		if localPath == "" {
			localPath = ".local_users.json"
		}
		fs, ferr := storage.NewFileStorage(localPath)
		if ferr != nil {
			log.Printf("Failed to initialize file storage: %v. Falling back to in-memory storage.", ferr)
			store = storage.NewMemoryStorage()
		} else {
			store = fs
			log.Printf("Using file-backed local auth at %s", localPath)
		}
	} else {
		dbConnected = true
	}

	if dbConnected {
		log.Println("Database connection established.")
	} else {
		log.Println("Database connection not available. Using local storage.")
	}

	if err := ensureDefaultAdmin(store); err != nil {
		log.Printf("Failed to ensure default admin: %v", err)
	}
	seedDemoData(store)

	k8sMgr := kubernetes.NewClusterManager()

	// Handlers
	authH := &handlers.AuthHandler{Storage: store}
	userH := &handlers.UserHandler{Storage: store}
	resH := &handlers.ResourceHandler{Storage: store, K8s: k8sMgr}
	contH := &handlers.ContainerHandler{Storage: store}

	r := mux.NewRouter()
	r.Use(middleware.AuthMiddleware)

	// API Routes
	api := r.PathPrefix("/api").Subrouter()
	api.Use(middleware.AuthMiddleware)

	api.HandleFunc("/login", authH.Login).Methods("POST")
	api.HandleFunc("/logout", authH.Logout).Methods("POST")
	api.HandleFunc("/register", authH.Register).Methods("POST")
	api.HandleFunc("/containers", contH.CreateContainer).Methods("POST")
	api.HandleFunc("/containers/{containerId}", contH.DeleteContainer).Methods("DELETE")

	// Users API
	adminOnly := api.PathPrefix("/users").Subrouter()
	adminOnly.Use(middleware.RequireRole("Administrator"))
	adminOnly.HandleFunc("", userH.GetAllUsers).Methods("GET")

	api.HandleFunc("/users/{userId}", userH.GetUser).Methods("GET")
	api.HandleFunc("/users/{userId}", userH.UpdateUser).Methods("PUT")
	api.HandleFunc("/users/{userId}", userH.DeleteUser).Methods("DELETE")
	api.HandleFunc("/users/{userId}/containers", contH.GetContainersByUser).Methods("GET")
	api.HandleFunc("/users/{userId}/containers/{containerId}", contH.AttachContainerToUser).Methods("POST")
	api.HandleFunc("/users/{userId}/containers/{containerId}", contH.DetachContainerFromUser).Methods("DELETE")

	// Clusters API
	api.HandleFunc("/clusters", resH.GetClusters).Methods("GET")
	api.HandleFunc("/clusters", resH.CreateCluster).Methods("POST")
	api.HandleFunc("/clusters/{clusterId}", resH.DeleteCluster).Methods("DELETE")
	api.HandleFunc("/clusters/{clusterId}/discover/containers", resH.DiscoverContainers).Methods("GET")

	// Policies API
	api.HandleFunc("/policies", resH.GetPolicies).Methods("GET")
	api.HandleFunc("/policies", resH.CreatePolicy).Methods("POST")

	// Alerts and Reports API
	api.HandleFunc("/tests", resH.GetAlerts).Methods("GET")           // As per 4.7 URI
	api.HandleFunc("/tests/{testId}", resH.GetReports).Methods("GET") // As per 4.8 URI (mapping to reports)

	api.HandleFunc("/actions/{action}", resH.HandleAction).Methods("POST")

	// Metrics
	r.Handle("/metrics", promhttp.Handler())

	// Frontend Views
	r.HandleFunc("/", serveTemplate("home.html"))
	r.HandleFunc("/clusters", serveTemplate("clusters.html"))
	r.HandleFunc("/alerts", serveTemplate("alerts.html"))
	r.HandleFunc("/policies", serveTemplate("policies.html"))
	r.HandleFunc("/register", serveTemplate("register.html"))
	r.HandleFunc("/login", serveTemplate("login.html"))
	r.HandleFunc("/personal", serveTemplate("personal.html"))
	r.HandleFunc("/reports", serveTemplate("reports.html"))
	r.HandleFunc("/about", serveTemplate("about.html"))

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	addr := ":" + port

	log.Println("Server starting on", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}

func seedDemoData(store storage.Storage) {
	admin, err := store.GetUserByEmail("admin@ksms.io")
	if err != nil {
		return
	}
	containers, err := store.GetContainersByUser(admin.ID)
	if err == nil && len(containers) > 0 {
		return
	}

	demoClusterID := "demo-cluster"
	for i := 1; i <= 3; i++ {
		c := models.Container{
			ID:            fmt.Sprintf("demo-%d", i),
			ClusterID:     demoClusterID,
			Namespace:     "default",
			PodName:       fmt.Sprintf("demo-pod-%d", i),
			ContainerName: "app",
			Image:         "nginx:latest",
			Status:        "Running",
			CreatedAt:     time.Now(),
		}
		if err := store.AddContainer(c); err == nil {
			_ = store.AttachContainerToUser(admin.ID, c.ID)
		}
	}

	store.AddAlert(models.Alert{ID: "demo-alert-1", ClusterID: demoClusterID, Severity: "High", Message: "Suspicious exec detected in container", Timestamp: time.Now()})
	store.AddAlert(models.Alert{ID: "demo-alert-2", ClusterID: demoClusterID, Severity: "Medium", Message: "Privileged container started", Timestamp: time.Now().Add(-2 * time.Minute)})
}

func ensureDefaultAdmin(store storage.Storage) error {
	adminEmail := os.Getenv("DEFAULT_ADMIN_EMAIL")
	if adminEmail == "" {
		adminEmail = os.Getenv("ADMIN_EMAIL")
	}
	if adminEmail == "" {
		adminEmail = "admin@ksms.io"
	}

	adminPassword := os.Getenv("DEFAULT_ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = os.Getenv("ADMIN_PASSWORD")
	}
	if adminPassword == "" {
		adminPassword = "admin123"
	}

	existing, err := store.GetUserByEmail(adminEmail)
	if err == nil {
		if bcrypt.CompareHashAndPassword([]byte(existing.Password), []byte(adminPassword)) == nil {
			return nil
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash default admin password: %w", err)
		}
		existing.Password = string(hashedPassword)
		existing.Role = models.RoleAdmin
		if uerr := store.UpdateUser(existing); uerr != nil {
			return uerr
		}
		log.Printf("Updated default admin credentials for %s", adminEmail)
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

	if err := store.AddUser(u); err != nil {
		return err
	}
	log.Printf("Seeded default admin user %s", adminEmail)
	return nil
}

func serveTemplate(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("web/templates/layout.html", "web/templates/"+name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var data struct {
			IsAuthenticated bool
			UserID          string
			Role            models.Role
		}
		if claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims); ok {
			data.IsAuthenticated = true
			data.UserID = claims.UserID
			data.Role = claims.Role
		}
		// Handle ExecuteTemplate error explicitly
		if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
			log.Println("Template execution error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}
