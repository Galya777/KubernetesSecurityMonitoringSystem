package main

import (
	"log"
	"net/http"
	"text/template"

	"KubernetesSecurityMonitoringSystem/internal/handlers"
	"KubernetesSecurityMonitoringSystem/internal/kubernetes"
	"KubernetesSecurityMonitoringSystem/internal/middleware"
	"KubernetesSecurityMonitoringSystem/internal/storage"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	var store storage.Storage
	var err error

	store, err = storage.NewDatabaseStorage()
	if err != nil {
		log.Printf("Failed to connect to database: %v. Falling back to memory storage.", err)
		store = storage.NewMemoryStorage()
	}

	k8sMgr := kubernetes.NewClusterManager()

	// Handlers
	authH := &handlers.AuthHandler{Storage: store}
	userH := &handlers.UserHandler{Storage: store}
	resH := &handlers.ResourceHandler{Storage: store, K8s: k8sMgr}

	r := mux.NewRouter()

	// API Routes
	api := r.PathPrefix("/api").Subrouter()
	api.Use(middleware.AuthMiddleware)

	api.HandleFunc("/login", authH.Login).Methods("POST")
	api.HandleFunc("/logout", authH.Logout).Methods("POST")
	api.HandleFunc("/register", authH.Register).Methods("POST")

	// Users API
	adminOnly := api.PathPrefix("/users").Subrouter()
	adminOnly.Use(middleware.RequireRole("Administrator"))
	adminOnly.HandleFunc("", userH.GetAllUsers).Methods("GET")

	api.HandleFunc("/users/{userId}", userH.GetUser).Methods("GET")
	api.HandleFunc("/users/{userId}", userH.UpdateUser).Methods("PUT")
	api.HandleFunc("/users/{userId}", userH.DeleteUser).Methods("DELETE")

	// Clusters API
	api.HandleFunc("/clusters", resH.GetClusters).Methods("GET")
	api.HandleFunc("/clusters", resH.CreateCluster).Methods("POST")
	api.HandleFunc("/clusters/{clusterId}", resH.DeleteCluster).Methods("DELETE")

	// Policies API
	api.HandleFunc("/policies", resH.GetPolicies).Methods("GET")
	api.HandleFunc("/policies", resH.CreatePolicy).Methods("POST")

	// Alerts and Reports API
	api.HandleFunc("/tests", resH.GetAlerts).Methods("GET")           // As per 4.7 URI
	api.HandleFunc("/tests/{testId}", resH.GetReports).Methods("GET") // As per 4.8 URI (mapping to reports)

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

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func serveTemplate(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("web/templates/layout.html", "web/templates/"+name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.ExecuteTemplate(w, "layout", nil)
	}
}
