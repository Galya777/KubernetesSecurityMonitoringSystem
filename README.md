# Kubernetes Security Monitoring System (KSMS)

![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=for-the-badge&logo=kubernetes&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=Prometheus&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)

KSMS is a real-time security monitoring system for Kubernetes clusters. It provides administrators and security analysts with the tools to define security policies, detect violations, and automate responses to threats.

## 🚀 Features

- **Real-time Monitoring**: Live updates on security incidents using SSE/WebSockets.
- **Cluster Management**: Connect and monitor multiple Kubernetes clusters.
- **Policy Enforcement**: Define and apply security policies across namespaces.
- **Incident Response**: Automated actions (e.g., pod isolation) triggered by policy violations.
- **Role-Based Access Control (RBAC)**: Secure access for Administrators, Security Analysts, and Students.
- **Metrics Collection**: Integration with Prometheus for cluster health and security trends.
- **Web Dashboard**: Clean and intuitive interface built with Go templates and Vue.js.

## 🛠️ Tech Stack

- **Backend**: Go (Golang)
- **Database**: PostgreSQL (for persistent storage)
- **Kubernetes Integration**: client-go
- **Metrics**: Prometheus
- **Frontend**: Go `html/template`, Vue.js, Tailwind CSS
- **Authentication**: JWT (JSON Web Tokens)

## 🏗️ Architecture

The system consists of a Go backend that communicates with Kubernetes API servers to monitor cluster state. Security policies are stored in a PostgreSQL database and evaluated against incoming events. Alerts are pushed to the frontend in real-time.

## 📋 Prerequisites

- Go 1.21+
- PostgreSQL
- Kubernetes cluster (or Minikube/Kind)
- `kubectl` configured to access your cluster

## ⚙️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/KubernetesSecurityMonitoringSystem.git
   cd KubernetesSecurityMonitoringSystem
   ```

2. **Install Dependencies**:
   ```bash
   go mod download
   ```

3. **Run the Application**:
   ```bash
   go run main.go
   ```

## 🔧 Configuration

The application can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_USER` | PostgreSQL user | `postgres` |
| `DB_PASSWORD` | PostgreSQL password | `password` |
| `DB_NAME` | PostgreSQL database name | `ksms` |
| `APP_PORT` | Application port | `8081` |
| `JWT_SECRET` | Secret key for JWT signing | `your-secret-key` |

## 🧪 API Documentation

The system provides a RESTful API for integration:

- `POST /api/login` - Authenticate and receive a JWT.
- `GET /api/clusters` - List managed clusters.
- `POST /api/policies` - Create a new security policy.
- `GET /api/users` - Manage system users (Admin only).

## 🗄️ Database Schema

The system uses the following tables in PostgreSQL:

- `users`: Stores user profiles, hashed passwords, and roles.
- `clusters`: Managed Kubernetes cluster configurations and connection status.
- `policies`: Security policies defined for clusters.
- `alerts`: Security incidents detected in real-time.
- `reports`: Detailed investigation reports for incidents.

Database tables are automatically created on first run if they don't exist.

## 👤 Author

**Galya Dodova**
- FN: 45616

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
