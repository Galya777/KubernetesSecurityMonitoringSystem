# Kubernetes Security Monitoring System (KSMS)

![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=for-the-badge&logo=kubernetes&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=Prometheus&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)

KSMS is a real-time security monitoring system for Kubernetes clusters. It provides administrators and security analysts with the tools to define security policies, detect violations, and automate responses to threats.

## 🚀 Features

- **Real-time Monitoring**: Live pod/event/log monitoring using Kubernetes watches and SSE streaming.
- **Policy Engine**: Static pod-spec rules (privileged, host namespaces, read-only rootfs, …) plus `log_pattern:<regex>` runtime rules that tail container logs.
- **Incident Response**: One-click pod isolation (NetworkPolicy-based), release and deletion from the alerts UI.
- **Cluster Management**: Connect and monitor multiple Kubernetes clusters via kubeconfig.
- **RBAC**: Role-based access for Administrators, Security Analysts, Instructors and Students.
- **Audit Log Monitoring**: Optional tailing of the Kubernetes API audit log to detect exec/attach/portforward activity.
- **Metrics**: Prometheus `/metrics` endpoint plus docker-compose Prometheus integration.
- **Persistence**: PostgreSQL storage with automatic schema creation and migrations; file/memory fallback for local runs.
- **Web Dashboard**: Server-rendered UI (Go templates + Vue.js + Bootstrap).

## 🛠️ Tech Stack

- **Backend**: Go (Golang), gorilla/mux
- **Database**: PostgreSQL (persistent), JSON file / in-memory fallback
- **Kubernetes Integration**: client-go (watches, logs, NetworkPolicy isolation)
- **Metrics**: Prometheus client + server
- **Frontend**: Go `html/template`, Vue.js, Bootstrap
- **Authentication**: JWT (JSON Web Tokens, HttpOnly cookie + Bearer)

## 🏗️ Architecture

```
cmd/ksms        application entrypoint (HTTP server, routes, graceful shutdown)
cmd/demo        demo script exercising the API
internal/
  auth          JWT issuing/verification
  handlers      REST API + SSE handlers
  kubernetes    client-go wrapper: clients, metrics, watches, isolation
  middleware    auth, RBAC, security headers, login rate limiting
  models        domain types
  monitor       cluster/pod/log/audit watchers -> alerts
  storage       Storage interface + Postgres / file / memory implementations
web/templates   server-rendered pages
```

## 📋 Prerequisites

- Go 1.21+
- PostgreSQL (optional — the app falls back to file/memory storage)
- Kubernetes cluster (or Minikube/Kind) for real monitoring

## ⚙️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/KubernetesSecurityMonitoringSystem.git
   cd KubernetesSecurityMonitoringSystem
   ```

2. **Install dependencies**:
   ```bash
   go mod download
   ```

3. **Configure** (optional but recommended):
   ```bash
   cp .env.example .env
   # set JWT_SECRET at minimum
   ```

4. **Run the application**:
   ```bash
   go run ./cmd/ksms
   ```
   or with Docker:
   ```bash
   docker compose up --build
   ```

## 🔧 Configuration

See `.env.example` for the full list. Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` / `APP_PORT` | HTTP listen port | `8081` |
| `JWT_SECRET` | JWT signing secret (random per-process if unset) | — |
| `COOKIE_SECURE` | Set `true` behind HTTPS | `false` |
| `DB_HOST`/`DB_PORT`/`DB_USER`/`DB_PASSWORD`/`DB_NAME` | PostgreSQL connection | `localhost:5433` |
| `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` | Seeded admin account | `admin@ksms.io` / `admin123` |
| `KSMS_AUDIT_LOG` | Path to kube-apiserver audit log for exec/attach detection | — |
| `KSMS_AUDIT_CLUSTER` | Cluster ID audit alerts are attributed to | first cluster |

## 🧪 API Documentation

All `/api/*` endpoints except `login`, `register` and `logout` require a valid JWT (cookie or `Authorization: Bearer`).

- `POST /api/login` · `POST /api/register` · `POST /api/logout` — auth (login is rate-limited)
- `GET /healthz` — liveness probe
- `GET/POST /api/clusters`, `DELETE /api/clusters/{id}` — cluster management (manager roles)
- `GET /api/clusters/{id}/discover/containers` — list real pods/containers
- `GET /api/clusters/{id}/containers/logs[/stream]` — container logs
- `GET/POST /api/policies`, `DELETE /api/policies/{id}` — policy management
- `GET /api/tests` (SSE), `GET /api/alerts` — real-time alerts
- `GET/POST /api/reports` — incident reports
- `POST /api/actions/{isolate|release|delete|evaluate}` — incident response
- `GET /api/users`, `GET/PUT/DELETE /api/users/{id}`, `POST /api/users/{id}/password` — user management
- `GET /metrics` — Prometheus metrics

## 🗄️ Database Schema

Tables: `users`, `clusters`, `policies`, `alerts`, `reports`, `containers`, `user_containers`.
Created automatically on startup; schema migrations (e.g. new alert columns) are applied idempotently.

## 🧪 Testing & Demo

```bash
# unit tests
go test ./...

# automated API demo (server must be running)
go run ./cmd/demo
```

Manual UI testing: open `http://localhost:8081`, log in with the seeded admin, add a cluster by pasting its kubeconfig, define a policy with rules, and watch alerts arrive in real time.

## 👤 Author

**Galya Dodova** — FN: 45616

## 📄 License

MIT — see [LICENSE](LICENSE).
