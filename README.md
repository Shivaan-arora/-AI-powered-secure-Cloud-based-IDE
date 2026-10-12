# 🔒 AI-Powered Secure Cloud IDE

> **Major CSE Project** — combining Cloud Computing · Full-Stack Web Development · Cybersecurity · Machine Learning · Docker Containerization · DevOps

---

## Problem Statement

Traditional online code execution platforms (online compilers) directly execute user-submitted code on host servers, creating significant security risks including sandbox escapes, resource exhaustion, and malicious code execution. This project addresses these risks by combining **static AST analysis**, **ML-based risk classification**, and **Docker containerization** into a defence-in-depth execution pipeline.

## Research Question

> *"Can a hybrid AST-based and machine-learning security system improve detection of suspicious code before execution while maintaining acceptable execution latency?"*

---

## Features

| Feature | Status |
|---|---|
| FastAPI backend with structured JSON API | ✅ Phase 1 |
| AST-based static security scanner | ✅ Phase 1 |
| Environment-variable configuration (no hardcoded secrets) | ✅ Phase 1 |
| React + Monaco Editor IDE frontend | 🔄 Phase 3 |
| Docker containerized execution (Python) | 🔄 Phase 6 |
| PostgreSQL database | 🔄 Phase 10 |
| JWT authentication | 🔄 Phase 11 |
| Project/file management | 🔄 Phase 12 |
| ML (Random Forest) code classification | 🔄 Phase 13 |
| ML pipeline integration | 🔄 Phase 15 |
| C++ / Java sandbox support | 🔄 Phase 16 |
| Execution history & audit logs | 🔄 Phase 17 |
| Admin/security dashboard | 🔄 Phase 18 |
| Cloud deployment (AWS/Azure/GCP) | 🔄 Phase 20 |

---

## Architecture

```
User Browser
     ↓
React Frontend (Vite + Monaco Editor)
     ↓
FastAPI Backend (Python)
     ↓
┌────────────────────────────────────┐
│         Security Pipeline         │
│  AST Scanner → Feature Extraction │
│       → ML Risk Classifier        │
│       → Risk Decision             │
└────────────────┬───────────────────┘
                 ↓
     Docker Isolated Container
     ┌─────────────────────┐
     │ - Non-root user     │
     │ - No network        │
     │ - CPU/memory limit  │
     │ - Timeout enforced  │
     │ - Temp filesystem   │
     └─────────────────────┘
                 ↓
     Structured JSON Response
                 ↓
     React Frontend (Output Panel)
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Monaco Editor, Axios, Tailwind CSS |
| Backend | Python 3.12, FastAPI, Uvicorn, Pydantic v2 |
| Database | PostgreSQL 16, SQLAlchemy, Alembic |
| Authentication | JWT (python-jose), bcrypt (passlib) |
| Code Execution | Docker SDK, isolated containers per execution |
| Security | Python AST module, static analysis, rate limiting |
| Machine Learning | scikit-learn (Random Forest), pandas, NumPy, joblib |
| Monitoring | Python logging, execution statistics |
| Cloud | Designed for AWS/Azure/GCP deployment |

---

## Project Structure

```
secure-cloud-ide/
├── backend/               ← FastAPI application
│   ├── main.py            ← App entry point
│   ├── api/routes/        ← API route handlers
│   ├── security/          ← AST security scanner
│   ├── execution/         ← Docker sandbox manager
│   ├── ml/                ← ML model integration
│   ├── schemas/           ← Pydantic request/response models
│   ├── models/            ← SQLAlchemy ORM models
│   ├── auth/              ← JWT authentication
│   └── utils/             ← Config, helpers
├── frontend/              ← React + Monaco IDE
├── sandbox/
│   ├── python/            ← Python execution container
│   ├── cpp/               ← C++ execution container
│   └── java/              ← Java execution container
├── ml/
│   ├── dataset/           ← Training data
│   ├── src/               ← Feature extraction, training, prediction
│   └── models/            ← Saved model files (.joblib)
├── docker-compose.yml
└── README.md
```

---

## Installation & Setup

### Prerequisites

- Python 3.12+
- Node.js 20+ (Phase 3+)
- Docker Desktop (Phase 6+)
- PostgreSQL 16 (Phase 10+, or via Docker Compose)

### 1. Clone & Environment Setup

```bash
git clone <your-repo-url>
cd secure-cloud-ide

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate      # macOS/Linux
# venv\Scripts\activate       # Windows

# Install dependencies
pip install -r backend/requirements.txt
```

### 2. Configure Environment

```bash
# Copy the example env file
cp backend/.env.example backend/.env

# Edit backend/.env — fill in your values:
# - JWT_SECRET: generate with:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
# - DATABASE_URL: update if your PostgreSQL is on a different host/port
```

### 3. Run the Backend

```bash
cd secure-cloud-ide
python3 -m uvicorn backend.main:app --reload --port 8000
```

The backend will start at: **http://localhost:8000**

Interactive API docs: **http://localhost:8000/docs**

---

## Testing Phase 1

```bash
# Health check
curl http://localhost:8000/health

# Root endpoint
curl http://localhost:8000/

# Execute benign code (scan passes, Docker pending Phase 6)
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d '{"language": "python", "code": "print(\"Hello World\")"}'

# Security scan — should return LOW risk
curl -X POST http://localhost:8000/security/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "print(\"Hello World\")", "language": "python"}'

# Security scan — should return HIGH/CRITICAL risk
curl -X POST http://localhost:8000/security/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\nos.system(\"ls\")\neval(\"1+1\")", "language": "python"}'
```

### Running Unit Tests

```bash
cd secure-cloud-ide
python3 -m pytest backend/tests/ -v
```

---

## Docker Compose (PostgreSQL only — Phase 1)

```bash
cd secure-cloud-ide
docker-compose up postgres -d    # Start only the database
```

---

## ML Pipeline (Phase 13)

```bash
cd secure-cloud-ide

# Train the model on the demo dataset
python3 -m ml.src.train

# The model is saved to ml/models/classifier.joblib
# NOTE: Demo dataset is synthetic — replace for real research
```

---

## Security Architecture

### Defence-in-Depth Layers

```
Layer 1: Input Validation (Pydantic)
Layer 2: Code Size Limits
Layer 3: Rate Limiting per User
Layer 4: AST Static Analysis (Python ast module)
Layer 5: ML Risk Classification (Random Forest)
Layer 6: Docker Container Isolation
  ├── Non-root execution (uid 1000)
  ├── Network disabled (--network none)
  ├── CPU quota (50% of 1 core)
  ├── Memory limit (128 MB default)
  ├── PID limit (50 processes)
  ├── Execution timeout (10 seconds)
  └── Temporary filesystem (destroyed after run)
Layer 7: Audit Logging
```

### What is NEVER done

- ❌ Execute user code directly in FastAPI process
- ❌ Use `eval()` / `exec()` / `os.system()` on host
- ❌ Run containers with `--privileged`
- ❌ Mount host filesystem into execution containers
- ❌ Expose Docker socket to user code
- ❌ Store plaintext passwords
- ❌ Hardcode secrets in source code

---

## API Documentation

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | API info |
| GET | `/health` | Health check |
| POST | `/execute` | Execute code in sandbox |
| POST | `/security/scan` | Static security scan |
| POST | `/auth/register` | Register (Phase 11) |
| POST | `/auth/login` | Login (Phase 11) |
| GET | `/projects` | List projects (Phase 12) |
| POST | `/projects` | Create project (Phase 12) |

Full interactive docs available at `/docs` when server is running.

---

## Role of Each Technology

| Technology | Role in Project |
|---|---|
| **Cloud Computing** | Architecture designed for AWS/GCP/Azure deployment; stateless backend; containerised services |
| **Machine Learning** | Random Forest classifier predicts code risk; trained on AST features |
| **Cybersecurity** | Multi-layer defence: AST scanner, ML classifier, Docker isolation, JWT auth, rate limiting |
| **Docker** | Isolated per-execution sandboxes; non-root; resource-limited; network-disabled |
| **FastAPI** | High-performance async Python backend; automatic OpenAPI docs |
| **React + Monaco** | Professional browser-based IDE interface (VS Code editor component) |
| **PostgreSQL** | Persistent storage for users, projects, files, execution history |
| **Pydantic** | Type-safe request/response validation; prevents injection via strict schema enforcement |

---

## Development Phases

| Phase | Description | Status |
|---|---|---|
| 1 | Project structure + FastAPI backend | ✅ Complete |
| 2 | React frontend scaffold | 🔄 Next |
| 3 | Monaco Editor integration | 🔄 |
| 4 | Frontend/backend communication | 🔄 |
| 5 | Docker sandbox foundation | 🔄 |
| 6 | Secure Python execution | 🔄 |
| 7 | Resource restrictions | 🔄 |
| 8 | Static security scanner (full) | 🔄 |
| 9 | Database integration | 🔄 |
| 10 | JWT Authentication | 🔄 |
| 11 | Project/file management | 🔄 |
| 12 | ML dataset + feature extraction | 🔄 |
| 13 | ML model training | 🔄 |
| 14 | ML pipeline integration | 🔄 |
| 15 | Multi-language support | 🔄 |
| 16 | Execution history + audit logs | 🔄 |
| 17 | Security dashboard | 🔄 |
| 18 | Testing suite | 🔄 |
| 19 | Cloud deployment | 🔄 |

---

## Screenshots

> *(Screenshots will be added as phases progress)*

---

## Future Scope

- Real-time collaborative editing (WebSocket)
- Support for additional languages (Go, Rust, Node.js)
- CI/CD pipeline integration
- Kubernetes orchestration for production scaling
- Advanced ML model (LSTM on code sequences)
- Differential privacy for execution logs
- SIEM integration for security events

---

## Academic Use

This project is designed to support:
- B.Tech / M.Tech Major Project
- Research paper on hybrid code security analysis
- Cybersecurity and cloud computing demonstrations

**Research metrics to collect:**
- Detection accuracy, precision, recall, F1, false positive/negative rates
- Scanning latency (ms)
- Execution latency (ms)
- Container startup overhead (ms)
