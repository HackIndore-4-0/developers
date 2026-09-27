# SignalThread Backend API

Enterprise Attack Surface & Security Intelligence API built with FastAPI, PostgreSQL (asyncpg), Neo4j Graph DB, and Redis.

## Architecture

- **FastAPI**: Async REST & WebSocket API endpoints.
- **PostgreSQL**: Primary transactional store for assets, subdomains, vulnerabilities, exposures, alerts, incidents, and audit logs.
- **Neo4j**: Graph database for attack path traversal and relationship mapping.
- **Redis**: Caching and background event message broker.
- **Alembic**: Database migrations and schema versioning.

## Prerequisites

- Python 3.10+
- Docker & Docker Compose (for PostgreSQL, Neo4j, Redis)

## Setup & Running

1. **Start Infrastructure Services:**
   ```bash
   docker compose up -d
   ```

2. **Create & Activate Virtual Environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Linux/macOS
   pip install -r requirements.txt
   ```

3. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Update variables in .env if necessary
   ```

4. **Run Database Migrations:**
   ```bash
   alembic upgrade head
   ```

5. **Start the API Server:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

6. **API Documentation:**
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`

## Seed Data & Verification

- Seed initial data: `python scripts/seed_phase1.py`
- Verify phase 1: `python scripts/verify_phase1.py`
- Verify phase 2: `python scripts/verify_phase2.py`
- Verify phase 3: `python scripts/verify_phase3.py`
- Run platform tests: `python test_platform.py`
