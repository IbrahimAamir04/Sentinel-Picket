# Sentinel-Picket

Status: Work in progress (WIP)

Sentinel-Picket is a modern security operations dashboard built to help teams detect, investigate, and monitor network threats in one place. It combines Snort alert ingestion, payload intelligence, and sensor health visibility into a unified interface, making it easier to track incidents, understand suspicious traffic patterns, and maintain operational awareness across distributed environments.

## Current implementation status

This project is a WIP and currently includes the work from Phase 1 through Phase 3:

- Phase 1: Frontend shell, demo data, and initial dashboard/alert/payload UI pages
- Phase 2: Django backend, PostgreSQL integration, REST API, authentication, and role-based access
- Phase 3: Snort ingestion pipeline, collector tooling, sensor management, and telemetry processing

### Roadmap

Implemented:
- Phase 1: Frontend, demo mode, and core pages
- Phase 2: Django API, auth, and persistence
- Phase 3: Snort ingestion, collectors, and sensor monitoring

Remaining:
- Phase 4: SHA-256 handling, VirusTotal integration, and Celery/Redis processing
- Phase 5: Realtime monitoring and WebSocket updates
- Phase 6: Docker, CI/CD, production hardening, and test coverage

## Why this project exists

Security telemetry is often spread across scattered tools and logs. Sentinel brings the most important pieces together in one UI:

- Snort alert triage
- Payload investigation and enrichment
- Sensor uptime and health tracking
- Role-aware access for analysts and administrators
- Demo-ready data for local testing and onboarding

## Features

- Dashboard overview for alert totals, severity summaries, detection trends, and sensor health
- Alert review pages with search, filtering, and sorting
- Payload analysis views with metadata, trend inspection, and detail drawers
- Secure role-based access using Django authentication and permission checks
- Backend ingestion pipeline for Snort `alert_fast` and `alert_json` data
- Demo mode for local development without requiring a live backend setup
- Mobile-friendly layout with responsive navigation and drawers

## Tech stack

### Frontend
- React
- TypeScript
- Vite
- Tailwind CSS
- React Router
- Redux Toolkit
- Lucide React icons

### Backend
- Python
- Django
- Django REST Framework
- PostgreSQL
- Environment-based configuration with `.env` files

### Security / telemetry pipeline
- Snort alert ingestion
- Python collector tooling
- Payload processing and metadata collection
- Sensor health monitoring

## Architecture

```text
backend/       Django + DRF API and business logic
collector/     Python-based Snort collectors and ingest workers
frontend/      React + TypeScript dashboard and UI
docs/          Product and ingestion documentation
```

## Getting started

### Option 1: Demo-only frontend

```bash
cd frontend
npm install
VITE_DATA_MODE=demo npm run dev
```

This starts the app in demo mode with synthetic data, without needing the Django backend.

### Option 2: Full stack local setup

#### 1. PostgreSQL

```bash
createdb sentinel
```

#### 2. Backend

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example ../.env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

#### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend serves on `http://localhost:5173` and proxies API requests to the Django backend.

## Configuration

Create a `.env` file in the project root based on `.env.example` and configure values such as:

- Django secret key
- Database connection settings
- Demo mode toggles
- Security-related environment values

## Running tests

```bash
cd backend
python manage.py test

cd collector
python -m unittest discover -s tests -t .

cd frontend
npm run build
```

## Contributing

Contributions are welcome. If you want to help improve the project:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the relevant tests/checks
5. Open a pull request with a clear description

## Security note

This project is intended for internal security monitoring workflows. Do not commit secrets, database credentials, `.env` files, or production telemetry data.

## License

This project is licensed under the [MIT License](LICENSE).
