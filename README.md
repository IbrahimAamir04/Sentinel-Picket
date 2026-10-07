# Sentinel

A security operations dashboard for monitoring Snort alerts, payload intelligence, and sensor health in real time.

Sentinel gives teams a centralized place to review traffic-generated security events, inspect suspicious payloads, and track the operational health of distributed sensors.

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

## Project status

This project is under active development and is structured around a phased roadmap:

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Frontend, demo data, core UI pages | Done |
| 2 | Django, API, auth, database integration | Done |
| 3 | Snort ingestion, collectors, sensors | In progress |
| 4 | SHA-256, VirusTotal, Celery/Redis | Planned |
| 5 | Realtime streaming / WebSockets | Planned |
| 6 | Docker, CI, additional hardening | Planned |

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
