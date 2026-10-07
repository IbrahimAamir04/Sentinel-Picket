"""
Sentinel settings. Everything environment-specific comes from environment variables
(see ../.env.example). Secrets are never hardcoded and never logged.
"""
import os
import sys
from datetime import timedelta
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR.parent / ".env")  # project-root .env (never committed)
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


DEBUG = env_bool("DEBUG", False)

SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    if not DEBUG:
        raise RuntimeError("SECRET_KEY must be set when DEBUG is off.")
    SECRET_KEY = "insecure-development-key-do-not-use-in-production"  # DEBUG only

ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "django_filters",
    "accounts",
    "sensors",
    "alerts",
    "payloads",
    "ingestion",
    "dashboard",
    "core",
    "integrations.virustotal",
    "demo",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

# --- Database -------------------------------------------------------------------------------
# PostgreSQL is the supported database. SQLite is only a convenience fallback for quick local runs.
DATABASES = {
    "default": dj_database_url.config(
        env="DATABASE_URL", default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}", conn_max_age=60
    )
}

# --- Auth -----------------------------------------------------------------------------------
AUTH_USER_MODEL = "accounts.User"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

SESSION_COOKIE_AGE = int(timedelta(hours=8).total_seconds())
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_HTTPONLY = False  # the SPA must read it to send X-CSRFToken
SECURE_COOKIES = env_bool("SECURE_COOKIES", not DEBUG)
SESSION_COOKIE_SECURE = SECURE_COOKIES
CSRF_COOKIE_SECURE = SECURE_COOKIES
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", "0" if DEBUG else "31536000"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = SECURE_HSTS_SECONDS > 0
SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", False)
if env_bool("BEHIND_TLS_PROXY", False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# --- CORS / CSRF ----------------------------------------------------------------------------
# The SPA is normally served same-origin (Vite proxy in development, reverse proxy in production),
# so no CORS origins are allowed by default. Add origins explicitly if the SPA lives elsewhere.
CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS")
CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS", "http://localhost:5173")

# --- REST framework -------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["accounts.authentication.Session401Authentication"],
    "DEFAULT_PERMISSION_CLASSES": ["accounts.permissions.IsViewer"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_PAGINATION_CLASS": "core.pagination.StandardPagination",
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": os.environ.get("THROTTLE_ANON", "60/min"),
        "user": os.environ.get("THROTTLE_USER", "600/min"),
        "login": os.environ.get("THROTTLE_LOGIN", "10/min"),
        "rescan": os.environ.get("THROTTLE_RESCAN", "20/min"),
        "ingest": os.environ.get("THROTTLE_INGEST", "120/min"),  # per sensor
        "heartbeat": os.environ.get("THROTTLE_HEARTBEAT", "20/min"),  # per sensor
    },
    "UNAUTHENTICATED_USER": None,
}

# --- Sentinel -------------------------------------------------------------------------------
# A sensor is WARNING after this many seconds without a heartbeat, OFFLINE after the second value.
# The frontend mirrors these numbers in its demo data source.
SENSOR_WARNING_AFTER_SECONDS = int(os.environ.get("SENSOR_WARNING_AFTER_SECONDS", "120"))
SENSOR_OFFLINE_AFTER_SECONDS = int(os.environ.get("SENSOR_OFFLINE_AFTER_SECONDS", "600"))

# --- Ingestion limits (sensor -> server) ---------------------------------------------------
INGEST_MAX_BODY_BYTES = int(os.environ.get("INGEST_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
INGEST_MAX_EVENTS_PER_REQUEST = int(os.environ.get("INGEST_MAX_EVENTS_PER_REQUEST", "500"))
INGEST_MAX_EVENT_AGE_DAYS = int(os.environ.get("INGEST_MAX_EVENT_AGE_DAYS", "30"))
INGEST_MAX_FUTURE_SKEW_SECONDS = int(os.environ.get("INGEST_MAX_FUTURE_SKEW_SECONDS", "300"))
INGEST_MAX_RAW_BYTES = int(os.environ.get("INGEST_MAX_RAW_BYTES", "16384"))
INGEST_AUTH_FAIL_LIMIT = int(os.environ.get("INGEST_AUTH_FAIL_LIMIT", "20"))  # bad keys per minute per client address
# Priority-1 events with these classifications become CRITICAL; other priority-1 events are HIGH.
SENTINEL_CRITICAL_CLASSIFICATIONS = env_list(
    "SENTINEL_CRITICAL_CLASSIFICATIONS", "trojan-activity,successful-admin,successful-user,shellcode-detect"
)

# Demo data may only be loaded, and is only labelled as such, when this is on.
SENTINEL_DEMO_MODE = env_bool("SENTINEL_DEMO_MODE", False)

# Capabilities advertised to the UI so it never shows an action the server cannot perform.
# VirusTotal and realtime are switched on in later phases.
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")  # backend only; never sent to the browser
REDIS_URL = os.environ.get("REDIS_URL", "")
FEATURES = {"virustotal": False, "realtime": False}

# --- i18n / static --------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Fast hashing keeps the test suite quick. Never applied outside `manage.py test`.
if len(sys.argv) > 1 and sys.argv[1] == "test":
    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# --- Logging --------------------------------------------------------------------------------
# Request bodies, passwords, API keys and session data are never logged. The security logger
# records events (e.g. a failed login) without the submitted credentials.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": os.environ.get("LOG_LEVEL", "INFO")},
    "loggers": {"sentinel.security": {"handlers": ["console"], "level": "INFO", "propagate": False}},
}
