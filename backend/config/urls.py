from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("core.urls")),
    path("api/auth/", include("accounts.urls")),
    path("api/ingest/", include("ingestion.urls")),
    path("api/dashboard/", include("dashboard.urls")),
    path("api/", include("sensors.urls")),
    path("api/", include("alerts.urls")),
    path("api/", include("payloads.urls")),
]
