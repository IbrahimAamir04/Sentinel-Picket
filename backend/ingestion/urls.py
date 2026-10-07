from django.urls import path

from .views import HeartbeatView, IngestEventsView

urlpatterns = [
    path("events", IngestEventsView.as_view(), name="ingest-events"),
    path("heartbeat", HeartbeatView.as_view(), name="ingest-heartbeat"),
]
