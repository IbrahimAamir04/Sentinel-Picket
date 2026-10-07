from django.urls import path

from . import views

urlpatterns = [
    path("stats", views.StatsView.as_view(), name="dashboard-stats"),
    path("timeline", views.TimelineView.as_view(), name="dashboard-timeline"),
    path("protocols", views.ProtocolsView.as_view(), name="dashboard-protocols"),
    path("rules", views.RulesView.as_view(), name="dashboard-rules"),
    path("filters", views.FilterOptionsView.as_view(), name="dashboard-filters"),
]
