from django.contrib import admin, messages

from .models import Sensor


@admin.register(Sensor)
class SensorAdmin(admin.ModelAdmin):
    list_display = ("name", "os", "ip", "snort_version", "is_active", "last_seen", "current_status", "key_prefix")
    list_filter = ("os", "is_active")
    search_fields = ("name", "hostname")
    readonly_fields = ("api_key_prefix", "api_key_created_at", "last_seen", "collector_version")
    actions = ["rotate_keys"]

    @admin.display(description="Status")
    def current_status(self, obj):
        return obj.status

    @admin.display(description="Key")
    def key_prefix(self, obj):
        return f"{obj.api_key_prefix}…" if obj.has_api_key else "none"

    @admin.action(description="Issue a new API key (shown once; the old key stops working)")
    def rotate_keys(self, request, queryset):
        for sensor in queryset:
            key = sensor.issue_api_key()
            # Shown once in this response only. Never logged.
            self.message_user(request, f"{sensor.name}: new API key {key}", level=messages.WARNING)
