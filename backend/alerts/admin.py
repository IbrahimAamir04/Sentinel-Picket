from django.contrib import admin

from .models import Alert


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "severity", "signature", "source_ip", "destination_ip", "sensor", "payload_available")
    list_filter = ("severity", "protocol", "sensor")
    search_fields = ("signature", "source_ip", "destination_ip", "payload_hash")
    exclude = ("raw_event",)  # untrusted blob; not rendered in the admin
