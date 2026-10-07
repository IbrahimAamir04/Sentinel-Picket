from django.contrib import admin

from .models import Payload


@admin.register(Payload)
class PayloadAdmin(admin.ModelAdmin):
    list_display = ("sha256", "status", "size", "mime_type", "sensor", "first_seen")
    list_filter = ("status", "sensor")
    search_fields = ("sha256", "filename")
