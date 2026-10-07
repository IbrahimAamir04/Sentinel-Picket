from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class SentinelUserAdmin(UserAdmin):
    list_display = ("username", "email", "role", "is_active", "is_superuser", "last_login")
    list_filter = ("role", "is_active", "is_superuser")
    fieldsets = UserAdmin.fieldsets + (("Sentinel", {"fields": ("role",)}),)
    add_fieldsets = UserAdmin.add_fieldsets + (("Sentinel", {"fields": ("role",)}),)
