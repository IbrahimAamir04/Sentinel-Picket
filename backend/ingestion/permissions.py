from rest_framework.permissions import BasePermission

from .authentication import SensorPrincipal


class IsSensor(BasePermission):
    message = "Sensor credentials are required."

    def has_permission(self, request, view):
        return isinstance(request.user, SensorPrincipal)
