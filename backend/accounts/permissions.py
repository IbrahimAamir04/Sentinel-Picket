from rest_framework.permissions import BasePermission

from .models import Role


class _MinRole(BasePermission):
    minimum: str = Role.VIEWER
    message = "Your role does not allow this action."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.has_role(self.minimum))


class IsViewer(_MinRole):
    """Any signed-in, active user with a role (all three roles qualify)."""

    minimum = Role.VIEWER
    message = "Authentication credentials were not provided."


class IsAnalyst(_MinRole):
    minimum = Role.ANALYST
    message = "This action requires the analyst or admin role."


class IsAdmin(_MinRole):
    minimum = Role.ADMIN
    message = "This action requires the admin role."
