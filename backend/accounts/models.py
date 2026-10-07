from django.contrib.auth.models import AbstractUser, UserManager as DjangoUserManager
from django.db import models


class Role(models.TextChoices):
    ADMIN = "ADMIN", "Admin"
    ANALYST = "ANALYST", "Analyst"
    VIEWER = "VIEWER", "Viewer"


ROLE_RANK = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}


class UserManager(DjangoUserManager):
    def create_superuser(self, username, email=None, password=None, **extra):
        extra.setdefault("role", Role.ADMIN)
        return super().create_superuser(username, email, password, **extra)


class User(AbstractUser):
    """Custom user from day one so roles never need a risky migration later. New users default to read-only."""

    role = models.CharField(max_length=10, choices=Role.choices, default=Role.VIEWER)

    objects = UserManager()

    @property
    def effective_role(self) -> str:
        return Role.ADMIN if self.is_superuser else self.role

    def has_role(self, minimum: str) -> bool:
        return self.is_active and ROLE_RANK[Role(self.effective_role)] >= ROLE_RANK[Role(minimum)]
