from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from alerts.models import Alert
from payloads.models import Payload
from sensors.models import Sensor

from demo.generator import generate


class Command(BaseCommand):
    help = "Load clearly labelled SYNTHETIC alerts, payloads and sensors. Requires SENTINEL_DEMO_MODE=True."

    def add_arguments(self, parser):
        parser.add_argument("--reset", action="store_true", help="Delete ALL alerts, payloads and sensors first.")
        parser.add_argument("--users-password", help="Also create demo_admin / demo_analyst / demo_viewer with this password. DEBUG only.")

    def handle(self, *args, **opts):
        if not settings.SENTINEL_DEMO_MODE:
            raise CommandError("Refusing to load demo data: set SENTINEL_DEMO_MODE=True first. Mock data must never mix with real telemetry.")
        if Sensor.objects.exclude(api_key_hash="").exists():
            raise CommandError("Refusing to continue: registered (real) sensors exist. Demo data is never loaded next to, or over, real telemetry.")
        if Sensor.objects.exists() or Alert.objects.exists() or Payload.objects.exists():
            if not opts["reset"]:
                raise CommandError("Data already exists. Re-run with --reset to replace everything with demo data.")
            Alert.objects.all().delete()
            Payload.objects.all().delete()
            Sensor.objects.all().delete()
        result = generate()
        self.stdout.write(self.style.SUCCESS(f"Loaded synthetic data: {result}"))

        if opts["users_password"]:
            if not settings.DEBUG:
                raise CommandError("Demo users are only created when DEBUG=True.")
            User = get_user_model()
            for name, role in (("demo_admin", "ADMIN"), ("demo_analyst", "ANALYST"), ("demo_viewer", "VIEWER")):
                user, _ = User.objects.get_or_create(username=name, defaults={"role": role})
                user.role = role
                user.set_password(opts["users_password"])
                user.save()
            self.stdout.write(self.style.SUCCESS("Created demo_admin, demo_analyst, demo_viewer."))
