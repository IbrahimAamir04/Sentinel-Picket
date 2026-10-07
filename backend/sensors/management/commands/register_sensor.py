from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from sensors.models import Sensor, SensorOS


class Command(BaseCommand):
    help = "Register a real sensor and print its API key ONCE. The key cannot be shown again."

    def add_arguments(self, parser):
        parser.add_argument("--name", required=True, help="Unique sensor name, e.g. linux-edge-01")
        parser.add_argument("--os", required=True, choices=[o.value.lower() for o in SensorOS])
        parser.add_argument("--hostname", default="")

    def handle(self, *args, **opts):
        if settings.SENTINEL_DEMO_MODE:
            raise CommandError("Server is in demo mode. Real sensors must not be registered next to synthetic data; set SENTINEL_DEMO_MODE=False.")
        if Sensor.objects.filter(name=opts["name"]).exists():
            raise CommandError(f"A sensor named {opts['name']!r} already exists. Use rotate_sensor_key to issue a new key.")
        sensor = Sensor.objects.create(name=opts["name"], os=opts["os"].upper(), hostname=opts["hostname"])
        key = sensor.issue_api_key()
        self.stdout.write(self.style.SUCCESS(f"Registered sensor {sensor.name} (id {sensor.pk})."))
        self.stdout.write("")
        self.stdout.write("API key (shown once; store it now in the collector's environment or key file):")
        self.stdout.write(f"  {key}")
        self.stdout.write("")
        self.stdout.write("The server keeps only a digest. If you lose this key, run: python manage.py rotate_sensor_key --name " + sensor.name)
