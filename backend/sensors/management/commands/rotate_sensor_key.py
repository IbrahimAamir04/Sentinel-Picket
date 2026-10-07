from django.core.management.base import BaseCommand, CommandError

from sensors.models import Sensor


class Command(BaseCommand):
    help = "Issue a new API key for a sensor. The old key stops working immediately."

    def add_arguments(self, parser):
        parser.add_argument("--name", required=True)

    def handle(self, *args, **opts):
        try:
            sensor = Sensor.objects.get(name=opts["name"])
        except Sensor.DoesNotExist:
            raise CommandError(f"No sensor named {opts['name']!r}.")
        key = sensor.issue_api_key()
        self.stdout.write(self.style.SUCCESS(f"New key issued for {sensor.name}. The previous key no longer works."))
        self.stdout.write("")
        self.stdout.write("API key (shown once):")
        self.stdout.write(f"  {key}")
