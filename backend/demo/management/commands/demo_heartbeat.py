import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from sensors.models import Sensor

LIVE = ("linux-edge-01", "linux-dmz-02")


class Command(BaseCommand):
    help = "Demo only: keep two demo sensors 'alive' by refreshing last_seen, so derived status can be seen changing."

    def add_arguments(self, parser):
        parser.add_argument("--interval", type=int, default=15)

    def handle(self, *args, **opts):
        if not settings.SENTINEL_DEMO_MODE:
            raise CommandError("Set SENTINEL_DEMO_MODE=True to use demo commands.")
        self.stdout.write(f"Heartbeat for {', '.join(LIVE)} every {opts['interval']}s. Ctrl-C to stop; they will then go WARNING, then OFFLINE.")
        try:
            while True:
                Sensor.objects.filter(name__in=LIVE).update(last_seen=timezone.now())
                time.sleep(opts["interval"])
        except KeyboardInterrupt:
            self.stdout.write("Stopped.")
