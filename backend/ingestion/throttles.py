from rest_framework.throttling import SimpleRateThrottle


class _PerSensor(SimpleRateThrottle):
    def get_cache_key(self, request, view):
        return self.cache_format % {"scope": self.scope, "ident": request.user.pk}


class IngestThrottle(_PerSensor):
    scope = "ingest"


class HeartbeatThrottle(_PerSensor):
    scope = "heartbeat"
