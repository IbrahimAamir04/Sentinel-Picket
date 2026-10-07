from django.conf import settings
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class MetaView(APIView):
    """
    Public, non-sensitive. Tells the UI whether it is showing demo data and which actions the server
    can perform, so the UI never presents an unavailable action as working.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def get(self, request):
        return Response(
            {
                "mode": "demo" if settings.SENTINEL_DEMO_MODE else "live",
                "generated_at": timezone.now().isoformat(),
                "features": settings.FEATURES,
            }
        )
