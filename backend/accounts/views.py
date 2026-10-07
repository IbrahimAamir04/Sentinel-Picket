import logging

from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from .permissions import IsViewer
from .serializers import LoginSerializer, UserSerializer

security_log = logging.getLogger("sentinel.security")


def client_ip(request) -> str:
    return request.META.get("REMOTE_ADDR", "unknown")


@method_decorator(ensure_csrf_cookie, name="dispatch")
class CsrfView(APIView):
    """Sets the csrftoken cookie. The SPA calls this once before logging in."""

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def get(self, request):
        return Response({"csrfToken": get_token(request)})


@method_decorator(csrf_protect, name="dispatch")
class LoginView(APIView):
    """Session login. CSRF is enforced here explicitly because DRF only checks it for authenticated requests."""

    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"

    def post(self, request):
        ser = LoginSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = authenticate(request, username=ser.validated_data["username"], password=ser.validated_data["password"])
        if user is None or not user.is_active:
            # Deliberately omits the submitted username: people sometimes type a password into that box.
            security_log.warning("Failed login attempt from %s", client_ip(request))
            return Response({"detail": "Incorrect username or password."}, status=status.HTTP_400_BAD_REQUEST)
        login(request, user)  # rotates the session key
        security_log.info("Login succeeded for user id=%s from %s", user.pk, client_ip(request))
        return Response(UserSerializer(user).data)


class LogoutView(APIView):
    permission_classes = [IsViewer]

    def post(self, request):
        security_log.info("Logout for user id=%s", request.user.pk)
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    permission_classes = [IsViewer]

    def get(self, request):
        return Response(UserSerializer(request.user).data)
