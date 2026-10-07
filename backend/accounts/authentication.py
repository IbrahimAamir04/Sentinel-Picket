from rest_framework.authentication import SessionAuthentication


class Session401Authentication(SessionAuthentication):
    """Session auth that answers 401 (not 403) when nobody is signed in, so the SPA can tell 'sign in' from 'not allowed'."""

    def authenticate_header(self, request):
        return "Session"
