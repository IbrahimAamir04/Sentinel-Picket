from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from core.testing import PASSWORD, client_for, make_payload, make_user


class LoginTests(TestCase):
    def setUp(self):
        self.user = make_user("ANALYST", username="alice")

    def _csrf_client(self):
        c = APIClient(enforce_csrf_checks=True)
        token = c.get("/api/auth/csrf").json()["csrfToken"]
        return c, token

    def test_login_requires_csrf_token(self):
        c, _ = self._csrf_client()
        r = c.post("/api/auth/login", {"username": "alice", "password": PASSWORD}, format="json")
        self.assertEqual(r.status_code, 403)

    def test_login_success_returns_role_and_starts_session(self):
        c, token = self._csrf_client()
        r = c.post("/api/auth/login", {"username": "alice", "password": PASSWORD}, format="json", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["role"], "ANALYST")
        self.assertEqual(c.get("/api/auth/me").status_code, 200)

    def test_wrong_password_is_rejected_and_not_logged_with_username(self):
        c, token = self._csrf_client()
        with self.assertLogs("sentinel.security", level="WARNING") as logs:
            r = c.post("/api/auth/login", {"username": "alice", "password": "wrong"}, format="json", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(r.status_code, 400)
        joined = " ".join(logs.output)
        self.assertNotIn("alice", joined)
        self.assertNotIn("wrong", joined)

    def test_inactive_user_cannot_log_in(self):
        self.user.is_active = False
        self.user.save()
        c, token = self._csrf_client()
        r = c.post("/api/auth/login", {"username": "alice", "password": PASSWORD}, format="json", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(r.status_code, 400)

    def test_login_is_rate_limited(self):
        from unittest import mock

        from django.core.cache import cache
        from rest_framework.throttling import ScopedRateThrottle

        cache.clear()
        with mock.patch.dict(ScopedRateThrottle.THROTTLE_RATES, {"login": "3/min"}):
            c, token = self._csrf_client()
            codes = [
                c.post("/api/auth/login", {"username": "alice", "password": "bad"}, format="json", HTTP_X_CSRFTOKEN=token).status_code
                for _ in range(5)
            ]
        cache.clear()
        self.assertEqual(codes[:3], [400, 400, 400])
        self.assertEqual(codes[3:], [429, 429])

    def test_logout_ends_session(self):
        c, token = self._csrf_client()
        c.post("/api/auth/login", {"username": "alice", "password": PASSWORD}, format="json", HTTP_X_CSRFTOKEN=token)
        token = c.get("/api/auth/csrf").json()["csrfToken"]
        self.assertEqual(c.post("/api/auth/logout", HTTP_X_CSRFTOKEN=token).status_code, 204)
        self.assertEqual(c.get("/api/auth/me").status_code, 401)


class AuthRequiredTests(TestCase):
    def test_every_data_endpoint_requires_authentication(self):
        c = APIClient()
        for url in ["/api/alerts", "/api/alerts/1", "/api/sensors", "/api/payloads", "/api/payloads/summary",
                    "/api/payloads/trend", "/api/dashboard/stats", "/api/dashboard/timeline",
                    "/api/dashboard/protocols", "/api/dashboard/rules", "/api/dashboard/filters", "/api/auth/me"]:
            self.assertEqual(c.get(url).status_code, 401, url)

    def test_meta_is_public_and_leaks_no_telemetry(self):
        r = APIClient().get("/api/meta")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.json()), {"mode", "generated_at", "features"})


class RoleTests(TestCase):
    def setUp(self):
        self.p = make_payload()

    def test_viewer_can_read_but_not_rescan(self):
        c = client_for("VIEWER")
        self.assertEqual(c.get("/api/payloads").status_code, 200)
        self.assertEqual(c.post(f"/api/payloads/{self.p.sha256}/rescan").status_code, 403)

    def test_analyst_and_admin_reach_rescan_which_is_not_implemented_yet(self):
        for role in ("ANALYST", "ADMIN"):
            r = client_for(role).post(f"/api/payloads/{self.p.sha256}/rescan")
            self.assertEqual(r.status_code, 501, role)

    def test_superuser_counts_as_admin(self):
        from django.contrib.auth import get_user_model

        su = get_user_model().objects.create_superuser("root", password=PASSWORD)
        self.assertEqual(su.effective_role, "ADMIN")
        self.assertEqual(su.role, "ADMIN")

    def test_new_users_default_to_read_only(self):
        from django.contrib.auth import get_user_model

        self.assertEqual(get_user_model().objects.create_user("x", password=PASSWORD).role, "VIEWER")

    def test_api_has_no_write_endpoints_for_data(self):
        c = client_for("ADMIN")
        detail = {"/api/alerts": "/api/alerts/1", "/api/sensors": "/api/sensors/1", "/api/payloads": f"/api/payloads/{self.p.sha256}"}
        for url, one in detail.items():
            self.assertEqual(c.post(url, {}, format="json").status_code, 405, url)
            self.assertEqual(c.put(one, {}, format="json").status_code, 405, one)
            self.assertEqual(c.delete(one).status_code, 405, one)
