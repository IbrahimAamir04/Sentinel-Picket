from rest_framework.routers import SimpleRouter

from .views import PayloadViewSet

router = SimpleRouter(trailing_slash=False)
router.register("payloads", PayloadViewSet, basename="payload")
urlpatterns = router.urls
