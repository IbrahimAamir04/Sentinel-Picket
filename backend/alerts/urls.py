from rest_framework.routers import SimpleRouter

from .views import AlertViewSet

router = SimpleRouter(trailing_slash=False)
router.register("alerts", AlertViewSet, basename="alert")
urlpatterns = router.urls
