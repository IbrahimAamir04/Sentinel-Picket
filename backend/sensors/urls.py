from rest_framework.routers import SimpleRouter

from .views import SensorViewSet

router = SimpleRouter(trailing_slash=False)
router.register("sensors", SensorViewSet, basename="sensor")
urlpatterns = router.urls
