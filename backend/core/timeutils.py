from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from rest_framework.exceptions import ValidationError


def parse_tz(request) -> ZoneInfo:
    """Optional ?tz=Area/City so day buckets match the viewer's calendar. Defaults to UTC."""
    name = request.query_params.get("tz", "UTC")
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ValidationError({"tz": "Unknown time zone."})
