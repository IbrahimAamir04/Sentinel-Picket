import io

from rest_framework.exceptions import APIException
from rest_framework.parsers import JSONParser

from django.conf import settings


class PayloadTooLarge(APIException):
    status_code = 413
    default_detail = "Request body is too large."
    default_code = "payload_too_large"


class BoundedJSONParser(JSONParser):
    """Reads at most INGEST_MAX_BODY_BYTES, so an oversized or endless body can never exhaust memory (even when chunked)."""

    def parse(self, stream, media_type=None, parser_context=None):
        limit = settings.INGEST_MAX_BODY_BYTES
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise PayloadTooLarge(f"Request body exceeds {limit} bytes. Send smaller batches.")
        return super().parse(io.BytesIO(data), media_type, parser_context)
