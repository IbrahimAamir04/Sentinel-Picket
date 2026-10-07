"""
Maps Snort's priority and classification onto Sentinel's four severities.

Snort has no 'critical' level: priority 1 is its highest, 2 medium, 3 and above low. Sentinel adds CRITICAL for
priority-1 events whose classification means a compromise is likely underway (set in SENTINEL_CRITICAL_CLASSIFICATIONS).
An event with no priority at all is LOW rather than guessed upward; the raw event is kept for review.
"""
from django.conf import settings


def derive_severity(priority: int | None, classification: str) -> str:
    if priority is None:
        return "LOW"
    if priority <= 1:
        critical = {c.lower() for c in settings.SENTINEL_CRITICAL_CLASSIFICATIONS}
        return "CRITICAL" if classification.lower() in critical else "HIGH"
    if priority == 2:
        return "MEDIUM"
    return "LOW"
