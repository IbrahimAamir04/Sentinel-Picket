# Sentinel REST API (Phases 2 and 3)

Base path `/api`. JSON only. Authentication is a Django **session cookie**; every non-GET request needs the
`X-CSRFToken` header (value of the `csrftoken` cookie). No token or key is ever returned to the browser.

Errors are `{"detail": "..."}` or `{"field": ["message"]}` with the usual status codes:
`400` bad input · `401` not signed in · `403` role too low or CSRF failure · `404` · `429` rate limited · `501` not available yet.

## Auth
| Method | Path | Notes |
|---|---|---|
| GET | `/auth/csrf` | Sets the CSRF cookie. Call before logging in. |
| POST | `/auth/login` | `{username, password}` → user. CSRF enforced. Throttled (10/min per IP by default). |
| POST | `/auth/logout` | 204. |
| GET | `/auth/me` | `{id, username, first_name, last_name, role}` or 401. |

Roles: `VIEWER` (read), `ANALYST` (read + VirusTotal actions), `ADMIN` (everything, plus Django admin for users). Superusers are admins.

## Public
`GET /meta` → `{mode: "demo"|"live", generated_at, features: {virustotal, realtime}}`. No telemetry; used by the UI to label demo data and to disable actions the server cannot perform.

## Dashboard (all roles)
| Path | Returns |
|---|---|
| `/dashboard/stats` | totals, severity counts, payload totals, `detection_rate` (malicious ÷ payloads with a VirusTotal result), classifications |
| `/dashboard/timeline?range=24h\|7d&tz=Area/City` | zero-filled buckets with per-severity counts |
| `/dashboard/protocols` | `[{protocol, count}]` |
| `/dashboard/rules?limit=8` | top rules (max 50) |
| `/dashboard/filters` | sensors, protocols, rules for filter dropdowns |

## Alerts, sensors, payloads (read-only)
`GET /alerts`, `/alerts/{id}`, `/sensors`, `/sensors/{id}`, `/payloads`, `/payloads/{sha256}`,
`/payloads/summary`, `/payloads/trend?tz=`, `/payloads/{sha256}/virustotal`.

Lists return `{count, page, page_size, results}`. `page_size` max 100; an out-of-range `page` is clamped to the last page.
Ordering is `?ordering=field` or `-field`; any other value is a 400. Ties are broken by id so pages never overlap.

**Alert filters:** `severity`, `sensor` (id), `protocol`, `rule` (signature id), `has_payload`, `date_from`, `date_to` (ISO datetimes), `search` (rule, classification, protocol, sensor, IPs, SHA-256, SID).
**Alert ordering:** `timestamp, severity (by rank), signature, classification, source_ip, destination_ip, protocol, sensor, payload`.
**Payload filters:** `status`, `sensor`, `search` (hash, file name, MIME type, rule, sensor, SID).
**Payload ordering:** `sha256, first_seen, size, mime_type, sensor, snort_rule, vt_detection, status`.

`/sensors` returns a plain array. A sensor's `status` is **derived from `last_seen`** on every request
(`ONLINE` < 2 min ≤ `WARNING` < 10 min ≤ `OFFLINE`, configurable) and is never stored.

`GET /payloads/{sha256}/virustotal` returns the locally cached result and never contacts VirusTotal.
`POST /payloads/{sha256}/rescan` (analyst+) returns **501** until Phase 4.

`raw_event` (the untrusted Snort JSON) is stored but deliberately not exposed in Phase 2.

## Ingestion (collectors only)
`POST /api/ingest/events` and `POST /api/ingest/heartbeat` use a per-sensor key, not a session. They are documented in
[INGESTION.md](INGESTION.md). Sensor keys cannot read any endpoint above, and a signed-in user (even an admin) cannot call them.
