# Ingestion API (Phase 3)

Used only by collectors. Authentication is a per-sensor key (`Authorization: Bearer snt_...`), never a session cookie,
and a sensor key cannot call any read endpoint (nor can a signed-in person call these). Both endpoints are POST + JSON only,
refuse to run while the server is in demo mode (409), and are throttled per sensor.

## Sensors and keys

| | |
|---|---|
| Create | `python manage.py register_sensor --name NAME --os linux\|windows` (prints the key once) |
| Rotate | `python manage.py rotate_sensor_key --name NAME` or the Django admin action "Issue a new API key" |
| Disable | untick `is_active` in the admin; the sensor is rejected immediately |
| Stored | a SHA-256 digest and a 12-character lookup prefix. The key itself cannot be recovered |
| Failures | all invalid credentials return the same `401 {"detail": "Invalid sensor credentials."}`; repeated failures from one address are throttled (`INGEST_AUTH_FAIL_LIMIT`, default 20/min) without ever blocking a valid key |

The sensor is identified by its key. A request can never name or choose which sensor it is.

## POST /api/ingest/events

```json
{"schema": 1, "events": [ { ...event... }, ... ]}
```

Limits: 500 events and 2 MiB per request (`INGEST_MAX_EVENTS_PER_REQUEST`, `INGEST_MAX_BODY_BYTES`; the body is read with a hard cap, so chunked or endless bodies are cut off with 413).

### Event

| Field | Required | Rule |
|---|---|---|
| `timestamp` | yes | ISO 8601. Rejected if more than 5 minutes in the future or older than 30 days |
| `signature_id` | yes | integer 0 to 2147483647 |
| `gid`, `rev` | no | integers |
| `signature` | no | text, control and invisible characters stripped, truncated to 512. Missing → stored as `SID gid:sid` (a label, not invented rule text) |
| `classification` | no | text, truncated to 128 |
| `priority` | no | 0 to 255 |
| `protocol` | no | `[A-Za-z0-9_-]{1,16}`, upper-cased |
| `source_ip`, `destination_ip` | no | valid IPv4/IPv6, normalised |
| `source_port`, `destination_port` | no | 0 to 65535 |
| `pkt_num` | no | used only to tell apart otherwise identical events |
| `payload` | no | `{sha256 (64 hex), size, mime_type?, filename?}`, metadata only. File names are reduced to a basename |
| `raw` | no | the original Snort object, stored for forensics. `b64_data` is always removed; over 16 KiB it is replaced by `{"truncated": true}`. Not exposed by the read API |

Unknown extra fields are ignored. Absent fields are stored as null/empty; nothing is filled in.

### Response (200)

```json
{"received": 4, "accepted": 2, "duplicates": 1, "rejected": 1,
 "errors": [{"index": 3, "errors": {"signature_id": ["Ensure this value is greater than or equal to 0."]}}]}
```

Valid events are stored even when others in the batch are rejected. At most 50 errors are listed. A malformed envelope (bad JSON, wrong `schema`, empty or oversized `events`) is `400`; wrong content type `415`; too large `413`; too many requests `429`.

### Severity

Snort has priorities, not severities. Sentinel maps: priority 1 → **HIGH**, or **CRITICAL** when the classification is in `SENTINEL_CRITICAL_CLASSIFICATIONS` (default `trojan-activity, successful-admin, successful-user, shellcode-detect`); priority 2 → **MEDIUM**; priority 3 or more → **LOW**; no priority → **LOW** (never guessed upward). Edit the setting to suit your environment. Severity is computed on the server, from the stored `priority` and `classification`.

### Duplicates

`event_id` is a hash of timestamp, rule ids, protocol, both endpoints and `pkt_num`, computed by the server (a collector cannot supply or forge one). Re-sending an event, which at-least-once delivery does after any failure, is counted as a duplicate and stored once. The same event from two different sensors is two alerts.

### Payload records

A first sighting creates a `Payload` with status `UNKNOWN` and no VirusTotal data. Later sightings widen `first_seen`/`last_seen` and fill a blank MIME type or file name. Ingestion never changes `status` or any `vt_*` field. The same SHA-256 reported with a different size is refused (impossible for genuine data).

## POST /api/ingest/heartbeat

```json
{"hostname": "edge01", "os": "LINUX", "ip": "10.20.0.11", "snort_version": "3.3.2.0", "collector_version": "0.1.0"}
```
All fields optional; only those present are updated, and absent ones never blank out stored values. Throttled separately from events (a quiet sensor still proves it is alive).

## Sensor health

`last_seen` is set from the **server's clock** on every authenticated request, including a heartbeat and a batch in which every event was rejected. A sensor's clock can therefore never make it look healthy. Status is derived on read: `ONLINE` under 2 minutes, `WARNING` under 10, `OFFLINE` after (`SENSOR_WARNING_AFTER_SECONDS`, `SENSOR_OFFLINE_AFTER_SECONDS`). A sensor that has never reported is `OFFLINE`, shown as "never reported".

## Settings

| Variable | Default |
|---|---|
| `INGEST_MAX_BODY_BYTES` | 2097152 |
| `INGEST_MAX_EVENTS_PER_REQUEST` | 500 |
| `INGEST_MAX_EVENT_AGE_DAYS` | 30 |
| `INGEST_MAX_FUTURE_SKEW_SECONDS` | 300 |
| `INGEST_MAX_RAW_BYTES` | 16384 |
| `INGEST_AUTH_FAIL_LIMIT` | 20 (per minute per client address) |
| `THROTTLE_INGEST` / `THROTTLE_HEARTBEAT` | `120/min` / `20/min` per sensor |
| `SENTINEL_CRITICAL_CLASSIFICATIONS` | `trojan-activity,successful-admin,successful-user,shellcode-detect` |

Behind a reverse proxy, also cap request bodies there (e.g. nginx `client_max_body_size 2m`) and make sure the server sees the real client address for the failed-key throttle.
