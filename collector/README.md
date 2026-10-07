# Sentinel collector

Reads Snort 3 JSON or Snort 2 fast alerts from a file, validates and normalises them, and sends them to the Sentinel API.
Pure Python standard library (3.11+): nothing to `pip install`, one shared core for Linux and Windows.

```
Snort 3 alert_json / Snort 2 alert_fast ──► alert file ──► collector ──► HTTPS + sensor key ──► Sentinel API
```

## What needs a real Snort 3, and what does not

| Needs | Why |
|---|---|
| A real **Snort 3** or **Snort 2** install | Snort 3 writes `alert_json`; Snort 2 writes one-line `alert_fast` records. The collector's parsers are unit tested; configure your own rules and verify the output from your Snort build. |
| A real network interface or pcap | for Snort to see traffic |
| A sensor **API key** from your Sentinel server | `python manage.py register_sensor ...` |

Everything else (parsing, delivery, retries, rotation, the server side) is tested end to end without Snort using synthetic lines, see "Try it without Snort".

## 1. Configure Snort output

### Snort 3

Add the contents of [`snort/snort-alert-json.lua`](snort/snort-alert-json.lua) to your `snort.lua`, run Snort with a log directory (`-l /var/log/snort`), and check what it produces:

```bash
snort --help-module alert_json          # lists the field names YOUR build supports. Compare with the .lua file.
tail -f /var/log/snort/alert_json.txt   # one JSON object per line
```

The collector reads these fields and tolerates any being absent: `seconds`, `timestamp`, `pkt_num`, `proto`, `src_addr`, `src_port`, `src_ap`, `dst_addr`, `dst_port`, `dst_ap`, `rule` (`gid:sid:rev`), `gid`, `sid`, `rev`, `msg`, `class`, `priority`, `b64_data`. A line with no rule/sid is skipped (it is not an alert). Nothing is invented for missing fields.

### Snort 2 on Windows

Snort 2.9.20 `-A fast` writes one alert per line to `alert.ids`. Identify the interface with `snort -W`, then run Snort from an elevated PowerShell (capture requires administrator rights):

```powershell
& 'C:\Snort\bin\snort.exe' -A fast -c 'C:\Snort\etc\snort.conf' -i 1 -l 'C:\Snort\log'
```

Replace `1` with the interface index reported by `snort -W`. Validate the configuration first with `snort -T -c 'C:\Snort\etc\snort.conf'`. Some Windows packages ship a Unix-oriented `snort.conf`; its dynamic-library paths must point to the actual Windows files under `C:\Snort\lib` before it will validate. Set the Windows collector's `snort.alert_file` to `C:\Snort\log\alert.ids`. The `alert_fast` output does not contain packet bytes, so payload hashing is unavailable with this format.

Two things worth knowing:

* **Time.** Snort's text `timestamp` is `MM/DD-HH:MM:SS.ffffff`: no year, no time zone. Logging `seconds` removes the ambiguity. Without it the collector assumes the sensor's local zone (`snort.timezone`) and infers the year as the most recent one that is not in the future. The server rejects events more than 5 minutes in the future, which exposes a wrong zone setting quickly.
* **IPv6.** `src_ap`/`dst_ap` ("address:port") cannot always be split unambiguously for IPv6. Log `src_addr`/`src_port`/`dst_addr`/`dst_port` (as the example does) and the collector uses those instead.

## 2. Register the sensor and get a key (on the Sentinel server)

```bash
cd backend && python manage.py register_sensor --name linux-edge-01 --os linux
```

The key is printed **once**; the server stores only a digest. Lost it? `python manage.py rotate_sensor_key --name linux-edge-01` (the old key stops working immediately). A sensor can be disabled in the Django admin (`is_active`). Registering is refused while the server is in demo mode.

## 3. Install and configure

The API key never goes in the config file (the collector refuses a config that contains `api_key`). Use an environment variable or a key file.

### Linux
```bash
sudo mkdir -p /opt/sentinel && sudo cp -r collector /opt/sentinel/
sudo install -d -m 750 /etc/sentinel-collector
sudo cp collector/linux/collector.example.toml /etc/sentinel-collector/collector.toml     # edit url, alert_file
echo 'SENTINEL_API_KEY=snt_...' | sudo tee /etc/sentinel-collector/env >/dev/null && sudo chmod 640 /etc/sentinel-collector/env
sudo cp collector/linux/sentinel-collector.service /etc/systemd/system/                   # read the header comments first
cd /opt/sentinel/collector
sudo -u sentinel-collector env $(cat /etc/sentinel-collector/env) python3 -m sentinel_collector check -c /etc/sentinel-collector/collector.toml
sudo systemctl enable --now sentinel-collector && journalctl -u sentinel-collector -f
```
The unit file is hardened (no new privileges, read-only filesystem except its state directory, only IP sockets). It was **not run under systemd** in the build environment; check it on your distribution.

### Windows
1. Install Python 3.11+. Copy the `collector` folder somewhere stable (e.g. `C:\Sentinel\collector`).
2. Copy `windows\collector.example.toml` to `C:\ProgramData\Sentinel\collector.toml` and edit `url` and `alert_file`. Use single quotes around Windows paths.
3. Create a dedicated low-privilege local account that can read the Snort log folder.
4. From an elevated PowerShell: `.\windows\install-task.ps1 -Credential (Get-Credential .\sentinel-collector) -ApiKey 'snt_...'`. This stores the key in a file only that account can read and registers a Scheduled Task that starts at boot and restarts on failure.
5. `python -m sentinel_collector check --config C:\ProgramData\Sentinel\collector.toml`, then `Start-ScheduledTask -TaskName SentinelCollector`.

The Windows collector and Snort 2 `alert_fast` parser are unit-tested on Windows. The scheduled-task installer has not been run here; test it before relying on it in production. The collector never keeps the alert file open, so Snort can rotate it; paths use `pathlib`, and `timezone = "local"` needs no tz database.

## 4. Commands

```
python -m sentinel_collector check   -c collector.toml            # config, file, connection and key
python -m sentinel_collector run     -c collector.toml            # follow the file (the normal mode)
python -m sentinel_collector dry-run -c collector.toml -f FILE    # print what would be sent; no network
python -m sentinel_collector replay  -c collector.toml -f FILE    # send a file once (testing)
```

## Try it without Snort

```bash
python -m sentinel_collector.sample 20 > /tmp/test_alerts.txt        # 20 SYNTHETIC Snort 3 JSON lines
python -m sentinel_collector dry-run -c collector.toml -f /tmp/test_alerts.txt
```
Every synthetic message starts with `SYNTHETIC TEST`. `replay` sends them as **real rows** to whatever server the config points at, so use a test server or scratch database, never production.

## Delivery guarantees

* **At-least-once, in order, nothing lost.** A line is marked done only after the server accepts it or definitively refuses it. Crash, restart, network outage and server errors cannot lose an alert. The server removes the duplicates this can cause (identical events are recognised by content).
* **Retries.** Network errors, 5xx, 408, 409, 429 → exponential backoff (cap 60 s, honours `Retry-After`). 401/403 (wrong, rotated or disabled key) → keep the data and retry every few minutes with a clear error. 413 → the batch is halved. Other 4xx → the batch is dropped and logged so one bad batch cannot block the queue forever.
* **Rotation.** Rename-and-recreate, truncation, and delete-and-recreate (even when the filesystem reuses the inode) are all detected.
* **State** lives in `collector.state_file`, written atomically. A corrupt or foreign state file is ignored safely.
* **First run.** `start_at = "end"` ignores existing history; `"beginning"` sends all of it.

## Payload hashing (off by default)

`[payloads] enabled = true` makes the collector hash each alert's `b64_data` and send only `{sha256, size, mime_type}`.

**Read this before enabling.** `b64_data` is the data of *one packet*, not a reassembled file. The hash identifies that packet's bytes. A file spread over many packets produces a different hash per packet, so Phase 4's VirusTotal lookups on these hashes will usually return "unknown", and busy sensors will fill the Payload page with packet fragments. It is therefore opt-in. Hashing *whole files* needs Snort's file inspection output, which this repository does not consume (it would need a real Snort to build and test against).

The decoded bytes are hashed in memory and discarded: never written to disk, never sent to the server, never executed or interpreted. The MIME type is a guess from the first bytes.

## Security notes

* TLS is verified. `http://` to a non-loopback host is refused unless `allow_insecure_http = true`. Redirects are never followed (so the key cannot be re-sent elsewhere). Use `ca_file` for a private CA.
* The key is read from an environment variable or a key file (a warning is printed if the file is group/world-readable on Linux), is redacted from any representation of the config, and is never logged.
* The server re-validates everything: a modified collector or stolen key cannot inject fields the schema does not allow, choose a different sensor, or store packet bytes.

## Tests

```bash
cd collector && python -m unittest discover -s tests -t .      # 102 tests, no network, no Snort
```
