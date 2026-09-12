# Access Log Triage

Load an Apache access log, enter an IP address, and reconstruct that client's web request journey.

Access Log Triage is a small local utility for operations staff. It parses Apache Combined/Common access logs, finds an exact IPv4 or IPv6 address, removes static-resource noise from the default view, and presents requests as time-ordered sessions. It is not a SIEM, IDS, WAF, or replacement for Wazuh.

## Requirements

- Python 3.12 or newer
- A modern browser

## Installation

Use a project-local virtual environment. Do not install the package globally.

### Ubuntu / Linux

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Run

### Quick start

After completing installation once, start the application from the project directory.

Windows Command Prompt or PowerShell:

```powershell
.\run.cmd
```

Ubuntu / Linux:

```bash
./run.sh
```

The scripts use the project `.venv`, start the server, and open the default browser when supported. Press `Ctrl+C` in the terminal to stop the server. If `.venv` is missing, the scripts print the commands required to create it; they never install packages automatically.

### Manual start

With the virtual environment active:

```bash
python -m access_log_triage
```

Open <http://127.0.0.1:8000>. All launch methods intentionally bind only to `127.0.0.1`.

Alternatively:

```bash
uvicorn access_log_triage.main:app --host 127.0.0.1 --port 8000
```

Load an Apache access log once, then enter any number of exact client IPs and select **Analyze**. The parsed log remains in process memory until you successfully replace it or stop the application. Static resources and query strings are hidden by default. Request details include referer, raw User-Agent, and source line number.

When an IP has at least two sessions, expand **Compare sessions** to compare the application-only journeys side by side. Comparison is positional and deterministic: it uses method plus normalized path, marks the first divergence, and does not treat a difference as an error.

Use **Replace log** to select another file. A replacement is atomic: the current parsed log remains available if the new file cannot be parsed. A successful replacement clears the previous analysis and IP from the view.

The upload limit is 150 MiB. Input is parsed once, line by line; malformed lines are counted and skipped without aborting the analysis. An in-memory IP index stores references to the parsed records so repeated lookups neither rescan the complete collection nor duplicate record objects. The parser supports HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/2.0 Combined Log Format requests.

## Tests

```bash
python -m pytest
```

The test suite uses only synthetic data, including `tests/fixtures/synthetic_journey.log`.

## Privacy and security

**All log processing is performed locally.**

**No access-log data is transmitted to external services.**

There is no telemetry, analytics, CDN, cloud API, database, or persistence layer. FastAPI/Starlette may spool an upload to an operating-system temporary file while processing it; the upload is closed immediately after parsing (including failed replacements) and is not copied into the application or static directories. Only structured records are retained in memory, and they disappear when the single application process stops. Log content is rendered through Jinja2 autoescaping and a restrictive Content Security Policy.

Access logs can contain sensitive query parameters. Query strings are hidden by default and do not appear in the timeline. Reveal them only when necessary.

## Scope

The tool organizes deterministic log evidence for human review. It does not classify attacks, query reputation or GeoIP services, block clients, call Wazuh, or make automated security decisions.
