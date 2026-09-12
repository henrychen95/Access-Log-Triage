from __future__ import annotations

import ipaddress
from pathlib import Path

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .analysis import (
    application_journey,
    format_duration,
    is_static_noise,
    is_static_resource,
    redacted_raw_line,
    split_sessions,
    status_group,
    top_paths,
)
from .parser import FileTooLargeError, parse_binary_stream
from .state import build_loaded_log, current_log_store

PACKAGE_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 150 * 1024 * 1024

app = FastAPI(title="Access Log Triage", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")
templates.env.globals.update(
    is_static_resource=is_static_resource,
    is_static_noise=is_static_noise,
    status_group=status_group,
    format_duration=format_duration,
    redacted_raw_line=redacted_raw_line,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = None
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            # Leave room for multipart headers around the 150 MiB file.
            if int(content_length) > MAX_UPLOAD_BYTES + 1024 * 1024:
                response = HTMLResponse("Request body is too large.", status_code=413)
        except ValueError:
            response = HTMLResponse("Invalid Content-Length header.", status_code=400)

    if response is None:
        response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def render(request: Request, *, status_code: int = 200, **context) -> HTMLResponse:
    template_context = {
        "loaded_log": current_log_store.get(),
        "replace_mode": False,
        "analysis_performed": False,
        "error": None,
        "entered_ip": "",
        "entered_gap": 30,
    }
    template_context.update(context)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context=template_context,
        status_code=status_code,
    )


def safe_display_filename(filename: str | None) -> str:
    basename = (filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    printable = "".join(character for character in basename if character.isprintable()).strip()
    return printable[:255] or "access.log"


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return render(request)


@app.get("/replace", response_class=HTMLResponse)
def replace_log(request: Request) -> HTMLResponse:
    loaded_log = current_log_store.get()
    return render(request, loaded_log=loaded_log, replace_mode=loaded_log is not None)


@app.post("/upload", response_class=HTMLResponse)
async def upload_log(request: Request, log_file: UploadFile) -> HTMLResponse:
    previous_log = current_log_store.get()
    try:
        if not log_file.filename:
            return render(
                request,
                loaded_log=previous_log,
                replace_mode=previous_log is not None,
                error="Choose an Apache access log file.",
                status_code=400,
            )
        if log_file.size is not None and log_file.size > MAX_UPLOAD_BYTES:
            raise FileTooLargeError("Log exceeds the 150 MiB limit")

        parsed = parse_binary_stream(log_file.file, max_bytes=MAX_UPLOAD_BYTES)
        if not parsed.entries:
            return render(
                request,
                loaded_log=previous_log,
                replace_mode=previous_log is not None,
                error="The file contained no valid Apache access-log records.",
                status_code=400,
            )
        candidate = build_loaded_log(safe_display_filename(log_file.filename), parsed)
    except FileTooLargeError as error:
        return render(
            request,
            loaded_log=previous_log,
            replace_mode=previous_log is not None,
            error=str(error),
            status_code=413,
        )
    except OSError:
        return render(
            request,
            loaded_log=previous_log,
            replace_mode=previous_log is not None,
            error="The uploaded log could not be read.",
            status_code=400,
        )
    finally:
        await log_file.close()

    # Atomic replacement: the previous snapshot remains current until parsing
    # and indexing the complete candidate has succeeded.
    current_log_store.replace(candidate)
    return RedirectResponse(url="/", status_code=303)


@app.post("/analyze", response_class=HTMLResponse)
def analyze(
    request: Request,
    log_id: str = Form(...),
    ip_address: str = Form(...),
    session_gap: int = Form(30),
) -> HTMLResponse:
    loaded_log = current_log_store.get()
    if loaded_log is None:
        return render(
            request,
            error="Load an Apache access log before analyzing an IP address.",
            status_code=400,
        )
    if log_id != loaded_log.id:
        return render(
            request,
            loaded_log=loaded_log,
            error="The loaded log changed. Submit the IP again using the current log.",
            entered_gap=session_gap,
            status_code=409,
        )

    ip_text = ip_address.strip()
    try:
        normalized_ip = str(ipaddress.ip_address(ip_text))
    except ValueError:
        return render(
            request,
            loaded_log=loaded_log,
            error="Enter a valid IPv4 or IPv6 address.",
            entered_ip=ip_text,
            entered_gap=session_gap,
            status_code=400,
        )

    if not 1 <= session_gap <= 1440:
        return render(
            request,
            loaded_log=loaded_log,
            error="Session gap must be between 1 and 1440 minutes.",
            entered_ip=ip_text,
            entered_gap=session_gap,
            status_code=400,
        )

    records = loaded_log.records_for(normalized_ip)
    sessions = split_sessions(records, session_gap)
    application_count = sum(not is_static_resource(entry) for entry in records)
    static_count = len(records) - application_count
    metrics = {
        "total": len(records),
        "application": application_count,
        "static": static_count,
        "post": sum(entry.method == "POST" for entry in records),
        "3xx": sum(status_group(entry.status) == "3xx" for entry in records),
        "4xx": sum(status_group(entry.status) == "4xx" for entry in records),
        "5xx": sum(status_group(entry.status) == "5xx" for entry in records),
    }
    journeys = [
        {
            "number": session.number,
            "requests": [
                {
                    "sequence": sequence,
                    "timestamp": entry.timestamp.strftime("%H:%M:%S"),
                    "method": entry.method,
                    "path": entry.path,
                    "status": entry.status,
                }
                for sequence, entry in enumerate(application_journey(session.entries), 1)
            ],
        }
        for session in sessions
    ]

    return render(
        request,
        loaded_log=loaded_log,
        analysis_performed=True,
        records=records,
        sessions=sessions,
        metrics=metrics,
        paths=top_paths(records),
        journeys=journeys,
        analyzed_ip=normalized_ip,
        entered_ip=ip_text,
        entered_gap=session_gap,
    )
