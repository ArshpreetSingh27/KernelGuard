"""Opt-in application activity ingestion. Store URL paths and recipient domains only."""
import hmac
import ipaddress
import os
import re
import time
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, abort, request

from .core import add_alert, digest, ingest, save_policy
from .locking import WriterBusy, writer_lock

EXTENSION_ORIGIN = re.compile(
    r"(?:moz-extension://[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    r"|chrome-extension://[a-p]{32})"
)


def domain_matches(domain, configured):
    return any(domain == item or domain.endswith("." + item) for item in configured)


def normalize_activity(payload, cfg):
    if not isinstance(payload, dict) or set(payload) != {"type", "event_id", "value", "application"}:
        raise ValueError("Invalid activity fields")
    kind, event_id, value, application = (payload[key] for key in
        ("type", "event_id", "value", "application"))
    if not isinstance(event_id, str) or not re.fullmatch(r"[A-Za-z0-9:_-]{1,160}", event_id):
        raise ValueError("Invalid event ID")
    if (kind, application) not in (("web_visit", "firefox"), ("web_visit", "chromium"),
                                   ("email_sent", "thunderbird")):
        raise ValueError("Invalid application activity")
    if kind == "web_visit":
        if not isinstance(value, str) or len(value) > 8192:
            raise ValueError("Invalid URL")
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid URL") from exc
        if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
            raise ValueError("Only public web URL schemes are accepted")
        host = host.lower().rstrip(".")
        if ":" in host:
            try:
                authority = f"[{ipaddress.IPv6Address(host).compressed}]"
            except ValueError as exc:
                raise ValueError("Invalid IPv6 host") from exc
        else:
            if (len(host) > 253 or not re.fullmatch(r"[a-z0-9._-]+", host)
                    or any(not part or len(part) > 63 for part in host.split("."))):
                raise ValueError("Invalid host")
            authority = host
        authority += f":{port}" if port is not None else ""
        resource = urlunsplit((parsed.scheme, authority, parsed.path or "/", "", ""))[:2048]
    else:
        if not isinstance(value, list) or not 1 <= len(value) <= 100:
            raise ValueError("Expected recipient domains")
        if any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", item)
               or ".." in item or item.startswith(".") or item.endswith(".") for item in value):
            raise ValueError("Invalid recipient domain")
        resource = ", ".join(sorted(set(item.lower() for item in value)))
        if len(resource) > 2048:
            raise ValueError("Too many recipient domains")
    return dict(source_id=digest("app:" + kind + ":" + application + ":" + event_id),
                host=cfg["host_id"], timestamp=int(time.time()), kind=kind,
                account="app:" + application, uid=None, effective_uid=None,
                session=None, pid=None, executable=application, resource=resource,
                outcome="success", origin="live")


def evaluate_app_activity(conn, record, eid, cfg):
    if record["kind"] == "web_visit":
        parsed = urlsplit(record["resource"])
        domain = parsed.hostname or ""
        if domain_matches(domain, cfg.get("risky_web_domains", [])):
            policy = save_policy(conn, "risky_web_domain", dict(
                domains=cfg["risky_web_domains"], severity=70))
            add_alert(conn, "Configured risky website", record, [eid], 70,
                f"Visited configured risky domain {domain} on {record['host']}.",
                "web:" + record["source_id"], policy)
        elif parsed.scheme == "http" and cfg.get("alert_insecure_http", True):
            policy = save_policy(conn, "insecure_http", dict(severity=45, scheme="http"))
            add_alert(conn, "Unencrypted web visit", record, [eid], 45,
                f"Visited {domain} over HTTP on {record['host']}.",
                "http:" + record["source_id"], policy)
    elif record["kind"] == "email_sent":
        trusted = cfg.get("trusted_email_domains", [])
        outside = [domain for domain in record["resource"].split(", ")
                   if not domain_matches(domain, trusted)]
        if trusted and outside:
            policy = save_policy(conn, "external_email", dict(
                trusted_domains=trusted, severity=65))
            add_alert(conn, "Email to external domain", record, [eid], 65,
                f"Sent email to domain(s) outside the trusted list: {', '.join(outside)}.",
                "mail:" + record["source_id"], policy)


def create_activity_app(engine, cfg, token=None):
    token = token if token is not None else os.environ.get("KERNELGUARD_ACTIVITY_TOKEN", "")
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError("KERNELGUARD_ACTIVITY_TOKEN must have at least 32 characters")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 12 * 1024

    @app.post("/v1/activity")
    def activity():
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied, "Bearer " + token):
            abort(401)
        if request.mimetype != "application/json":
            abort(415)
        try:
            record = normalize_activity(request.get_json(), cfg)
        except (ValueError, TypeError):
            abort(400)
        try:
            with writer_lock(engine, wait_seconds=30), engine.begin() as conn:
                inserted = ingest(conn, record, cfg)
        except WriterBusy:
            abort(503)
        return ({"inserted": bool(inserted)}, 201 if inserted else 200)

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        origin = request.headers.get("Origin", "")
        if EXTENSION_ORIGIN.fullmatch(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "POST"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            response.headers["Vary"] = "Origin"
        return response

    return app
