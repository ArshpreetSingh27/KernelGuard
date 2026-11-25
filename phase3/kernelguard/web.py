import json
import time
from pathlib import Path
from flask import Flask, render_template, request, abort, g, redirect, url_for, send_from_directory
from jinja2 import ChoiceLoader, FileSystemLoader
from sqlalchemy import select, func, or_
from .core import (events, alerts, alert_events, checkpoints, event_context, utc_display,
                   audit_details, rule_policies, alert_policies, alert_reviews, administrators)
from .auth import configure_auth
from .locking import writer_lock
from .reviews import review_alert, ReviewConflict


def event_view():
    return select(events, audit_details.c.login_uid, audit_details.c.real_uid,
        audit_details.c.effective_uid.label("observed_effective_uid"),
        audit_details.c.audit_serial, audit_details.c.syscall,
        audit_details.c.architecture, audit_details.c.inode, audit_details.c.device
        ).outerjoin(audit_details, events.c.id == audit_details.c.event_id)


def alert_source(origins):
    if origins == {"live"}:
        return "live"
    if origins == {"demo"}:
        return "demo"
    return "mixed" if origins else "unknown"


def collector_status(value, now):
    """A damaged health checkpoint must not take down the investigation UI."""
    try:
        health = json.loads(value) if value else None
    except (TypeError, ValueError):
        return None, False
    if not isinstance(health, dict):
        return None, False
    last_poll = health.get("last_poll")
    if type(last_poll) is not int or not 0 <= last_poll <= now + 30:
        return None, False
    return health, 0 <= now - last_poll < 30


def create_app(engine, cfg, secret_key=None):
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([app.jinja_loader, FileSystemLoader(str(Path(__file__).parent))])
    configure_auth(app, engine, secret_key)
    from .inventory.routes import register_inventory
    register_inventory(app, engine)
    app.jinja_env.filters["utc"] = utc_display

    @app.get("/refresh.js")
    def refresh_script():
        return send_from_directory(Path(__file__).parent, "refresh.js", mimetype="application/javascript")

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def dashboard():
        kind = request.args.get("kind", "")
        account = request.args.get("account", "").strip()[:128]
        resource = request.args.get("resource", "").strip()[:256]
        alert_filter = request.args.get("alert_source", "all")
        if alert_filter not in ("all", "live", "demo"):
            abort(400, "Invalid alert source")
        query = event_view().order_by(events.c.timestamp.desc(), events.c.id.desc()).limit(100)
        if kind == "app_activity":
            query = query.where(events.c.kind.in_(("web_visit", "email_sent")))
        elif kind:
            query = query.where(events.c.kind == kind)
        if account:
            query = query.where(events.c.account == account)
        if resource:
            query = query.where(events.c.resource.contains(resource, autoescape=True))
        with engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
            recent_files = conn.execute(select(events).where(
                events.c.kind == "file_access",
                events.c.resource.startswith(cfg["protected_path"]))
                .order_by(events.c.timestamp.desc(), events.c.id.desc()).limit(8)).mappings().all()
            recent_processes = conn.execute(select(events).where(events.c.kind == "process_exec")
                .order_by(events.c.timestamp.desc(), events.c.id.desc()).limit(8)).mappings().all()
            recent_apps = conn.execute(select(events).where(events.c.kind.in_(("web_visit", "email_sent")))
                .order_by(events.c.timestamp.desc(), events.c.id.desc()).limit(8)).mappings().all()
            sources = select(alert_events.c.alert_id,
                func.min(events.c.origin).label("first_origin"),
                func.max(events.c.origin).label("last_origin")
                ).join(events, events.c.id == alert_events.c.event_id
                ).group_by(alert_events.c.alert_id).subquery()
            alert_query = select(alerts, sources.c.first_origin, sources.c.last_origin
                ).outerjoin(sources, sources.c.alert_id == alerts.c.id)
            if alert_filter != "all":
                alert_query = alert_query.where(sources.c.first_origin == alert_filter,
                    sources.c.last_origin == alert_filter)
            latest_alerts = conn.execute(alert_query.order_by(
                alerts.c.timestamp.desc(), alerts.c.id.desc()).limit(30)).mappings().all()
            source_counts = dict(conn.execute(select(sources.c.first_origin, func.count())
                .where(sources.c.first_origin == sources.c.last_origin)
                .group_by(sources.c.first_origin)).all())
            total = conn.execute(select(func.count()).select_from(events)).scalar()
            latest_event_ts = conn.execute(select(func.max(events.c.timestamp))).scalar()
            alert_count = conn.execute(select(func.count()).select_from(alerts)).scalar()
            file_count = conn.execute(select(func.count()).select_from(events).where(
                events.c.kind == "file_access")).scalar()
            process_count = conn.execute(select(func.count()).select_from(events).where(
                events.c.kind == "process_exec")).scalar()
            app_count = conn.execute(select(func.count()).select_from(events).where(
                events.c.kind.in_(("web_visit", "email_sent")))).scalar()
            demo_count = conn.execute(select(func.count()).select_from(events).where(events.c.origin == "demo")).scalar()
            health_value = conn.execute(select(checkpoints.c.value).where(checkpoints.c.name == "collector_health")).scalar()
            latest_review = select(alert_reviews.c.alert_id, func.max(alert_reviews.c.id).label("latest_id")).group_by(
                alert_reviews.c.alert_id).subquery()
            reviews = dict(conn.execute(select(alert_reviews.c.alert_id, alert_reviews.c.action).join(
                latest_review, alert_reviews.c.id == latest_review.c.latest_id)).all())
            open_alert_count = conn.execute(select(func.count()).select_from(
                alerts.outerjoin(latest_review, alerts.c.id == latest_review.c.alert_id)
                .outerjoin(alert_reviews, alert_reviews.c.id == latest_review.c.latest_id))
                .where(or_(alert_reviews.c.action.is_(None),
                           alert_reviews.c.action != "acknowledge"))).scalar()
        health, healthy = collector_status(health_value, time.time())
        return render_template("dashboard.html", rows=rows, alerts=latest_alerts,
            recent_files=recent_files, recent_processes=recent_processes, recent_apps=recent_apps,
            total=total, file_count=file_count, process_count=process_count, app_count=app_count,
            alert_count=alert_count, open_alert_count=open_alert_count,
            live_alert_count=source_counts.get("live", 0), demo_alert_count=source_counts.get("demo", 0),
            alert_filter=alert_filter, latest_event_ts=latest_event_ts, demo_count=demo_count, health=health,
            healthy=healthy, backend=engine.dialect.name, cfg=cfg, kind=kind, account=account,
            resource=resource, reviews=reviews)

    @app.get("/alerts/<int:alert_id>")
    def detail(alert_id):
        with engine.connect() as conn:
            alert = conn.execute(select(alerts).where(alerts.c.id == alert_id)).mappings().first()
            if alert is None:
                abort(404)
            evidence = conn.execute(event_view().join(alert_events, events.c.id == alert_events.c.event_id).where(
                alert_events.c.alert_id == alert_id).order_by(events.c.timestamp)).mappings().all()
            policy = conn.execute(select(rule_policies).join(alert_policies).where(
                alert_policies.c.alert_id == alert_id)).mappings().first()
            history = conn.execute(select(alert_reviews, administrators.c.username).join(administrators)
                .where(alert_reviews.c.alert_id == alert_id).order_by(alert_reviews.c.id.desc())).mappings().all()
            from .inventory.schema import devices, device_events
            device_evidence = conn.execute(select(devices.c.id, devices.c.label).join(device_events)
                .join(alert_events, alert_events.c.event_id == device_events.c.event_id)
                .where(alert_events.c.alert_id == alert_id)).mappings().all()
        return render_template("alert.html", alert=alert, rows=evidence,
            alert_source=alert_source({row["origin"] for row in evidence}), policy=policy, parameters=json.loads(policy["parameters_json"]) if policy else {}, history=history,
            device_evidence=device_evidence)

    @app.get("/investigate/<int:event_id>")
    def investigate(event_id):
        from .inventory.schema import users, sessions
        from .investigation import classify_timeline

        try:
            minutes = int(request.args.get("minutes", "60"))
        except ValueError:
            abort(400, "Invalid time window")
        if minutes not in (15, 60, 240):
            abort(400, "Invalid time window")
        detail_view = event_view().add_columns(event_context.c.boot_id).outerjoin(
            event_context, events.c.id == event_context.c.event_id)
        with engine.connect() as conn:
            seed = conn.execute(detail_view.where(events.c.id == event_id)).mappings().first()
            if seed is None:
                abort(404)
            window = minutes * 60
            candidates = conn.execute(detail_view.where(
                events.c.host == seed["host"],
                events.c.timestamp.between(seed["timestamp"] - window, seed["timestamp"] + window),
                (events.c.origin == "demo") if seed["origin"] == "demo" else (events.c.origin != "demo"))
                .order_by(func.abs(events.c.timestamp - seed["timestamp"]), events.c.id)
                .limit(501)).mappings().all()
            identities = conn.execute(select(users.c.uid, users.c.username).where(
                users.c.host == seed["host"],
                (users.c.origin == "demo") if seed["origin"] == "demo" else (users.c.origin != "demo"))).all()
            observed_sessions = conn.execute(select(sessions, users.c.uid, users.c.username)
                .outerjoin(users, sessions.c.user_id == users.c.id).where(
                    sessions.c.host == seed["host"],
                    sessions.c.first_seen.between(seed["timestamp"] - window, seed["timestamp"] + window),
                    (sessions.c.origin == "demo") if seed["origin"] == "demo" else (sessions.c.origin != "demo"))
                .order_by(sessions.c.first_seen, sessions.c.id).limit(100)).mappings().all()
        session_rows = [dict(id="session:" + item["id"],
            timestamp=item["first_seen"], kind="session_observed",
            account=item["username"] or ("uid:" + item["uid"] if item["uid"] else "unknown"),
            uid=item["uid"], session=item["audit_session"], boot_id=item["boot_id"],
            resource="Audit session " + item["audit_session"] + " first observed",
            executable=None, outcome="observed") for item in observed_sessions]
        event_rows = candidates[:500]
        if not any(row["id"] == event_id for row in event_rows):
            event_rows = [*event_rows[:499], seed]
        rows = classify_timeline(seed, [*event_rows, *session_rows], identities)
        return render_template("investigation.html", seed=seed, rows=rows,
            minutes=minutes, truncated=len(candidates) > 500)

    @app.post("/alerts/<int:alert_id>/review")
    def review(alert_id):
        if not g.administrator:
            abort(403)
        try:
            expected = int(request.form.get("expected_id", ""))
            with writer_lock(engine), engine.begin() as conn:
                review_alert(conn, alert_id, g.administrator["id"], request.form.get("action"),
                    request.form.get("note", ""), expected)
        except LookupError:
            abort(404)
        except (ReviewConflict, RuntimeError) as exc:
            abort(409, str(exc))
        except ValueError as exc:
            abort(400, str(exc))
        return redirect(url_for("detail", alert_id=alert_id))

    return app
