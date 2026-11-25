from pathlib import Path

from sqlalchemy import select

from kernelguard.app_activity import normalize_activity
from kernelguard.core import alert_events, alerts, database, events, ingest, metadata, settings
from kernelguard.demo import activity_audit
from kernelguard.inventory.service import store_snapshot
from kernelguard.parser import parse_audit
from kernelguard.web import create_app
from tests.test_inventory import example


def test_every_alert_rule_has_demo_evidence_and_source_label():
    engine = database("sqlite://")
    metadata.create_all(engine)
    cfg = settings()
    cfg.update(risky_web_domains=["risky.example"], trusted_email_domains=["trusted.example"])
    audit_text = Path("fixtures/demo.audit").read_text() + "\n" + activity_audit()
    app_examples = [
        dict(type="web_visit", application="firefox", event_id="risky-site",
             value="https://risky.example/path?private=removed"),
        dict(type="web_visit", application="chromium", event_id="plain-http",
             value="http://ordinary.example/path"),
        dict(type="email_sent", application="thunderbird", event_id="external-mail",
             value=["outside.example"]),
    ]
    with engine.begin() as conn:
        for record in parse_audit(audit_text, cfg["host_id"], "demo"):
            ingest(conn, record, cfg)
        snapshot = example(host=cfg["host_id"])
        store_snapshot(conn, snapshot, cfg)
        for payload in app_examples:
            record = normalize_activity(payload, cfg)
            record["origin"] = "demo"
            ingest(conn, record, cfg)
        demo_alerts = conn.execute(select(alerts.c.id, alerts.c.rule)).all()
        assert {rule for _, rule in demo_alerts} == {
            "Repeated login failures", "After-hours protected access",
            "Bulk protected-file activity", "Sensitive privileged command",
            "Unapproved USB device", "Configured risky website",
            "Unencrypted web visit", "Email to external domain",
        }
        assert len(demo_alerts) == 8
        assert set(conn.execute(select(events.c.origin).join(alert_events).distinct()).scalars()) == {"demo"}
        assert len(conn.execute(select(alert_events.c.alert_id).distinct()).all()) == 8
        store_snapshot(conn, example(host=cfg["host_id"], origin="live"), cfg)

    client = create_app(engine, cfg).test_client()
    all_page = client.get("/").get_data(as_text=True)
    demo_page = client.get("/?alert_source=demo").get_data(as_text=True)
    live_page = client.get("/?alert_source=live").get_data(as_text=True)
    assert "Recorded live <span>1</span>" in all_page
    assert "Demo <span>8</span>" in all_page
    assert all(rule in demo_page for _, rule in demo_alerts)
    assert "alert-origin-live" not in demo_page
    assert "Unapproved USB device" in live_page
    assert "Configured risky website" not in live_page
    assert client.get("/?alert_source=invalid").status_code == 400
    for alert_id, _ in demo_alerts:
        detail = client.get(f"/alerts/{alert_id}").get_data(as_text=True)
        assert "Synthetic demo evidence" in detail
        assert "Imported Linux Audit evidence" not in detail
    engine.dispose()
