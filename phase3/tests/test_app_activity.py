"""Receiver authorization, privacy, replay, and application policy checks."""
from sqlalchemy import select

from kernelguard.app_activity import create_activity_app
from kernelguard.core import alerts, database, events, metadata, settings
from kernelguard.web import create_app


def fixture():
    engine = database("sqlite://")
    metadata.create_all(engine)
    cfg = settings()
    cfg.update(risky_web_domains=["bad.example"], trusted_email_domains=["company.example"])
    app = create_activity_app(engine, cfg, token="t" * 40)
    return engine, cfg, app.test_client()


def send(client, payload, token="t" * 40):
    return client.post("/v1/activity", json=payload,
                       headers={"Authorization": "Bearer " + token})


def test_receiver_rejects_unauthorized_and_extra_fields():
    engine, cfg, client = fixture()
    value = dict(type="web_visit", application="firefox", event_id="visit_1",
                 value="https://example.org/a?secret=1")
    assert client.post("/v1/activity", json=value).status_code == 401
    assert send(client, value, "wrong").status_code == 401
    assert send(client, dict(value, body="private")).status_code == 400
    with engine.connect() as conn:
        assert conn.execute(select(events)).all() == []


def test_extension_preflight_allows_authenticated_post_only_from_extension_origin():
    engine, cfg, client = fixture()
    origin = "moz-extension://9e2a68a1-1861-4110-9920-95dde5908a56"
    response = client.options("/v1/activity", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type"})
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == origin
    assert response.headers["Access-Control-Allow-Methods"] == "POST"
    assert "Authorization" in response.headers["Access-Control-Allow-Headers"]
    untrusted = client.options("/v1/activity", headers={"Origin": "https://example.com"})
    assert "Access-Control-Allow-Origin" not in untrusted.headers
    unauthorized = client.post("/v1/activity", json={}, headers={"Origin": origin})
    assert unauthorized.status_code == 401
    assert unauthorized.headers["Access-Control-Allow-Origin"] == origin
    with engine.connect() as conn:
        assert conn.execute(select(events)).all() == []


def test_web_privacy_alerts_and_replay():
    engine, cfg, client = fixture()
    value = dict(type="web_visit", application="chromium", event_id="visit_2",
                 value="https://sub.bad.example/report?token=private#fragment")
    assert send(client, value).status_code == 201
    assert send(client, value).status_code == 200
    assert send(client, dict(value, event_id="visit_3", value="http://safe.example/a" )).status_code == 201
    with engine.connect() as conn:
        rows = conn.execute(select(events)).mappings().all()
        rules = conn.execute(select(alerts.c.rule)).scalars().all()
    assert len(rows) == 2
    assert rows[0]["resource"] == "https://sub.bad.example/report"
    assert "private" not in str(rows)
    assert set(rules) == {"Configured risky website", "Unencrypted web visit"}
    html = create_app(engine, cfg).test_client().get("/?kind=web_visit").data
    assert b"Web and sent mail" in html and b"sub.bad.example" in html


def test_web_receiver_preserves_ipv6_and_rejects_invalid_host():
    engine, cfg, client = fixture()
    visit = dict(type="web_visit", application="firefox", event_id="ipv6",
                 value="http://[2001:db8::1]/report?token=private")
    assert send(client, visit).status_code == 201
    assert send(client, dict(visit, event_id="bad", value="http://bad host/path")).status_code == 400
    with engine.connect() as conn:
        row = conn.execute(select(events.c.resource)).scalar_one()
        rule = conn.execute(select(alerts.c.rule)).scalar_one()
    assert row == "http://[2001:db8::1]/report"
    assert rule == "Unencrypted web visit"


def test_sent_mail_domains_only_and_external_alert():
    engine, cfg, client = fixture()
    payload = dict(type="email_sent", application="thunderbird", event_id="mail_1",
                   value=["company.example", "Outside.Example"])
    assert send(client, payload).status_code == 201
    assert send(client, dict(payload, event_id="mail_2", value=["company.example"])).status_code == 201
    with engine.connect() as conn:
        rows = conn.execute(select(events)).mappings().all()
        rules = conn.execute(select(alerts.c.rule)).scalars().all()
    assert rows[0]["resource"] == "company.example, outside.example"
    assert rules == ["Email to external domain"]
    assert send(client, dict(payload, value=["name@outside.example"])).status_code == 400
