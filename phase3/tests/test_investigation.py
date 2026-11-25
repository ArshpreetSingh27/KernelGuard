"""An investigation links recorded identities while keeping host context separate."""

from sqlalchemy import select

from kernelguard.core import database, events, event_context, metadata, settings
from kernelguard.inventory.schema import users, sessions
from kernelguard.investigation import classify_timeline
from kernelguard.web import create_app


def test_investigation_timeline_and_attribution():
    engine = database("sqlite://")
    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(users.insert().values(id="alice", host="lab", origin="live",
            uid="1000", username="alice", last_seen=1000, present=True))
        conn.execute(sessions.insert().values(id="session7", host="lab", origin="live",
            boot_id="a", audit_session="7", user_id="alice", first_seen=1000,
            last_seen=1100, present=True))

        def add(source, kind, account, *, host="lab", stamp=1000, uid=None,
                session=None, origin="live", boot=None):
            eid = conn.execute(events.insert().values(source_id=source, host=host,
                timestamp=stamp, kind=kind, account=account, uid=uid,
                session=session, outcome="observed", origin=origin,
                resource=source)).inserted_primary_key[0]
            if boot:
                conn.execute(event_context.insert().values(event_id=eid, boot_id=boot))
            return eid

        add("login", "login_failure", "alice", stamp=990)
        add("process", "process_exec", "uid:1000", uid="1000", session="7", boot="a")
        seed = add("file", "file_access", "uid:1000", uid="1000", session="7", boot="a")
        add("usb", "usb_seen", "unattributed")
        add("web", "web_visit", "app:firefox")
        add("mail", "email_sent", "app:thunderbird")
        add("other-user", "file_access", "uid:1001", uid="1001", session="9")
        add("other-host", "file_access", "uid:1000", host="elsewhere")
        add("other-boot", "process_exec", "uid:1000", uid="1000", session="7", boot="b")
        add("synthetic", "file_access", "uid:1000", uid="1000", origin="demo")
        add("outside-window", "file_access", "uid:1000", uid="1000", stamp=9000)

    client = create_app(engine, settings()).test_client()
    response = client.get(f"/investigate/{seed}")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Same user and session" in html
    assert "Same account · login unverified" in html
    assert "Audit session 7 first observed" in html
    assert "Same user" in html
    assert "Host context · user unverified" in html
    for source in ("login", "process", "file", "usb", "web", "mail", "other-user"):
        assert f">{source}<" in html
    for source in ("other-host", "other-boot", "synthetic", "outside-window"):
        assert f">{source}<" not in html
    assert client.get(f"/investigate/{seed}?minutes=2").status_code == 400
    assert client.get("/investigate/999999").status_code == 404
    assert b"Investigate nearby" in client.get("/").data
    with engine.connect() as conn:
        assert len(conn.execute(select(events)).all()) == 11
    engine.dispose()


def test_application_and_usb_context_never_inherit_user_identity():
    seed = dict(id=1, kind="file_access", uid="1000", account="uid:1000", session="7", boot_id="a", timestamp=1000)
    candidates = [seed,
        dict(id=2, kind="web_visit", uid=None, account="app:firefox", session=None, boot_id=None, timestamp=1001),
        dict(id=3, kind="usb_seen", uid=None, account="unattributed", session=None, boot_id=None, timestamp=1002),
        dict(id=4, kind="file_access", uid="1001", account="uid:1001", session="7", boot_id="a", timestamp=1003),
        dict(id=5, kind="file_access", uid="1000", account="uid:1000", session="7", boot_id=None, timestamp=1004),
        dict(id=6, kind="login_failure", uid=None, account="alice", session=None, boot_id=None, timestamp=1005)]
    rows = classify_timeline(seed, candidates, [("1000", "alice"), ("1001", "bob")])
    assert [row["relation"] for row in rows] == [
        "Selected event", "Host context · user unverified", "Host context · user unverified",
        "Host context · user unverified", "Same user", "Same account · login unverified"]


def test_selected_event_is_visible_when_window_is_capped():
    engine = database("sqlite://")
    metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(events.insert(), [dict(source_id=str(i), host="lab", timestamp=1000,
            kind="file_access", account="uid:1000", uid="1000", outcome="success",
            origin="live", resource=f"file-{i}") for i in range(501)])
        seed = conn.execute(select(events.c.id).where(events.c.source_id == "500")).scalar_one()
    html = create_app(engine, settings()).test_client().get(f"/investigate/{seed}").get_data(as_text=True)
    assert "Selected event" in html
    assert "file-500" in html
    assert "Showing the 500 events closest" in html
    engine.dispose()
