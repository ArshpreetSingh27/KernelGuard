# KernelGuard: run the project and demonstrate its features

Use this guide from the **outer project folder** (`KernalGuard/`, which contains `requirements.txt`). The easiest presentation uses the synthetic SQLite demo. It works on Windows or Linux and does not need auditd, MySQL, a USB device, or browser extensions. Label its records as **synthetic demo**, not live monitoring.

## 1. Start a repeatable demo

Python 3.11 or newer is required. The commands below select `data/presentation-demo.db`, so they do not mix the presentation with the default `data/kernelguard.db` or a live database. Keep the same `KERNELGUARD_DB_URL` in every terminal used for this demo. The `demo` command creates the schema and imports the fixture; repeating it does not add duplicate fixture records.

### Windows PowerShell

```powershell
cd phase3
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:KERNELGUARD_DB_URL = 'sqlite:///data/presentation-demo.db'
.\.venv\Scripts\python.exe -m kernelguard demo
.\.venv\Scripts\python.exe -m kernelguard serve
```

If `.venv` already exists, the `py -m venv` step can be skipped. Keep this terminal open. Visit **http://127.0.0.1:5000/**. Press **Ctrl+C** to stop the server. If port 5000 is busy, use `serve --port 5001` and open that port instead.

The existing `scripts/start.ps1` is a shorter Windows launcher, but it explicitly selects the **default** `data/kernelguard.db`; use it only when that is the database you intend to show.

### Linux standalone demo

```bash
cd /path/to/KernalGuard
python3 -m venv .venv-linux
. .venv-linux/bin/activate
python -m pip install -r requirements.txt
export KERNELGUARD_DB_URL=sqlite:///data/presentation-demo.db
python -m kernelguard demo
python -m kernelguard serve
```

Open **http://127.0.0.1:5000/** on that Linux machine. This is still a synthetic demo; starting the web server alone does not start Linux Audit or the inventory collector.

On a fresh presentation database, expect **21 events, 5 alerts, 2 users, 1 audit session, 3 processes, and 1 USB device**. Counts can differ if that database already has other records or review decisions.

## 2. Enable the interactive administrator features

Without an administrator, the dashboard is a read-only preview. To demonstrate alert acknowledgement and USB approval, stop the server with **Ctrl+C** and create one administrator in the **same selected database**. There is no default account or password.

Windows, in the same PowerShell terminal:

```powershell
.\.venv\Scripts\python.exe -m kernelguard create-admin admin
$env:KERNELGUARD_SECRET_KEY = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")
.\.venv\Scripts\python.exe -m kernelguard serve
```

Linux, in the same shell:

```bash
python -m kernelguard create-admin admin
export KERNELGUARD_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m kernelguard serve
```

Enter a new **12–256 character** password at the private prompts, then sign in at **http://127.0.0.1:5000/login**. If you open a new terminal, set `KERNELGUARD_DB_URL` and `KERNELGUARD_SECRET_KEY` there again before serving. Once an administrator exists, the server requires a secret of at least 32 characters. Keep the password and secret off presentation slides.

## 3. Feature-by-feature demonstration

The following order takes about 10–15 minutes. Use the sidebar links and refresh the page after an action. Alert IDs are assigned by the database, so find alerts by **name**, not by a hard-coded number.

| Feature | What to do on the demo dashboard | What to explain |
| --- | --- | --- |
| Overview and source labels | Open **Overview & activity**. Point to Stored events, Open alerts, the synthetic-data banner, and the **Demo** alert filter. | The fixture is labelled synthetic; the Audit collector can say **Not live** because no Linux poll is running. Event time is shown in UTC. |
| Failed logins | Open **Repeated login failures** in Security alerts. Show the five linked `login_failure` events. | Five failures for the same attempted account within 300 seconds cause the alert. Dashboard sign-in failures are separate from Linux login evidence. |
| After-hours protected file access | Open **After-hours protected access**. Show its supporting successful file event and the saved policy settings. | The configured protected path and allowed hours are evaluated in `Asia/Kolkata`; access can be recorded without being blocked. |
| Bulk file activity | Open **Bulk protected-file activity** and inspect the linked paths. | The rule needs ten **distinct** protected paths in 60 seconds for matching user/session context. It does not prove copying. |
| Privileged command | Open **Sensitive privileged command**. Show the selected executable, login UID and effective UID in the evidence. | The rule looks for selected root-effective commands launched from a non-root login identity. |
| USB observation and enrollment | Open **Unapproved USB device**, follow the device link, then inspect its observations and decision history. If signed in, approve the **synthetic** device with an honest demo note; optionally revoke it and inspect both decisions. | Approval affects future observations; it does not erase the old alert or control the hardware. |
| Inventory | Open **Host inventory** and click **Devices**, **Users**, **Sessions**, and **Processes**. | These are stored observations, including user identity, boot-scoped session, process metadata, and USB presence. A process list is a polling snapshot, not a complete launch history. |
| Event explorer and investigation | Open **Event explorer**, filter by event type such as File access or Process launch, click a row, and show its investigation timeline. Try account/resource filters. | The timeline links supported identity/session facts and labels nearby context; nearby events do not automatically prove the same person caused them. |
| Alert review | While signed in, open an alert, select **Acknowledge**, enter a demo review note, and submit. Then **Reopen** it with another note. | Review history is retained; evidence rows and the policy snapshot stay available. |
| Detection policy | Open **Detection policy** in the sidebar. | Point out the protected path, hours, thresholds, privileged executables, and web/mail settings. This view displays the active configuration; it is not a rule editor. |

The standalone fixture produces the five alert types above. The full application also supports three **optional extension-based** rules: **Configured risky website**, **Unencrypted web visit**, and **Email to external domain**. They require the receiver, a browser or Thunderbird extension, and appropriate policy settings. Do not claim those three are generated by the basic 21-event fixture. See [application activity setup](APP_ACTIVITY.md) for the receiver/token/extension steps.

## 4. Demonstrate live features on Linux (optional)

For a real Linux demonstration, use [Linux setup](LINUX_SETUP.md) to install and load the Audit rules, configure MySQL or another selected database, and start `collect` and `inventory`. The web server, both collectors, and the optional activity receiver must use the **same database** and matching policy configuration. The dashboard remains on loopback. `collect` requires Linux audit-log access; live inventory needs Linux host access. A protected file produces an Audit event only when an applicable Audit rule is loaded.

If you are presenting the **existing Kali MySQL 8.4 installation**, follow the [start-to-finish Kali walkthrough](DEMONSTRATION_WALKTHROUGH.md). Its dashboard uses **port 5001** and has host-specific service names and paths; those commands are not fresh-install instructions. That walkthrough covers live file reads, process launches, bulk activity, a harmless privileged command, Firefox reporting, Thunderbird reporting, MySQL evidence joins, and known hardware limits. Do not disconnect a USB drive that the machine is booted from.

## 5. Quick checks and troubleshooting

- **Server will not start after creating admin:** set `KERNELGUARD_SECRET_KEY` in the server terminal; it must be at least 32 characters.
- **Data or login seems missing:** check that `KERNELGUARD_DB_URL` points to the same database used for `demo` and `create-admin`.
- **Audit collector says Not live in the standalone demo:** expected. That label only becomes active after a recent successful Linux Audit poll.
- **Web/mail list is empty:** expected in the basic fixture. Follow `APP_ACTIVITY.md` for an opt-in receiver and extensions.
- **Port conflict:** pass `serve --port 5001`, then open `http://127.0.0.1:5001/`.
- **Need a code-level check:** run `python -m pytest tests -q` from the project root in the activated environment. The separate MySQL integration test requires its own disposable test database.

KernelGuard detects configured policy matches and links them to recorded evidence. It does not block activity, prove malicious intent, or guarantee that every host action was observed.
