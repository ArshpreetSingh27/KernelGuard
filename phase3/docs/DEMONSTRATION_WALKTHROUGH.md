# KernelGuard: start-to-finish demonstration

Use the **full project at http://127.0.0.1:5001/**. Phase 2 at port 5002 is a separate project/database with fewer features. These steps are for the existing Kali installation, not a fresh OS installation.

## 1. Introduce the project (30 seconds)

Say: “KernelGuard monitors selected Linux activity, process and USB inventory, and optional browser and sent-mail reports. It stores normalized events in MySQL, evaluates eight rules, and shows alerts linked to their evidence. It detects and supports investigation; it does not block attacks.”

Explain the flow:

```text
Linux Audit / inventory / browser and mail extensions
                         ↓
                 Parse and validate
                         ↓
               MySQL event + rule evaluation
                         ↓
                Alert and evidence links
                         ↓
               Dashboard and administrator review
```

## 2. Start the existing deployment

Run in a terminal:

```bash
sudo systemctl start docker
sudo docker start kernelguard-mysql84
sudo docker exec kernelguard-mysql84 mysqladmin --defaults-extra-file=/run/secrets/root-client.cnf ping
```

Wait until the last command says `mysqld is alive`, then:

```bash
sudo systemctl start auditd
sudo systemctl start kernelguard-mysql84-web.service kernelguard-mysql84-audit.service kernelguard-mysql84-inventory.service kernelguard-mysql84-activity.service
systemctl is-active kernelguard-mysql84-web.service kernelguard-mysql84-audit.service kernelguard-mysql84-inventory.service kernelguard-mysql84-activity.service
```

All four should say `active`. Open http://127.0.0.1:5001/ and sign in as `admin` with your configured password. Do not project the password on a presentation screen.

The services use `/home/kali/Desktop/KernalGuard`. The editable source is `/run/media/kali/Acer/KernalGuard`; editing the latter does not automatically deploy changes.

## 3. Explain the overview and source labels

Show the totals, security alerts, recent files, audited program launches, web/mail feed, and Audit collector panel.

- **Recorded live / Reported live:** observed by the configured source or reported by an extension.
- **Synthetic demo:** intentionally generated examples, not actual user actions.
- **Active Audit collector:** a recently completed Audit poll. It does not certify the browser or mail add-ons.
- **Latest stored event:** event time, not necessarily collection health. Clock corrections can leave older stored events with future-looking times.
- Counts change as activity continues; do not promise a fixed count.

Refresh the page after actions. Normal collection takes seconds; recovery of a backlog can take longer.

## 4. Live file activity and after-hours detection

Run as the normal Kali desktop user:

```bash
cat /srv/kernelguard/protected/demo.txt
```

Open http://127.0.0.1:5001/?kind=file_access&resource=/srv/kernelguard/protected and look for that path and the time of your action. The overview also has a dedicated **Protected file activity** card; use **All protected files →** to return to this filtered list. Open the event to show its account, successful outcome, Audit identity, and investigation context. On 21 October 2026, a real read of this file was stored as live event **554650** and created after-hours alert **62** at http://127.0.0.1:5001/alerts/62.

The configured allowed hours are 09:00–18:00 in Asia/Kolkata. Outside those hours, successful access under the protected path can create **After-hours protected access** (score 70). During allowed hours the event still appears, but this alert should not. Do not change the system clock to force a demonstration.

## 5. Program launches and process inventory

Run:

```bash
/usr/bin/sleep 20 &
```

Open http://127.0.0.1:5001/?kind=process_exec to show the launch, then Host inventory → Processes to inspect processes observed by the inventory poll.

Explain the distinction: Audit stores launch history; inventory observes processes that exist when it polls. A short-lived program can exit before inventory sees it. Not every ordinary launch generates a security alert.

If launches are missing, verify the active rule:

```bash
sudo auditctl -l | grep kernelguard_process_exec
```

## 6. Bulk protected-file activity

Prepare ten harmless files in a new subdirectory:

```bash
kg_demo_dir=$(sudo mktemp -d /srv/kernelguard/protected/viva.XXXXXX)
sudo chmod 755 "$kg_demo_dir"
for n in $(seq 1 10); do
  printf 'KernelGuard demonstration file %s\n' "$n" | sudo tee "$kg_demo_dir/file-$n.txt" >/dev/null
 done
```

Preparation can itself create events/alerts. Wait at least 60 seconds, then read the files as your ordinary desktop user:

```bash
for n in $(seq 1 10); do
  cat "$kg_demo_dir/file-$n.txt" >/dev/null
 done
```

Look for **Bulk protected-file activity** (score 70) and inspect its linked events. The rule needs ten distinct successful protected paths in 60 seconds with matching identity/session context. Reading one file ten times is not equivalent. Explain that file activity does not prove copying or exfiltration.

## 7. Sensitive privileged command

From the normal user's terminal, run the harmless help command:

```bash
sudo /usr/bin/passwd --help
```

It displays help; it does not change a password. Show **Sensitive privileged command** (score 75) and the evidence: executable `/usr/bin/passwd`, effective UID 0, and a known non-root login UID. This depends on the privileged Audit rule and a normal logged-in user session. Starting from an unrelated root/service session can fail the rule's identity conditions.

## 8. Repeated login failures

For the viva, show an existing **Repeated login failures** alert and its five linked failed authentication events. The rule groups five failures for the same attempted account within 300 seconds (score 60).

To create a fresh live alert on this host, use the disposable `kgdemo` account at the local text console:

1. Press **Ctrl+Alt+F3** to open a Linux login console.
2. Enter `kgdemo` as the username and deliberately enter an incorrect password. Repeat the failed login four more times within five minutes. Do not use your normal `kali` account.
3. Return to the desktop with **Ctrl+Alt+F7** (or the display-manager shortcut shown by the system).
4. Wait for the Audit collector, then open http://127.0.0.1:5001/?kind=login_failure#activity and refresh the alerts list. Open the new **Repeated login failures** alert and show its five linked events.

This uses the Linux `login` program, which is one of the event types KernelGuard parses. The host SSH configuration has `PasswordAuthentication no`, so an ordinary `ssh` command will not prompt for a password and will not create this alert. Incorrect dashboard passwords are also web-authentication events, not Linux `USER_AUTH` records. If the console account is subject to a lockout policy, stop after the policy limit and use the existing live alert 58 for the viva instead.

## 9. Host inventory: users, sessions, processes, USB

Open http://127.0.0.1:5001/inventory and visit each tab:

| Tab | Show and explain |
| --- | --- |
| Users | Observed OS account identity and last observation. |
| Sessions | Login/session information; not a complete screen-activity recording. |
| Processes | PID, observed executable, user/session and parent information where available. |
| USB devices | Device identity, presence, connection-observed time, last seen, approval status. |

Open a device's detail page. Explain:

- Connection time is when KernelGuard observed the connection, potentially after the physical plug-in.
- First seen, latest connection observed, and last seen mean different things.
- A new or reappearing unapproved identity can generate **Unapproved USB device** (score 65).
- Approval changes the policy for future observations; it does not erase historical alerts.
- The approve/revoke controls keep a decision history. Use only a device you intend to approve, with an honest note.

You currently have no separate expendable USB device. Show existing device evidence and explain the physical unplug/replug test is unverified. **Do not disconnect the Cruzer Blade used to boot Kali.** If you later obtain a spare device, connect it, wait for inventory, inspect its event/alert, approve it if appropriate, and demonstrate a reconnect and decision history.

## 10. Firefox web reporting

In Firefox:

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on**.
3. Select `/home/kali/Desktop/KernalGuard/extensions/firefox/manifest.json`.
4. If the receiver token is not already configured, open the extension options and paste the local token privately, as described in `APP_ACTIVITY.md`.
5. Visit **http://127.0.0.1:5001/login** in that Firefox profile.
6. Open http://127.0.0.1:5001/?kind=web_visit to show the reported URL and source.

With the default policy, that HTTP visit can produce **Unencrypted web visit** (score 45). HTTPS does not trigger the plain-HTTP rule. A temporary Firefox add-on must be loaded again after restarting Firefox.

The **Configured risky website** rule (score 70) needs a domain in `risky_web_domains`. The current live list is empty, so use the existing synthetic risky-site alert to explain it. Do not visit a real dangerous website for this demonstration. A hostname match can include subdomains. Risky-site matching takes precedence over the HTTP rule on the same report.

Only scheme, hostname and path are stored; not page contents, query strings, URL credentials or fragments. Browser reporting does not independently prove a page fully loaded.

## 11. Thunderbird mail reporting

Start the configured profile:

```bash
/home/kali/Desktop/KernalGuard/scripts/start-thunderbird-kali.sh
```

Or use the **Thunderbird (KernelGuard)** desktop launcher. In Thunderbird, verify **KernelGuard Sent Mail Activity** is enabled under Add-ons and Themes.

1. Send a short message from Thunderbird to an address you own or a consenting recipient outside `gmail.com`.
2. Wait for processing, then open http://127.0.0.1:5001/?kind=email_sent.
3. Show the recipient domain and live source label.
4. Open the linked **Email to external domain** alert (score 65).
5. Explain the negative case: a message to `gmail.com` is still recorded, but Gmail is trusted and does not trigger this external-domain rule.

A real send to `geu.ac.in` was verified as event **239365**, linked to alert **31**: http://127.0.0.1:5001/alerts/31. Use that evidence if you do not want to send another message during the viva.

This feature observes Thunderbird sends, not Gmail sends in Firefox. It stores recipient domains, not full addresses, subject, body or attachments. It does not prove inbox delivery. Queued mail is not presented as a successful immediate send.

In add-on Preferences, the delivery status helps diagnose problems: `receiverResponse` 201 means a new stored event; 200 means an already-seen event ID. Network failures/503 are retried up to three times while the add-on runs; there is no persistent retry queue.

## 12. Event explorer and investigation timeline

Use event-kind, account and resource filters in the Event explorer. Show an individual event and its nearby timeline. Explain that nearby time and host activity gives context, not proof that the same person caused every event. Browser/mail labels identify the reporting application, not a verified OS user.

Use live/demo alert filters to distinguish real observations from test examples. Inventory also has source and host filters. Open a larger list and show pagination where available.

## 13. Alert review workflow

Open an alert and show:

1. Rule name, score, reason and source label.
2. Exact supporting event rows.
3. Saved policy parameters used for that alert.
4. Existing review history.

For an alert you have actually reviewed, choose **Acknowledge**, enter a note such as “Reviewed during PBL demonstration; expected test activity”, and submit. Show the new history entry. Reopen it if you want to demonstrate that action, using an explanatory note. These actions change review state; they do not delete evidence. Scores are configured severity values, not probabilities of malicious intent.

## 14. Detection policy

Show the dashboard Detection policy section. Point out the protected path, allowed hours, thresholds and sensitive executables. Explain these are configuration-driven rules. Do not claim the dashboard has a rule editor if it only displays settings.

The eight rules are: repeated login failures, after-hours access, bulk protected-file activity, sensitive privileged command, unapproved USB, configured risky website, unencrypted web visit, and external-domain mail.

## 15. Show the actual MySQL database

Open a terminal:

```bash
sudo docker exec -it kernelguard-mysql84 mysql --defaults-extra-file=/run/secrets/root-client.cnf kernelguard84
```

At `mysql>`:

```sql
SELECT VERSION(), DATABASE(), UTC_TIMESTAMP();
SHOW TABLES;
SELECT origin, kind, COUNT(*) AS records
FROM events GROUP BY origin, kind ORDER BY origin, kind;

SELECT id, origin, kind, resource, FROM_UNIXTIME(timestamp) AS db_session_time
FROM events ORDER BY id DESC LIMIT 10;

SELECT a.id AS alert_id, a.rule, a.score,
       e.id AS event_id, e.origin, e.kind, e.resource
FROM alerts a
JOIN alert_events ae ON ae.alert_id = a.id
JOIN events e ON e.id = ae.event_id
WHERE a.id = 31;

SELECT value FROM checkpoints WHERE name = 'collector_health';
```

Explain that events are the observations, alerts are rule matches, and `alert_events` links alerts to evidence. `FROM_UNIXTIME` uses the database session timezone; compare with `UTC_TIMESTAMP()` and the displayed timezone instead of assuming IST. Type `exit;` to leave MySQL.

## 16. Tests and evidence of correctness

```bash
cd /run/media/kali/Acer/KernalGuard
.venv-linux/bin/python -m pytest tests -q
```

Explain what passed, failed or skipped in the actual output. The opt-in MySQL integration test needs a separate disposable test database; do not point it at the live schema. On 16 October, the focused pipeline suite passed 31 tests after the checkpoint recovery fix. That result is not a claim that every hardware scenario has been exercised.

The existing detailed viva reference is `docs/PBL_VIVA_COMPLETE_GUIDE.md`; use it for schema, module and rule explanations.

## 17. Optional Phase 2 comparison

Open http://127.0.0.1:5002/ only when comparing versions. Explain that Phase 2 has its own database, two rules, and no USB inventory. Return to port 5001 for the full-feature demonstration. Do not interpret Phase 2 counts as full-project counts.

## 18. If Audit collector says “Not live”

Check both service status and recent successful polls:

```bash
sudo systemctl status kernelguard-mysql84-audit.service --no-pager
sudo journalctl -u kernelguard-mysql84-audit.service -n 30 --no-pager
```

`active` from systemd alone does not prove fresh data. The UI expects a recent completed poll. The collector now retries ausearch checkpoint errors 10/11/12 using its documented timestamp recovery. Retained backlog can take time to process; deleted logs cannot be recovered. Do not delete the database or all checkpoints to remove the warning.

If only mail/web is missing, check the activity receiver and relevant extension, because those sources run separately from Audit. If a source is unavailable, show labelled existing evidence and explain the limitation.

## Suggested presentation order

For 15–20 minutes: introduction → services/login → overview/source labels → live file and process action → alert evidence/review → inventory/USB → Firefox → Thunderbird → MySQL JOIN → tests and limitations.

For a short viva: introduction → live file event → one alert with evidence → mail event 239365/alert 31 → MySQL JOIN → limitations.

Closing statement: “We can demonstrate live observation, rule-based alerts, persistent evidence and review history. Polling, configured audit coverage, extension availability and device access determine what is observed. This is not complete surveillance, attribution or attack prevention.”
