# Browser and sent mail activity (opt in)

This feature uses local Firefox/Chromium and Thunderbird extensions. Linux Audit
cannot identify a visited page or a successfully sent message. The extension reports
those events to a receiver bound to `127.0.0.1:5003`; the regular dashboard remains
at `127.0.0.1:5000`. Install only for a profile you are authorized to monitor.

On the Kali MySQL 8.4 deployment, the dashboard is at `127.0.0.1:5001` and the
receiver runs as `kernelguard-mysql84-activity.service`. Its token is stored in
`/etc/kernelguard/mysql84/activity.env`; display it locally with
`sudo sed -n 's/^KERNELGUARD_ACTIVITY_TOKEN=//p' /etc/kernelguard/mysql84/activity.env`
and paste it into each extension's Options page. Check the service with
`sudo systemctl is-active kernelguard-mysql84-activity.service`.

The deployed Firefox add-on is at
`/home/kali/Desktop/KernalGuard/extensions/firefox/manifest.json`. Load it in
`about:debugging#/runtime/this-firefox` with **Load Temporary Add-on**. A visit
to `http://127.0.0.1:5001/login` reports an HTTP visit and, with the default
`alert_insecure_http` setting, produces an **Unencrypted web visit** alert.
Firefox does not report sent mail. That requires the Thunderbird extension and
a configured `trusted_email_domains` list. On this Kali host, the Thunderbird
158.0 archive is extracted at `/home/kali/Downloads/thunderbird/`, and the
deployed config uses `gmail.com` as the trusted domain. The Gmail account is
connected in Thunderbird, and the KernelGuard Sent Mail Activity add-on is
enabled in its active profile. Its private profile XPI contains the local
receiver token. Mail sent to any recipient domain outside `gmail.com` can
produce an alert. A real Thunderbird send to `geu.ac.in` was verified in MySQL: live event
`239365`, received at `2026-10-15 19:40:18 UTC` (`16 October, 01:10:18 IST`),
linked to alert `31`, **Email to external domain** (score 65). The generic
XPI for a fresh installation is in `extensions/KernelGuard-Sent-Mail.xpi`.

On this Kali host, start the Gmail profile used for live sends with
`scripts/start-thunderbird-kali.sh` (or run
`'/home/kali/Downloads/thunderbird (2)/thunderbird' --profile /home/kali/.config/thunderbird/2x4terv9.default-release-1`).
Both downloaded Thunderbird copies have separate Gmail profiles; the add-on is
installed in each. Messages sent from the Gmail website are outside the
Thunderbird add-on's scope.
In Thunderbird, open **Add-ons and Themes → KernelGuard Sent Mail Activity →
Preferences** to see the last delivery stage. `receiverResponse` with HTTP 201
means KernelGuard stored a new event; HTTP 200 means a duplicate event ID.
`beforeSend` or `afterSend` without a receiver response helps locate a failed
report. The status contains only a stage, time, recipient-domain count and HTTP
status; it does not show message content or recipient addresses.

## Configure and start

Create a random token and place it in your shell environment. Keep it outside the
repository and use the same value in each extension's Options page.

```bash
export KERNELGUARD_ACTIVITY_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export KERNELGUARD_DB_URL=sqlite:///data/kernelguard-linux.db
python -m kernelguard activity-serve
```

Start the normal dashboard separately with the same `KERNELGUARD_DB_URL` and `--config`
values. To configure alerts, create a JSON file such as:

```json
{
  "risky_web_domains": ["known-risk.example"],
  "trusted_email_domains": ["company.example"],
  "alert_insecure_http": true
}
```

Pass `--config /path/to/config.json` **before** the command to both receiver and
dashboard. Domain matching includes subdomains. HTTP visits alert by default.
The risky website list starts empty. External mail alerts start only after trusted
email domains are configured. Those alerts are review signals, not proof of harm.

## Install extensions

- Chromium: open `chrome://extensions`, enable Developer mode, choose Load unpacked,
  and select `extensions/chromium`.
- Firefox: use `about:debugging` → This Firefox → Load Temporary Add-on and select
  `extensions/firefox/manifest.json`. A temporary add-on must be loaded again after
  restart. For persistent use, package/sign it following Firefox's add-on process.
- Thunderbird 115+: open Add-ons and Themes → gear menu → Install Add-on From
  File, then select `extensions/KernelGuard-Sent-Mail.xpi`. Enable it if
  Thunderbird asks. This XPI stays installed after restart.

For a fresh installation, open the extension's Options page and paste the
receiver token. The current Thunderbird profile has already been configured
privately; its generic repository XPI has no embedded token. Restart the
receiver when you change its token. The receiver waits up to 30 seconds for a
busy database writer. The Thunderbird add-on makes up to three attempts for
network failures or HTTP 503 responses while it remains running. Events are
not saved in a persistent retry queue, so failed reports can still be lost.
The receiver's port is fixed at 5003
in these extension files; if you change the CLI port, change the URLs and host
permissions in the extensions as well.

## What is collected

- Browser: HTTP/HTTPS URL scheme, hostname and path. Query strings, fragments,
  URL credentials and page content are discarded. A visited history entry may be
  created before a page finishes loading.
- Thunderbird: recipient **domains** from `To`, `Cc` and `Bcc` for `sendNow` with
  no send error. Addresses, subject, body and attachments are not sent. Queued mail
  is not labelled as sent. This is extension reported, not mail server delivery proof.
- Event timestamps are receiver receipt times. Replayed extension event IDs are
  deduplicated. The dashboard presents these events with `app:...` identities to
  avoid claiming an OS account that the extension cannot establish.

The token is stored in the extension profile and sent only to loopback. Anyone with
access to that token can submit application events, so protect the browser profile
and rotate the token if it is exposed. Keep the receiver on loopback; it does not
offer TLS or authentication for remote connections. Local database retention follows
the existing KernelGuard database policy. URL paths can still contain private data;
limit access to the database and dashboard accordingly.
