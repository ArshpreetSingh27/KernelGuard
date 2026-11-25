# Complete project file distribution

This is a **maintenance and viva explanation allocation**, not a claim about who
originally authored each file. Keep files in their current functional directories:
moving Python modules, templates, extensions, or service files into member folders
would break imports or deployment paths. Shared integration and generated artifacts
are listed separately below.

## Arshpreet Singh — Linux collection and host observation

| Area | Primary files |
| --- | --- |
| Audit and inventory collection | `kernelguard/parser.py`, `kernelguard/locking.py`, `kernelguard/inventory/__init__.py`, `kernelguard/inventory/models.py`, `kernelguard/inventory/collector.py` |
| Browser and mail collection | `extensions/chromium/background.js`, `extensions/chromium/manifest.json`, `extensions/chromium/options.html`, `extensions/chromium/options.js`, `extensions/firefox/background.js`, `extensions/firefox/manifest.json`, `extensions/firefox/options.html`, `extensions/firefox/options.js`, `extensions/thunderbird/background.js`, `extensions/thunderbird/manifest.json`, `extensions/thunderbird/options.html`, `extensions/thunderbird/options.js` |
| Linux rules and services | `linux/kernelguard.rules`, `linux/activity-observation-kali.rules`, `linux/services/kernelguard-audit.service`, `linux/services/kernelguard-inventory.service`, `linux/services/kernelguard-inventory-kali.service` |
| Fixtures, setup and checks | `fixtures/inventory.json`, `scripts/check_environment.py`, `scripts/start-thunderbird-kali.sh`, `docs/LINUX_SETUP.md`, `docs/LIVE_AUDIT_CHECK.md`, `docs/APP_ACTIVITY.md`, `docs/ARSHPREET_WORK.md` |

Arshpreet explains Audit records, identity fields, boot and process identity,
snapshot completeness, USB sampling, and how the optional extensions collect
limited application metadata. The activity receiver and policy decisions are
shared with Ankit and Ahmed.

## Mohd Ahmed Khan — database, persistence and integration

| Area | Primary files |
| --- | --- |
| Core data and startup | `kernelguard/core.py`, `kernelguard/__main__.py`, `kernelguard/config.py`, `kernelguard/inventory/schema.py`, `kernelguard/inventory/service.py` |
| SQL and database setup | `sql/schema.mysql.sql`, `sql/analysis.sql`, `scripts/export_schema.py`, `docs/MYSQL84_DOCKER.md` |
| Database tests | `tests/test_mysql.py`, `tests/test_concepts.py` |

Ahmed explains the schema, foreign keys, transactions, replay protection,
writer integration, MySQL/SQLite differences, and how the CLI connects the
collectors, rules and web server. Rule-specific logic in `core.py` and
`inventory/service.py` is shared with Ankit.

## Ankit — detection rules and evaluation

| Area | Primary files |
| --- | --- |
| Rules and activity receiver | `kernelguard/activity_rules.py`, `kernelguard/app_activity.py`, `kernelguard/demo.py`, `linux/privileged-execution.rules`, `linux/services/kernelguard-mysql84-activity.service` |
| Evaluation fixtures and scripts | `fixtures/demo.audit`, `scripts/evaluate.py`, `scripts/make_fixture.py`, `docs/EVALUATION.md`, `docs/evaluation.json` |
| Rule and activity tests | `tests/test_pipeline.py`, `tests/test_alert_sources.py`, `tests/test_app_activity.py` |

Ankit explains thresholds, the eight policy matches, alert evidence, false
positives, synthetic evaluation, and the application-activity receiver's
validation. The receiver's database transaction is shared with Ahmed; the
extensions that send its input are assigned to Arshpreet.

## Mohd Shoaib — dashboard, authentication and review

| Area | Primary files |
| --- | --- |
| Web logic | `kernelguard/web.py`, `kernelguard/auth.py`, `kernelguard/reviews.py`, `kernelguard/investigation.py`, `kernelguard/inventory/routes.py` |
| Templates and assets | `kernelguard/templates/base.html`, `kernelguard/templates/dashboard.html`, `kernelguard/templates/events.html`, `kernelguard/templates/alert.html`, `kernelguard/templates/inventory.html`, `kernelguard/templates/device.html`, `kernelguard/templates/login.html`, `kernelguard/templates/investigation.html`, `kernelguard/refresh.js`, `kernelguard/static/style.css` |
| Web service and launchers | `linux/services/kernelguard-web.service`, `scripts/start.ps1`, `scripts/start-demo.ps1`, `docs/OPERATIONS.md`, `docs/SERVICES.md` |
| UI and review tests | `tests/test_activity_reviews.py`, `tests/test_investigation.py` |

Shoaib explains authentication, CSRF, dashboard queries, evidence timelines,
alert reviews and USB enrollment history. Inventory queries share schema
knowledge with Ahmed.

## Shared integration and presentation files

| Files | Responsibility |
| --- | --- |
| `README.md`, `docs/ARCHITECTURE.md`, `docs/ACCEPTANCE.md`, `docs/FILE_GUIDE.md`, `docs/ORIGINALITY_AND_ATTRIBUTION.md`, `docs/DEMONSTRATION_WALKTHROUGH.md`, `docs/PBL_VIVA_COMPLETE_GUIDE.md` | All four members should review and explain the parts related to their work. |
| `config.example.json`, `requirements.txt`, `kernelguard/__init__.py`, `tests/__init__.py`, `pytest.ini`, `.gitignore` | Shared project configuration and package/test plumbing. |
| `tests/test_inventory.py` | Arshpreet: input and collection; Ahmed: storage and transactions; Ankit: USB alert behavior; Shoaib: inventory and enrollment UI. |
| `docs/contributions/README.md`, `docs/contributions/ARSHPREET.md`, `docs/contributions/AHMED.md`, `docs/contributions/ANKIT.md`, `docs/contributions/SHOAIB.md`, this file | Team allocation record; each member reviews their own section. |
| `docs/reference/` | Historical design and handover notes for the whole team. |
| `deliverables/` | Reports and presentations for the team; final documents should be reviewed by all members. |

Local databases and virtual environments in `data/`, `.venv/` and `.venv-linux/`,
generated output in `output/` and `tmp/`, caches, and packaged extension builds
are runtime or generated artifacts. They are not separate authored source modules.
