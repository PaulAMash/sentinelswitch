# SentinelSwitch 2.0 artifacts

Generated deliverables of the SentinelSwitch 2.0 upgrade. Everything here is produced by the
application itself; nothing is hand-edited.

| path | produced by | contents |
| --- | --- | --- |
| `screenshots/` | `make screenshots-2` (`scripts/screenshots.py --only-2`) | genuine screenshots of the running dashboard at 1600 × 1000 CSS px (2× device scale, 3200 × 2000 files) at two workflow stages: after containment, and after the analyst decision, remediation, recovery and export |
| `reports/` | `make demo-2` / `make report` | `security-posture-report.json` (schema 2.0), `security-posture-report.html`, `security-posture-report.pdf` (when headless Chromium is available) |
| `validation/` | `make demo-2`, `scripts/test.sh` | `demo-results.json` (every workflow step with the observed counts) and `test-results.md` |

See `PORTFOLIO-PACKAGE.md` in this directory for the LinkedIn post and message drafts.
