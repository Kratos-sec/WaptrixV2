# Requiem OWASP Assessment

Requiem is a standalone presentation demo for an OWASP Top 10 (2025) assessment platform. Its default completed assessment for `acme-corp.example` contains five assets, 65 findings, six high-severity findings, and a posture score of 42/100. Requiem’s visual design frames WAPTrix’s findings and coverage data.

Use **Demo profile** to open a completed sample immediately. All results, including those labeled with a real website as a reference, use fictional hosts under `.example`. Google contains 200 generated demo assets.

| Profile | Reference | Demo assets |
| --- | --- | ---: |
| Acme Corp | `acme-corp.example` | 5 |
| Vishwakarma University | `vupune.ac.in` | 5 |
| OWASP Juice Shop | `demo.owasp-juice.shop` | 3 |
| Flipkart | `flipkart.com` | 6 |
| Canva | `canva.com` | 5 |
| Google | `google.com` | 200 |

## Run locally

Use Node.js 22.12 or later and npm.

```text
npm ci
npm run build
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). After dependency installation, the server, UI, CLI, and exports work with a loopback connection. The demo includes its own assets and data.

Local state is written to the ignored `.demo-state/` directory. Set `REQUIEM_STATE_DIR` to a fresh directory to rehearse in a separate workspace. Set `REQUIEM_PORT` to run on a different loopback port. For development, run `npm start` in one terminal and `npm run dev` in another with the default API port.

## Presentation walkthrough

1. Start in **OWASP Top 10**. Show the score, severity and category charts, and subdomain scores. Scroll to the coverage matrix to show **Manual review** and per-host findings.
2. Select **Replay scan** and start the bundled domain discovery. **Audit workflow** shows the six stages, tool records, scope decisions, and host-filtered logs. Use the same form to replay an explicit host list.
3. In the matrix, select **A04** for **admin**. Open **TLS certificate expired or not yet valid**, then show its evidence and recommended action. The **Source** filter includes **Nuclei**. Its run history and the lookalike-domain workspace are adjacent tabs.
4. Open **Asset inventory** and select **Graph**. Open the same host to show DNS, TLS, services, application routes, tool results, and finding history.
5. In **Reports**, choose an executive or technical PDF for the engagement or a single host. The builder also exports HTML, JSON, CSV, and SARIF. **Delivery & schedule** records sample email and Slack outcomes in a local log.

Use **PQC Dashboard** to show readiness grades, application status, migration readiness, and the infrastructure charts. Select a host to update its details and recommended actions. Use its **CBOM**, **Cyber Rating**, and **Compliance Mappings** tabs for deeper views. **Rule catalog**, **Benchmark lab**, and **Settings** provide reference, evaluation, and demo account controls.

## CLI and API

Keep the local server running in a separate terminal while using the CLI.

```text
npm run cli -- demo
npm run cli -- profiles
npm run cli -- demo google
npm run cli -- audit --domain acme-corp.example --ref DEMO-2026
npm run cli -- audit --hosts admin.acme-corp.example,api.acme-corp.example --ref DEMO-HOSTS
npm run cli -- history
npm run cli -- export demo-acme-corp --format pdf --host admin.acme-corp.example
npm run cli -- benchmark
npm run cli -- help
```

The local API exposes `/api/demo`, `/api/audits`, per-audit status, logs, stop, host detail, Nuclei history and export, and catalogs under `/api/tools`, `/api/rules`, and `/api/owasp`. Host history is available at `/api/assets/<hostname>/history`. Account and delivery endpoints support the browser’s local workflows.

## Demo behavior

- Scanning, tool results, and lookalike observations come from bundled records. Each replay uses its selected demo profile. The loopback server makes no requests to target websites.
- Benchmark scores use synthetic counts for the five applications in WAPTrix’s lab inventory.
- The presenter starts with an administrator demo session. Sample accounts use addresses under `acme-corp.example` and the initial password `requiem-demo`. The preloaded IT administrator at `itadmin@acme-corp.example` uses the visible sample TOTP code `184026`. Use only demo identities and passwords.
- Report schedules are one-time local simulations. A due entry changes to **Simulated delivery** when the local log is refreshed. Email and Slack controls record the selected channels locally.

## Feature map

| Original | Carried into the demo |
| --- | --- |
| WAPTrix `backend/app/compliance` and `backend/sample_data` | Bundled audit and rule catalog from commit `a2324b3`, OWASP matrix, scores, mappings, and finding evidence |
| WAPTrix `backend/app/engine`, `backend/app/cli.py`, and `backend/app/reporting` | Simulated staged audits, local CLI and API, history, scope, filterable logs, and five export formats |
| WAPTrix `backend/app/evaluation`, `lab/`, `docker-compose.yml`, and `docker-compose.lab.yml` | Benchmark view and CLI output using sample metrics. The original checkout contains the lab definition, ground truth, Docker setup, and evaluation tooling |
| Requiem `qshield-backend/frontend` | Burgundy navigation and cream dashboard, asset list and graph, CBOM and posture, reporting, demo accounts and admin controls |
| Requiem `qshield-backend/backend/app/services` | Sample asset, port, certificate, Nuclei, lookalike, PQC and rating records in the same assessment model |

The original Requiem assistant is deferred. Run `npm test` to verify the local API, replay and persistence, all export formats, CLI, delivery log, and demo account flow.
