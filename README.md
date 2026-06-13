# FedRAMP RET Tool

Desktop application for 3PAO assessors that automates ingestion of vulnerability
scan results into the FedRAMP **Risk Exposure Table (RET) Workbook v2.5**.

Drop in scan output from common scanners, cross-reference findings against the
Integrated Inventory Workbook (IIW), review and resolve in a guided wizard, and
export a populated RET XLSX — all **fully offline**. The app makes zero network
calls at runtime and is designed to run in air-gapped assessment environments.

---

## Features

- **Multi-scanner ingestion** — Tenable Nessus (`.nessus`/XML), Qualys (XML),
  Rapid7 InsightVM (XML/CSV), Prisma Cloud/Twistlock (JSON), SCAP/XCCDF/STIG
  (XML), plus any CSV/XLSX/JSON via a manual field mapper.
- **Authentication detection** — multi-tier per-host credential analysis with a
  confidence rating and per-host evidence trail.
- **IIW asset matching** — 5-tier matcher (exact ID/IP/DNS → composite → fuzzy)
  with an `AMBIGUOUS` state the assessor resolves inline.
- **Inventory coverage** — per-scanner authenticated% and IIW coverage%, plus a
  list of inventory assets not reached by any scan.
- **Compliance scans** — extracts pass/fail/warning results, routes config
  findings to the Configuration Findings tab, auto-creates the CM-6 roll-up row.
- **Rescans** — mark a file as a rescan; findings dropped since the baseline are
  auto-marked Corrected During Testing (RCDT).
- **Parse-failure recovery** — friendly modal with "Retry with Field Mapper" /
  "Skip", plus a local error log (air-gap safe).
- **Validation gate** — pre-export checks (V-01…V-08) block or warn before export.

---

## Architecture

Electron app with a hard main/renderer split. The renderer never touches the
filesystem or Node APIs directly — everything goes through the preload bridge.

```
src/
  main/            Electron main process (Node)
    main.js          Window creation + security hardening (sandbox, no network)
    preload.js       contextBridge API exposed to the renderer
    ipc-handlers.js  ipcMain handlers: parse, match, validate, export, dialogs
    error-log.js     Append-only local parse-error log (userData/logs)
  parsers/         Pure parsing → Canonical Finding Objects (CFOs)
    index.js         detectAndParse(): format detection + dispatch
    nessus.js qualys.js rapid7.js prisma.js scap.js   scanner parsers
    iiw.js           Integrated Inventory Workbook (header-detecting)
    generic-csv.js   field-mapper-driven CFO builder
    csv-sections.js universal-parser.js   tabular helpers
  engine/          Pure transforms over CFOs
    matcher.js       5-tier IIW asset matching
    classifier.js    CFO → destination tab (RET / CONFIG / RCDT)
    id-generator.js  sequential RET/POA&M ID assignment
    validator.js     pre-export validation (V-01…V-08)
    consolidate.js   shared CVE consolidation + risk sorting
    severity.js      shared CVSS / severity normalization
    normalizer.js    field normalization helpers
  export/
    ret-writer.js    writes the populated RET v2.5 XLSX (ExcelJS)
  renderer/        React UI (Zustand store, no Node access)
    steps/           Step1…Step5 wizard
    components/      FieldMapperModal, ParseErrorModal, FlagIcon, etc.
    utils/           coverage.js, rescan.js (browser-safe ES modules)
    store.js         Zustand session state
tests/
  qa-harness.js    Standalone QA suite (npm test)
```

The central data structure is the **Canonical Finding Object (CFO)** — every
parser emits CFOs, every engine stage transforms them, and the exporter writes
them. Its schema is documented in [`docs/CFO_SCHEMA.md`](docs/CFO_SCHEMA.md).

### Wizard flow

1. **System Info** — CSP/system name, impact level, RET date, ID prefixes.
2. **Upload IIW** — parse the Integrated Inventory Workbook into the asset list.
3. **Upload Scans** — drop scan files; per-file scan type + rescan flag.
   On *Next*: dedup → (rescan comparison) → IIW asset matching → coverage.
4. **Review & Resolve** — filter/triage findings, resolve ambiguous matches,
   acknowledge unauthenticated scans, mark RCDT. IDs assigned on *Next*.
5. **Export** — validation gate, then write the populated RET XLSX.

---

## Air-gap / security posture

- `BrowserWindow` runs with `sandbox: true`, `contextIsolation: true`,
  `nodeIntegration: false`, `webSecurity: true` (`src/main/main.js`).
- All outbound network requests are cancelled; only `file:`/localhost load.
- External navigation and `window.open` are blocked; permission requests denied.
- No telemetry, no auto-update, no runtime network dependency.

---

## Develop / build / run

Requires Node.js 18+ and npm.

```bash
npm install          # install dependencies

npm run dev          # webpack-dev-server + Electron (hot reload)
npm start            # run Electron against the last built renderer

npm run build:renderer   # production renderer bundle → dist/
npm run build:win        # Windows NSIS installer
npm run build:mac        # macOS DMG
npm run build            # both (requires platform toolchains)

npm test             # run the QA harness (tests/qa-harness.js)
```

> The macOS DMG step requires `dmg-license` and only builds on macOS; on Linux
> use `build:win` or `build:renderer`.

---

## Testing

There is no third-party test runner — `tests/qa-harness.js` is a dependency-free
Node script (uses `@babel/core`, already a dev dependency, to load the ESM
renderer utils). Run with `npm test`. It covers the engine (matcher, classifier,
id-generator, validator, consolidate, severity), the parsers (Nessus compliance
extraction, Qualys/SCAP/Rapid7/Prisma, IIW header detection), the renderer utils
(coverage, rescan), and a full RET export round-trip that reads the written XLSX
back and asserts its contents.

When changing parser or engine logic, add a check to the relevant section of the
harness and keep it green.

---

## Adding a new scanner parser

1. Create `src/parsers/<scanner>.js` exporting an async parse function that
   returns CFOs (see [`docs/CFO_SCHEMA.md`](docs/CFO_SCHEMA.md) for the exact
   field shape — every field must be present so downstream stages are uniform).
   Use the shared `engine/severity.js` mappers; do not re-implement CVSS logic.
2. Wire detection + dispatch into `detectAndParse` in `src/parsers/index.js`.
   Host-based scanners should also return `authStatusByHost` and route through a
   `handle<Scanner>Result` helper so authentication summaries are computed.
3. Add a functional parse test (and a CFO-shape assertion) to
   `tests/qa-harness.js`.
