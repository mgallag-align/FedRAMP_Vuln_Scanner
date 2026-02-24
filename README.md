# FedRAMP RET Tool

**FedRAMP 3PAO Automated Vulnerability Scan Ingestion Tool**
Risk Exposure Table (RET) Workbook v2.5 Automation

A local desktop application that automates the ingestion of vulnerability scan results and population of the FedRAMP Risk Exposure Table (RET) Workbook (SAR Appendix A). Designed exclusively for Third-Party Assessment Organizations (3PAOs) during FedRAMP initial authorization and annual assessment engagements.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| **Node.js** | 18.x or later |
| **npm** | 9.x or later (ships with Node.js) |
| **Git** | Any recent version |

### Installing Node.js

**macOS**

Option A — Homebrew (recommended):
```bash
brew install node
```

Option B — Official installer:
Download the macOS `.pkg` from [https://nodejs.org](https://nodejs.org) (LTS recommended) and run the installer.

**Windows**

Download the Windows `.msi` installer from [https://nodejs.org](https://nodejs.org) (LTS recommended) and run it. Ensure "Add to PATH" is checked during installation.

Verify your installation on either platform:
```bash
node --version
npm --version
```

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/mgallag-align/FedRAMP_Vuln_Scanner.git
cd FedRAMP_Vuln_Scanner
```

### 2. Install Dependencies

```bash
npm install
```

This installs Electron, React, Tailwind CSS, ExcelJS, xml2js, csv-parse, and all other project dependencies locally. No global installs are required.

### 3. Run in Development Mode

```bash
npm run dev
```

This starts the webpack dev server for the React renderer and launches the Electron window. The app will open automatically once the dev server is ready.

### 4. Run Directly (Production Mode)

If you have already built the renderer bundle:
```bash
npm run build:renderer
npm start
```

---

## Building Distributable Packages

### macOS (.dmg)

```bash
npm run build:mac
```

The output `.dmg` file will be in the `release/` directory. Double-click to mount and drag the app to your Applications folder.

### Windows (.exe installer)

```bash
npm run build:win
```

The output `.exe` installer will be in the `release/` directory. Run the installer and follow the prompts.

### Both Platforms

```bash
npm run build
```

> **Note:** Cross-compilation has limitations. Building a Windows `.exe` on macOS requires Wine, and building a macOS `.dmg` on Windows is not supported. Build on the target platform for best results.

---

## Usage Walkthrough

The application is a 5-step wizard. Each step must be completed before proceeding.

### Step 1 — System Information

Enter the assessment engagement details:
- **CSP Name** — Cloud Service Provider name
- **System Name** — System under assessment
- **Impact Level** — Low, Moderate, or High
- **RET Date** — Date for the RET workbook
- **ID Prefixes** — Customize the RET ID prefixes (default: VS for vulnerabilities, CF for config findings, RC for RCDT)

### Step 2 — Upload IIW

Drag and drop the **Integrated Inventory Workbook** (SSP Appendix M, `.xlsx` format). The tool parses the `Inventory` sheet and builds an asset lookup map. You will see the total asset count and any warnings about duplicate identifiers.

### Step 3 — Upload Scan Files

Drag and drop one or more vulnerability scan result files. Supported formats:

| Scanner | File Type |
|---------|-----------|
| Tenable Nessus | `.nessus` (XML) |
| Qualys | `.xml` |
| Rapid7 InsightVM | `.csv`, `.xml` |
| Prisma Cloud / Twistlock | `.json` |
| SCAP / XCCDF / STIG | `.xml` |
| Generic CSV | `.csv` (manual field mapping) |

Each file is auto-detected. If a CSV format is not recognized, a field mapping modal will open so you can map your columns to the required RET fields.

### Step 4 — Review & Resolve

A filterable, sortable table displays all parsed findings with flag indicators:
- **Green** — Clean match, authenticated scan
- **Orange** — Unauthenticated scan (results may be incomplete)
- **Red** — Asset ID not found in IIW (must be resolved before export)
- **Yellow** — Authentication status unknown

Available actions:
- Edit asset identifiers inline to resolve mismatches
- Mark findings as **RCDT** (Risks Corrected During Testing)
- Add assessor comments
- Acknowledge unauthenticated scan warnings
- Bulk select and apply actions

### Step 5 — Export

Review the summary of findings per tab, then export. The tool validates all rules (V-01 through V-08) before enabling the Export button. The output is saved as:

```
[CSP_Name]_[System_Name]_RET_[YYYY-MM-DD].xlsx
```

The exported workbook preserves the FedRAMP RET v2.5 template structure with all header/guidance rows intact.

---

## Project Structure

```
FedRAMP_Vuln_Scanner/
├── package.json                  # Dependencies and build scripts
├── webpack.renderer.config.js    # Webpack config for React renderer
├── tailwind.config.js            # Tailwind CSS theme
├── public/
│   └── index.html                # HTML shell
├── assets/
│   └── RET_template.xlsx         # (Optional) FedRAMP RET v2.5 template
├── src/
│   ├── main/
│   │   ├── main.js               # Electron main process
│   │   ├── preload.js            # Context bridge (renderer ↔ main IPC)
│   │   └── ipc-handlers.js       # IPC channel handlers
│   ├── renderer/
│   │   ├── index.jsx             # React entry point
│   │   ├── App.jsx               # Root component with wizard router
│   │   ├── store.js              # Zustand state management
│   │   ├── styles.css            # Tailwind + custom styles
│   │   ├── components/           # Shared UI components
│   │   │   ├── DropZone.jsx
│   │   │   ├── FieldMapperModal.jsx
│   │   │   ├── FlagIcon.jsx
│   │   │   ├── ProgressBar.jsx
│   │   │   ├── ScannerBadge.jsx
│   │   │   └── Stepper.jsx
│   │   └── steps/                # Wizard step components
│   │       ├── Step1SystemInfo.jsx
│   │       ├── Step2UploadIIW.jsx
│   │       ├── Step3UploadScans.jsx
│   │       ├── Step4ReviewResolve.jsx
│   │       └── Step5Export.jsx
│   ├── parsers/
│   │   ├── index.js              # Scanner detection and dispatch
│   │   ├── nessus.js             # Tenable Nessus parser
│   │   ├── qualys.js             # Qualys XML parser
│   │   ├── rapid7.js             # Rapid7 CSV/XML parser
│   │   ├── prisma.js             # Prisma Cloud / Twistlock parser
│   │   ├── scap.js               # SCAP / XCCDF / STIG parser
│   │   ├── generic-csv.js        # Generic CSV with field mapper
│   │   └── iiw.js                # IIW XLSX parser
│   ├── engine/
│   │   ├── normalizer.js         # CFO field normalization
│   │   ├── matcher.js            # Three-tier IIW asset matching
│   │   ├── classifier.js         # Finding classification
│   │   ├── id-generator.js       # RET ID sequential assignment
│   │   └── validator.js          # Pre-export validation (V-01–V-08)
│   └── export/
│       └── ret-writer.js         # RET XLSX workbook writer
```

---

## Security & Compliance

This tool is designed for air-gapped operation in FedRAMP assessment environments:

- **Zero network calls** — All outbound HTTP/HTTPS requests are blocked at the Electron session level
- **Context isolation** — Renderer process has no direct access to Node.js or the filesystem
- **No telemetry** — No crash reporting, analytics, or auto-update mechanisms
- **No persistence** — All session data is in-memory only; nothing is written to disk except the final exported XLSX to a user-chosen path
- **No remote code** — The application runs entirely from local bundled files

---

## Troubleshooting

**`npm install` fails on macOS**

If you see native module build errors, ensure Xcode Command Line Tools are installed:
```bash
xcode-select --install
```

**`npm install` fails on Windows**

If you see native module build errors, install the Windows Build Tools:
```bash
npm install --global windows-build-tools
```

Or install Visual Studio Build Tools with the "Desktop development with C++" workload.

**Electron window is blank**

Ensure the dev server is running. If using `npm run dev`, wait for the webpack compilation to finish before the Electron window loads. Check the terminal output for errors.

**Cannot drag and drop files**

On some Linux desktop environments, drag-and-drop may require running with `--no-sandbox`. On macOS and Windows this should work out of the box.

**Large scan files cause slow parsing**

The tool handles up to 10,000 findings. For very large files, parsing runs in the main process thread. If the UI freezes briefly during parse, wait for the progress bar to complete.
