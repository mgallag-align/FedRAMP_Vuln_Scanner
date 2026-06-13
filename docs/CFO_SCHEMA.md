# Canonical Finding Object (CFO) Schema

The **CFO** is the single internal data model that flows through the entire
pipeline: every parser emits CFOs, every `engine/` stage transforms them, the
Zustand store holds them, and `export/ret-writer.js` writes them to the RET.

**Rule:** every parser must populate *all* of the public fields below (use the
documented empty/default value when a source has no data) so downstream stages
never have to guard for missing keys. Fields prefixed with `_` are internal
(computed by engine stages / the UI) and are never written to the RET.

---

## Public fields (set by parsers)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cfo_id` | string (UUID) | — | Unique per finding. Generated with `uuid` at parse time. |
| `scanner_source` | string | — | `"<fileName> \| <Scanner>"`, e.g. `"scan.nessus \| Tenable Nessus"`. Consolidation merges multiple sources with `; `. |
| `weakness_name` | string | `''` | Short title. For compliance items, the specific check name. |
| `weakness_description` | string | `''` | Full description / diagnosis text. |
| `weakness_source_identifier` | string | `''` | CVE, Plugin ID, `QID-####`, or XCCDF rule id. **Consolidation/dedup key.** Blank ⇒ finding is never grouped. |
| `asset_identifier` | string | — | IP / hostname / asset id. Canonicalized to the IIW unique asset id after matching. May become newline-separated after CVE consolidation. |
| `original_detection_date` | string \| null | `null` | `YYYY-MM-DD`. Consolidation keeps the earliest. |
| `original_risk_rating` | enum | — | `Critical` \| `High` \| `Moderate` \| `Low` \| `Informational`. Informational is excluded from export. |
| `scan_type` | enum | `VULNERABILITY` | `VULNERABILITY` (→ RET tab) or `CONFIG_FINDING` (→ Configuration Findings tab). |
| `is_authenticated` | bool \| null | `null` | `true`/`false` from credential detection; `null` = unknown. |
| `vendor_dependency` | bool | `false` | Vendor-dependent finding. Consolidation ORs across the group. |
| `vendor_name` | string | `''` | Required by validator (V-08) when `vendor_dependency` is true. |
| `hardening_benchmark` | string | `''` | Config findings only — CIS/STIG/benchmark name. Written to Configuration Findings column S. |
| `compliance_result` | enum \| null | `null` | `PASSED` \| `FAILED` \| `WARNING` \| `ERROR` \| `SKIPPED` for compliance items; `null` for vulnerabilities. |
| `compliance_actual_value` | string | `''` | Observed value for a compliance check. |
| `compliance_policy_value` | string | `''` | Expected/required value for a compliance check. |
| `assessor_comments` | string | `''` | Free text → RET Comments column. Parsers may pre-populate (auth/compliance/fuzzy notes); the assessor edits in Step 4. |
| `ret_id` | string \| null | `null` | Assigned in Step 4 by `id-generator` (e.g. `VS-001`). One id per consolidated CVE. |
| `mark_as_rcdt` | bool | `false` | Route to the Risks Corrected During Testing tab. Set by the assessor or by rescan comparison. |

---

## Internal / computed fields (prefix `_`, never exported)

| Field | Set by | Values | Description |
|-------|--------|--------|-------------|
| `scanner_file_id` | Step 3 (renderer) | UUID | Ties a finding to its scan-file entry in the store. |
| `_auth_confidence` | parsers | `high` \| `medium` \| `manual` | Confidence of the credential detection. |
| `iiw_match_status` | `engine/matcher` | `null` \| `MATCHED` \| `UNMATCHED` \| `AMBIGUOUS` | Result of IIW matching. `null` before matching runs. |
| `_match_tier` | `engine/matcher` | `1`–`5` \| `'manual'` | Which matcher tier resolved it (1 exact id … 5 fuzzy; `manual` = assessor-resolved). |
| `_match_confidence` | `engine/matcher` | `exact` \| `composite` \| `fuzzy` \| `assessor-resolved` | Match strength. |
| `_iiw_candidates` | `engine/matcher` | object[] | Candidate IIW assets for an `AMBIGUOUS` finding; cleared on resolution. |
| `_iiw_asset_type` | `engine/matcher` | string | Asset type carried from the matched IIW row. |
| `_rcdt_reason` | `utils/rescan` | string | Why a finding was auto-marked RCDT (e.g. "Not detected in rescan"). |
| `_destination` | `engine/classifier` | `RET` \| `CONFIG` \| `RCDT` | Target export tab; `mark_as_rcdt` takes precedence over `scan_type`. |

---

## Lifecycle

```
parser ──► CFO (public fields populated, iiw_match_status=null, ret_id=null)
  │
Step 3: dedup ──► rescan comparison (sets mark_as_rcdt/_rcdt_reason)
  │
engine/matcher ──► iiw_match_status + _match_* + canonical asset_identifier
  │
Step 4: assessor edits (resolve AMBIGUOUS, acknowledge unauth, mark RCDT)
  │
engine/id-generator ──► ret_id (per consolidated CVE, per tab)
  │
engine/classifier ──► _destination
  │
export/ret-writer ──► consolidateByCVE → rows on RET / Config / RCDT tabs
```

> Consolidation and risk sorting are shared between `id-generator` and
> `ret-writer` via `engine/consolidate.js`, so IDs are assigned to exactly the
> same row groups the exporter writes — they cannot drift.
