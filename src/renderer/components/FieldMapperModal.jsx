import React, { useState, useMemo } from 'react';
import useStore from '../store';

const CFO_FIELDS = [
  {
    key: 'asset_identifier',
    label: 'Asset Identifier',
    required: true,
    tooltip: 'IP address, hostname, or IIW unique asset ID that identifies the affected system',
  },
  {
    key: 'weakness_name',
    label: 'Weakness Name',
    required: true,
    tooltip: 'Short title of the vulnerability or configuration finding (appears in RET column D)',
  },
  {
    key: 'weakness_description',
    label: 'Weakness Description',
    required: false,
    tooltip: 'Detailed description — written to the RET Description column (E)',
  },
  {
    key: 'weakness_source_identifier',
    label: 'Weakness Source ID (CVE / Plugin)',
    required: false,
    tooltip: 'CVE ID, Plugin ID, QID, or other scanner identifier — used for deduplication and linking',
  },
  {
    key: 'original_risk_rating',
    label: 'Risk Rating / Severity',
    required: true,
    tooltip:
      'Severity level. Accepts: Critical, High, Moderate/Medium, Low, Info/Informational, None, Untriaged, CVSS scores (e.g. 7.5), or numeric scales 1–5',
  },
  {
    key: 'original_detection_date',
    label: 'Detection Date',
    required: false,
    tooltip: 'Date the finding was first detected. Most date formats accepted.',
  },
  {
    key: 'scan_type',
    label: 'Scan Type (vuln / config)',
    required: false,
    tooltip:
      'Column whose value indicates compliance/config findings (e.g. "Policy", "Config"). Rows containing "config" or "compliance" route to the Configuration Findings tab.',
  },
  {
    key: 'hardening_benchmark',
    label: 'Hardening Benchmark',
    required: false,
    tooltip: 'CIS Benchmark, STIG, or other hardening standard reference (Config Findings tab, Column S)',
  },
];

// Pre-built column mapping templates for common scanner CSV exports.
// `detect` receives normalized (lowercased) header list and returns true when
// the template matches the file. Matching template is auto-applied on open.
const BUILTIN_TEMPLATES = [
  {
    name: 'Nessus CSV',
    detect: (lh) =>
      lh.includes('plugin id') && (lh.includes('host') || lh.includes('ip address')),
    mappings: {
      asset_identifier: 'Host',
      weakness_name: 'Plugin Name',
      weakness_description: 'Description',
      weakness_source_identifier: 'Plugin ID',
      original_risk_rating: 'Risk',
      original_detection_date: 'First Detected',
    },
  },
  {
    name: 'Qualys VM CSV',
    detect: (lh) =>
      (lh.includes('qid') || lh.includes('vuln id')) && lh.includes('ip'),
    mappings: {
      asset_identifier: 'IP',
      weakness_name: 'Title',
      weakness_description: 'Diagnosis',
      weakness_source_identifier: 'QID',
      original_risk_rating: 'Severity',
      original_detection_date: 'First Detected',
    },
  },
  {
    name: 'Burp Suite',
    detect: (lh) =>
      lh.includes('issue name') && (lh.includes('host') || lh.includes('url')),
    mappings: {
      asset_identifier: 'Host',
      weakness_name: 'Issue Name',
      weakness_description: 'Issue Detail',
      weakness_source_identifier: 'Issue Type ID',
      original_risk_rating: 'Severity',
    },
  },
  {
    name: 'AWS Inspector',
    detect: (lh) =>
      lh.includes('finding arn') ||
      (lh.includes('aws account id') && lh.includes('title')),
    mappings: {
      asset_identifier: 'Resource ID',
      weakness_name: 'Title',
      weakness_description: 'Description',
      weakness_source_identifier: 'Finding ARN',
      original_risk_rating: 'Severity',
      original_detection_date: 'First Observed At',
    },
  },
];

/**
 * Resolve template mappings against available CSV headers.
 * Tries exact match first, falls back to case-insensitive comparison.
 */
function resolveMapping(templateMappings, availableHeaders) {
  const result = {};
  const lowerHeaders = availableHeaders.map((h) => h.toLowerCase());

  for (const [field, targetCol] of Object.entries(templateMappings)) {
    if (availableHeaders.includes(targetCol)) {
      result[field] = targetCol;
    } else {
      const idx = lowerHeaders.indexOf(targetCol.toLowerCase());
      if (idx >= 0) result[field] = availableHeaders[idx];
    }
  }
  return result;
}

export default function FieldMapperModal({ csvHeaders, prevMapping, onConfirm, onCancel }) {
  const mapperTemplates = useStore((s) => s.mapperTemplates);
  const saveMapperTemplate = useStore((s) => s.saveMapperTemplate);

  const lowerHeaders = useMemo(() => csvHeaders.map((h) => h.toLowerCase()), [csvHeaders]);

  // Auto-detect the first matching built-in template
  const autoTemplate = useMemo(
    () => BUILTIN_TEMPLATES.find((t) => t.detect(lowerHeaders)) ?? null,
    [lowerHeaders]
  );

  const [mapping, setMapping] = useState(() =>
    autoTemplate ? resolveMapping(autoTemplate.mappings, csvHeaders) : {}
  );
  const [showRequiredOnly, setShowRequiredOnly] = useState(false);
  const [showSaveTemplate, setShowSaveTemplate] = useState(false);
  const [templateName, setTemplateName] = useState('');

  const handleChange = (cfoField, csvColumn) => {
    setMapping((prev) => {
      const next = { ...prev };
      if (csvColumn) next[cfoField] = csvColumn;
      else delete next[cfoField];
      return next;
    });
  };

  const applyBuiltin = (template) => {
    setMapping(resolveMapping(template.mappings, csvHeaders));
  };

  const applySaved = (name) => {
    const t = mapperTemplates.find((x) => x.name === name);
    if (t) setMapping(resolveMapping(t.mappings, csvHeaders));
  };

  const handleSaveTemplate = () => {
    const name = templateName.trim();
    if (!name) return;
    saveMapperTemplate({ name, mappings: { ...mapping } });
    setTemplateName('');
    setShowSaveTemplate(false);
  };

  const unmappedRequired = CFO_FIELDS.filter((f) => f.required && !mapping[f.key]);
  const requiredMapped = unmappedRequired.length === 0;
  const visibleFields = showRequiredOnly ? CFO_FIELDS.filter((f) => f.required) : CFO_FIELDS;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-[660px] max-h-[92vh] flex flex-col">

        {/* Header */}
        <div className="px-6 py-4 border-b bg-fedramp-blue text-white rounded-t-lg flex-shrink-0">
          <h2 className="text-lg font-bold">Map Columns to RET Fields</h2>
          <p className="text-sm text-blue-200 mt-0.5">
            {autoTemplate
              ? `Auto-detected: ${autoTemplate.name} — verify or adjust mappings below`
              : 'Select a template or map columns manually to the required fields'}
          </p>
        </div>

        {/* Template bar */}
        <div className="px-6 py-2.5 border-b bg-gray-50 flex-shrink-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-medium text-gray-500 mr-1">Quick-fill:</span>
            {BUILTIN_TEMPLATES.map((t) => (
              <button
                key={t.name}
                onClick={() => applyBuiltin(t)}
                title={`Apply ${t.name} column mapping`}
                className={`text-xs px-2.5 py-1 rounded border transition-colors ${
                  autoTemplate?.name === t.name
                    ? 'border-fedramp-blue bg-blue-50 text-fedramp-blue font-semibold'
                    : 'border-gray-300 text-gray-600 hover:border-fedramp-blue hover:text-fedramp-blue'
                }`}
              >
                {t.name}
              </button>
            ))}
            {mapperTemplates.length > 0 && (
              <select
                className="text-xs border rounded px-2 py-1 text-gray-600 bg-white ml-1"
                value=""
                onChange={(e) => applySaved(e.target.value)}
              >
                <option value="">Saved templates…</option>
                {mapperTemplates.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.name}
                  </option>
                ))}
              </select>
            )}
            {prevMapping && (
              <button
                onClick={() => setMapping(resolveMapping(prevMapping, csvHeaders))}
                className="text-xs px-2.5 py-1 rounded border border-dashed border-gray-400 text-gray-600 hover:border-fedramp-blue hover:text-fedramp-blue ml-1"
                title="Re-apply the mapping used for the previous file in this session"
              >
                ↩ Previous mapping
              </button>
            )}
          </div>
        </div>

        {/* Controls bar */}
        <div className="px-6 py-2 border-b bg-gray-50 flex items-center justify-between flex-shrink-0">
          <label className="flex items-center gap-1.5 text-xs text-gray-600 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showRequiredOnly}
              onChange={(e) => setShowRequiredOnly(e.target.checked)}
              className="rounded"
            />
            Required fields only
          </label>
          {!requiredMapped && (
            <span className="text-xs text-red-600 font-medium">
              Missing: {unmappedRequired.map((f) => f.label).join(', ')}
            </span>
          )}
        </div>

        {/* Mapping rows */}
        <div className="px-6 py-4 space-y-3 overflow-auto flex-1">
          {visibleFields.map((field) => {
            const isMapped = !!mapping[field.key];
            return (
              <div key={field.key} className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-1.5 min-w-0 flex-1">
                  <span className="text-sm font-medium text-gray-700 truncate">
                    {field.label}
                  </span>
                  {field.required && (
                    <span
                      className={`text-sm font-bold flex-shrink-0 ${
                        isMapped ? 'text-green-500' : 'text-red-500'
                      }`}
                    >
                      {isMapped ? '✓' : '*'}
                    </span>
                  )}
                  <span
                    className="text-gray-400 text-xs cursor-help flex-shrink-0"
                    title={field.tooltip}
                  >
                    ⓘ
                  </span>
                </div>
                <select
                  className={`border rounded px-3 py-1.5 text-sm w-60 flex-shrink-0 ${
                    field.required && !isMapped ? 'border-red-300 bg-red-50' : ''
                  }`}
                  value={mapping[field.key] || ''}
                  onChange={(e) => handleChange(field.key, e.target.value)}
                >
                  <option value="">— Select column —</option>
                  {csvHeaders.map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </select>
              </div>
            );
          })}
        </div>

        {/* Save template row */}
        <div className="px-6 py-2.5 border-t bg-gray-50 flex-shrink-0">
          {showSaveTemplate ? (
            <div className="flex items-center gap-2">
              <input
                type="text"
                className="flex-1 text-sm border rounded px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-fedramp-blue"
                placeholder="Template name (e.g. Nessus Weekly)"
                value={templateName}
                autoFocus
                onChange={(e) => setTemplateName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSaveTemplate()}
              />
              <button
                onClick={handleSaveTemplate}
                disabled={!templateName.trim()}
                className="text-xs px-3 py-1.5 bg-fedramp-blue text-white rounded hover:bg-blue-800 disabled:opacity-40"
              >
                Save
              </button>
              <button
                onClick={() => setShowSaveTemplate(false)}
                className="text-xs text-gray-500 hover:text-gray-700"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setShowSaveTemplate(true)}
              className="text-xs text-fedramp-blue hover:underline"
            >
              + Save current mapping as template
            </button>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t flex justify-end gap-3 flex-shrink-0">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm border rounded hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm(mapping)}
            disabled={!requiredMapped}
            className="px-4 py-2 text-sm bg-fedramp-blue text-white rounded hover:bg-blue-800 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Apply Mapping
          </button>
        </div>
      </div>
    </div>
  );
}
