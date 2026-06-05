import React, { useState } from 'react';

const CFO_FIELDS = [
  { key: 'asset_identifier', label: 'Asset Identifier (IP/Hostname)', required: true },
  { key: 'weakness_name', label: 'Weakness Name', required: true },
  { key: 'weakness_description', label: 'Weakness Description', required: false },
  { key: 'weakness_source_identifier', label: 'Weakness Source ID (CVE/Plugin)', required: false },
  { key: 'original_risk_rating', label: 'Risk Rating / Severity', required: true },
  { key: 'original_detection_date', label: 'Detection Date', required: false },
  { key: 'scan_type', label: 'Scan Type (vuln/config)', required: false },
  { key: 'hardening_benchmark', label: 'Hardening Benchmark', required: false },
];

export default function FieldMapperModal({ csvHeaders, onConfirm, onCancel }) {
  const [mapping, setMapping] = useState({});

  const handleChange = (cfoField, csvColumn) => {
    setMapping((prev) => ({ ...prev, [cfoField]: csvColumn || null }));
  };

  const requiredMapped = CFO_FIELDS.filter((f) => f.required).every(
    (f) => mapping[f.key]
  );

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-[600px] max-h-[80vh] overflow-auto">
        <div className="px-6 py-4 border-b bg-fedramp-blue text-white rounded-t-lg">
          <h2 className="text-lg font-bold">Map CSV Columns to RET Fields</h2>
          <p className="text-sm text-blue-200 mt-1">
            This CSV format was not auto-detected. Map your columns to the required fields below.
          </p>
        </div>

        <div className="px-6 py-4 space-y-3">
          {CFO_FIELDS.map((field) => (
            <div key={field.key} className="flex items-center justify-between">
              <label className="text-sm font-medium text-gray-700">
                {field.label}
                {field.required && <span className="text-red-500 ml-1">*</span>}
              </label>
              <select
                className="border rounded px-3 py-1.5 text-sm w-64"
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
          ))}
        </div>

        <div className="px-6 py-4 border-t flex justify-end gap-3">
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
