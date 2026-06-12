import React, { useState, useCallback, useEffect } from 'react';
import useStore from '../store';

export default function Step5Export() {
  const findings = useStore((s) => s.findings);
  const systemInfo = useStore((s) => s.systemInfo);
  const iiwAssets = useStore((s) => s.iiwAssets);
  const scanFiles = useStore((s) => s.scanFiles);
  const coverage = useStore((s) => s.coverage);
  const unauthAcknowledged = useStore((s) => s.unauthAcknowledged);
  const getExportSummary = useStore((s) => s.getExportSummary);
  const setProgress = useStore((s) => s.setProgress);
  const prevStep = useStore((s) => s.prevStep);

  const [validationErrors, setValidationErrors] = useState([]);
  const [validationWarnings, setValidationWarnings] = useState([]);
  const [overrideWarnings, setOverrideWarnings] = useState(false);
  const [exportStatus, setExportStatus] = useState(null); // null | 'exporting' | 'success' | 'error'
  const [exportPath, setExportPath] = useState('');
  const [exportError, setExportError] = useState('');

  const summary = getExportSummary();

  // Run validation
  useEffect(() => {
    const sessionData = {
      systemInfo,
      findings: findings.filter((f) => f.original_risk_rating !== 'Informational'),
      iiwAssets,
      scanFiles,
      unauthAcknowledged: Array.from(unauthAcknowledged),
    };

    window.electronAPI.validateExport(sessionData).then((result) => {
      setValidationErrors(result.errors || []);
      setValidationWarnings(result.warnings || []);
      setOverrideWarnings(false);
    });
  }, [findings, systemInfo, iiwAssets, scanFiles, unauthAcknowledged]);

  const hasErrors = validationErrors.length > 0;
  const hasWarnings = validationWarnings.length > 0;
  const canExport = !hasErrors && (!hasWarnings || overrideWarnings);

  const handleExport = useCallback(async () => {
    // Default filename
    const csp = systemInfo.cspName.replace(/\s+/g, '_');
    const sys = systemInfo.systemName.replace(/\s+/g, '_');
    const date = systemInfo.retDate; // YYYY-MM-DD from input
    const defaultName = `${csp}_${sys}_RET_${date}.xlsx`;

    const savePath = await window.electronAPI.saveFileDialog({
      defaultPath: defaultName,
    });

    if (!savePath) return;

    setExportStatus('exporting');
    setProgress({ message: 'Exporting RET workbook...', percent: 0, visible: true });

    try {
      const sessionData = {
        systemInfo,
        findings: findings.filter((f) => f.original_risk_rating !== 'Informational'),
        iiwAssets,
        scanFiles,
        coverage: coverage || null,
      };

      const result = await window.electronAPI.exportRET(sessionData, savePath);

      if (result.success) {
        setExportStatus('success');
        setExportPath(result.path);
      } else {
        setExportStatus('error');
        setExportError(result.error);
      }
    } catch (err) {
      setExportStatus('error');
      setExportError(err.message);
    } finally {
      setProgress({ message: '', percent: 0, visible: false });
    }
  }, [systemInfo, findings, iiwAssets, scanFiles, setProgress]);

  return (
    <div className="max-w-2xl mx-auto">
      <h2 className="text-xl font-bold text-fedramp-blue mb-1">Step 5: Export RET Workbook</h2>
      <p className="text-sm text-gray-500 mb-6">
        Review the summary below and export the populated RET XLSX.
      </p>

      {/* Summary */}
      <div className="bg-white rounded-lg border shadow-sm p-6 mb-6">
        <h3 className="text-sm font-bold text-gray-700 mb-4 uppercase tracking-wide">
          Export Summary
        </h3>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="flex justify-between">
            <span className="text-gray-500">Risk Exposure Table findings:</span>
            <span className="font-bold">{summary.retCount}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Configuration Findings:</span>
            <span className="font-bold">{summary.configCount}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">RCDT findings:</span>
            <span className="font-bold">{summary.rcdtCount}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Total findings:</span>
            <span className="font-bold">{summary.totalFindings}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Informational excluded:</span>
            <span className="font-bold text-gray-400">{summary.informationalExcluded}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Duplicates removed:</span>
            <span className="font-bold text-gray-400">{summary.dedupCount}</span>
          </div>
          {summary.unmatchedCount > 0 && (
            <div className="flex justify-between col-span-2">
              <span className="text-red-600">Unresolved asset IDs:</span>
              <span className="font-bold text-red-600">{summary.unmatchedCount}</span>
            </div>
          )}
          {summary.ambiguousCount > 0 && (
            <div className="flex justify-between col-span-2">
              <span className="text-purple-600">Ambiguous asset matches:</span>
              <span className="font-bold text-purple-600">{summary.ambiguousCount}</span>
            </div>
          )}
          {summary.unauthUnacknowledgedCount > 0 && (
            <div className="flex justify-between col-span-2">
              <span className="text-orange-600">Unacknowledged unauthenticated:</span>
              <span className="font-bold text-orange-600">
                {summary.unauthUnacknowledgedCount}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Validation errors (blocking) */}
      {hasErrors && (
        <div className="error-banner mb-6">
          <p className="font-medium mb-2">Export blocked — resolve these issues:</p>
          <ul className="list-disc list-inside text-sm space-y-1">
            {validationErrors.map((err, idx) => (
              <li key={idx}><span className="font-semibold">[{err.code}]</span> {err.message}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Validation warnings (overridable) */}
      {hasWarnings && (
        <div className="warning-banner mb-6">
          <p className="font-medium mb-2">Warnings — export can proceed with override:</p>
          <ul className="list-disc list-inside text-sm space-y-1">
            {validationWarnings.map((warn, idx) => (
              <li key={idx}><span className="font-semibold">[{warn.code}]</span> {warn.message}</li>
            ))}
          </ul>
          {!hasErrors && (
            <label className="flex items-center gap-2 mt-3 cursor-pointer">
              <input
                type="checkbox"
                checked={overrideWarnings}
                onChange={(e) => setOverrideWarnings(e.target.checked)}
                className="rounded border-gray-300"
              />
              <span className="text-sm font-medium">
                I acknowledge these warnings and want to export anyway
              </span>
            </label>
          )}
        </div>
      )}

      {/* Export result */}
      {exportStatus === 'success' && (
        <div className="success-banner mb-6">
          <p className="font-medium">RET workbook exported successfully!</p>
          <p className="text-sm mt-1">Saved to: {exportPath}</p>
        </div>
      )}

      {exportStatus === 'error' && (
        <div className="error-banner mb-6">
          <p className="font-medium">Export failed</p>
          <p className="text-sm mt-1">{exportError}</p>
        </div>
      )}

      {/* Navigation */}
      <div className="flex justify-between">
        <button
          onClick={prevStep}
          className="px-6 py-2 border rounded font-medium hover:bg-gray-50"
        >
          Back
        </button>
        <button
          onClick={handleExport}
          disabled={!canExport || exportStatus === 'exporting'}
          className="px-8 py-2 bg-green-600 text-white rounded font-bold hover:bg-green-700 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {exportStatus === 'exporting' ? 'Exporting...' : 'Export RET Workbook'}
        </button>
      </div>
    </div>
  );
}
