import React, { useCallback, useState } from 'react';
import useStore from '../store';
import DropZone from '../components/DropZone';
import ScannerBadge from '../components/ScannerBadge';
import FieldMapperModal from '../components/FieldMapperModal';
import ParseErrorModal from '../components/ParseErrorModal';
import { getAuthPercent, computeCoverage } from '../utils/coverage';
import { applyRescanComparison } from '../utils/rescan';
import { v4 as uuidv4 } from 'uuid';

export default function Step3UploadScans() {
  const scanFiles = useStore((s) => s.scanFiles);
  const addScanFile = useStore((s) => s.addScanFile);
  const removeScanFile = useStore((s) => s.removeScanFile);
  const updateScanFile = useStore((s) => s.updateScanFile);
  const findings = useStore((s) => s.findings);
  const setFindings = useStore((s) => s.setFindings);
  const iiwAssets = useStore((s) => s.iiwAssets);
  const setCoverage = useStore((s) => s.setCoverage);
  const deduplicateFindings = useStore((s) => s.deduplicateFindings);
  const setProgress = useStore((s) => s.setProgress);
  const nextStep = useStore((s) => s.nextStep);
  const prevStep = useStore((s) => s.prevStep);

  const [mapperState, setMapperState] = useState(null); // { csvHeaders, filePath, fileName, fileId }
  const [parseErrors, setParseErrors] = useState([]);
  const [failedFiles, setFailedFiles] = useState([]); // queue of hard parse failures → ParseErrorModal
  const [expandedAuthFile, setExpandedAuthFile] = useState(null); // fileId for expanded host details

  const handleFiles = useCallback(
    async (files) => {
      for (const file of files) {
        const fileId = uuidv4();
        setProgress({ message: `Parsing ${file.name}...`, percent: 0, visible: true });

        try {
          const result = await window.electronAPI.parseScanFile(file.path, file.name);

          if (result.error) {
            if (result.needsMapping && result.csvHeaders) {
              // Auto-detected as an unknown tabular format → open field mapper
              setMapperState({
                csvHeaders: result.csvHeaders,
                filePath: file.path,
                fileName: file.name,
                fileId,
              });
            } else {
              // Hard parse failure → recovery modal (Retry with mapper / Skip)
              setFailedFiles((prev) => [
                ...prev,
                {
                  fileId,
                  fileName: file.name,
                  filePath: file.path,
                  error: result.error,
                  errorDetail: result.errorDetail,
                  recoverable: !!result.recoverable,
                  logPath: result.logPath,
                },
              ]);
            }
            continue;
          }

          if (result.findings.length === 0) {
            setParseErrors((prev) => [
              ...prev,
              {
                fileName: file.name,
                error: `No findings detected in ${file.name}. Verify this is a complete scan output.`,
                isWarning: true,
              },
            ]);
          }

          // Tag findings with file id
          const taggedFindings = result.findings.map((f) => ({
            ...f,
            scanner_file_id: fileId,
          }));

          addScanFile({
            id: fileId,
            name: file.name,
            path: file.path,
            scannerType: result.scannerType,
            findingCount: result.findings.length,
            authWarning: result.authWarning || false,
            authDetails: result.authDetails || '',
            authField: result.authField || '',
            authSummary: result.authSummary || null,
          });

          setFindings([...useStore.getState().findings, ...taggedFindings]);
        } catch (err) {
          const ext = (file.name.split('.').pop() || '').toLowerCase();
          setFailedFiles((prev) => [
            ...prev,
            {
              fileId,
              fileName: file.name,
              filePath: file.path,
              error: `Could not parse ${file.name} — file may be corrupt or truncated.`,
              errorDetail: err && err.message,
              recoverable: ['csv', 'xls', 'xlsx', 'json'].includes(ext),
            },
          ]);
        }
      }

      setProgress({ message: '', percent: 0, visible: false });
    },
    [addScanFile, setFindings, setProgress]
  );

  const handleMapperConfirm = useCallback(
    async (mapping) => {
      const { filePath, fileName, fileId } = mapperState;
      setMapperState(null);
      setProgress({ message: `Parsing ${fileName} with mapping...`, percent: 0, visible: true });

      try {
        const result = await window.electronAPI.parseScanFileWithMapping(filePath, fileName, mapping);

        if (result.error) {
          setParseErrors((prev) => [
            ...prev,
            { fileName, error: result.error },
          ]);
        } else if (result.findings && result.findings.length > 0) {
          const taggedFindings = result.findings.map((f) => ({
            ...f,
            scanner_file_id: fileId,
          }));

          addScanFile({
            id: fileId,
            name: fileName,
            path: filePath,
            scannerType: result.scannerType || 'Mapped CSV',
            findingCount: result.findings.length,
            authWarning: false,
          });

          setFindings([...useStore.getState().findings, ...taggedFindings]);
        } else {
          setParseErrors((prev) => [
            ...prev,
            {
              fileName,
              error: `No findings detected in ${fileName} after applying mapping.`,
              isWarning: true,
            },
          ]);
        }
      } catch (err) {
        setParseErrors((prev) => [
          ...prev,
          { fileName, error: err.message },
        ]);
      }

      setProgress({ message: '', percent: 0, visible: false });
    },
    [mapperState, addScanFile, setFindings, setProgress]
  );

  // Dequeue the first failed file (after the user chooses an action on it).
  const dequeueFailure = useCallback((fileId) => {
    setFailedFiles((prev) => prev.filter((f) => f.fileId !== fileId));
  }, []);

  // "Retry with Field Mapper" on a failed file: re-extract its columns through
  // the universal parser, then open the field mapper. If headers can't be read,
  // surface that as a banner so the user isn't stuck on the modal.
  const handleRetryWithMapper = useCallback(
    async (failed) => {
      dequeueFailure(failed.fileId);
      setProgress({ message: `Reading columns from ${failed.fileName}...`, percent: 0, visible: true });
      try {
        const res = await window.electronAPI.mapperParseFile(failed.filePath, failed.fileName);
        if (res && res.headers && res.headers.length > 0) {
          setMapperState({
            csvHeaders: res.headers,
            filePath: failed.filePath,
            fileName: failed.fileName,
            fileId: failed.fileId,
          });
        } else {
          setParseErrors((prev) => [
            ...prev,
            {
              fileName: failed.fileName,
              error: (res && res.error) || 'No columns could be read from this file for mapping.',
            },
          ]);
        }
      } catch (err) {
        setParseErrors((prev) => [
          ...prev,
          { fileName: failed.fileName, error: err.message },
        ]);
      }
      setProgress({ message: '', percent: 0, visible: false });
    },
    [dequeueFailure, setProgress]
  );

  const handleSkipFailure = useCallback(
    (failed) => {
      dequeueFailure(failed.fileId);
      setParseErrors((prev) => [
        ...prev,
        { fileName: failed.fileName, error: 'Skipped — not included in the RET.', isWarning: true },
      ]);
    },
    [dequeueFailure]
  );

  const handleRemoveFile = useCallback(
    (fileId) => {
      removeScanFile(fileId);
    },
    [removeScanFile]
  );

  const handleProceed = useCallback(() => {
    const allFindings = useStore.getState().findings;
    const allScanFiles = useStore.getState().scanFiles;
    const currentAssets = useStore.getState().iiwAssets;

    // Step 1: Apply rescan comparison before dedup — baseline findings absent from
    // rescan files are auto-marked RCDT; rescan-only (new) findings are included.
    const hasRescan = allScanFiles.some((sf) => sf.isRescan);
    if (hasRescan) {
      setFindings(applyRescanComparison(allFindings, allScanFiles));
    }

    // Step 2: Dedup by asset+CVE key
    deduplicateFindings();

    const deduped = useStore.getState().findings;

    // Step 3: IIW asset matching
    window.electronAPI.matchAssets(deduped, currentAssets).then((matched) => {
      setFindings(matched);
      if (currentAssets && currentAssets.length > 0) {
        setCoverage(computeCoverage(matched, currentAssets, allScanFiles));
      }
      nextStep();
    });
  }, [deduplicateFindings, setFindings, setCoverage, nextStep]);

  const canProceed = scanFiles.length > 0;

  return (
    <div className="max-w-3xl mx-auto">
      <h2 className="text-xl font-bold text-fedramp-blue mb-1">Step 3: Upload Scan Files</h2>
      <p className="text-sm text-gray-500 mb-6">
        Drop one or more vulnerability scan result files. Supported: .nessus, .xml, .csv, .json, .xlsx, .xls
      </p>

      <DropZone
        accept=".nessus,.xml,.csv,.json,.xlsx,.xls"
        multiple={true}
        onFilesDropped={handleFiles}
        label="Drag & drop scan files here"
        sublabel="Accepts .nessus, .xml, .csv, .json, .xlsx, .xls — multiple files supported"
      />

      {/* Parse errors */}
      {parseErrors.map((err, idx) => (
        <div
          key={idx}
          className={err.isWarning ? 'warning-banner mt-3' : 'error-banner mt-3'}
        >
          <strong>{err.fileName}:</strong> {err.error}
        </div>
      ))}

      {/* Unauthenticated scan warning */}
      {scanFiles.some((sf) => sf.authWarning) && (
        <div className="warning-banner mt-4">
          <p className="font-medium">Unauthenticated scan(s) detected</p>
          <ul className="text-sm mt-1 list-disc list-inside">
            {scanFiles.filter((sf) => sf.authWarning).map((sf) => (
              <li key={sf.id}>
                <strong>{sf.name}</strong>: {sf.authDetails || 'Authentication status could not be confirmed'}
                {sf.authField && (
                  <span className="block text-xs text-orange-600 ml-5 mt-0.5">
                    Detection fields: {sf.authField}
                  </span>
                )}
                {sf.authSummary && sf.authSummary.manualReview > 0 && (
                  <span className="block text-xs text-orange-700 ml-5 mt-0.5 font-medium">
                    {sf.authSummary.manualReview} host(s) require manual review: {sf.authSummary.manualReviewHosts.slice(0, 5).join(', ')}
                    {sf.authSummary.manualReviewHosts.length > 5 && ` +${sf.authSummary.manualReviewHosts.length - 5} more`}
                  </span>
                )}
              </li>
            ))}
          </ul>
          <p className="text-xs mt-2 text-orange-700">
            Unauthenticated scans may produce incomplete results. FedRAMP requires authenticated scanning for all applicable assets.
          </p>
        </div>
      )}

      {/* Authentication detection summary — per-scan with expandable host details */}
      {scanFiles.some((sf) => sf.authSummary || sf.authField) && (
        <div className="mt-3 bg-blue-50 border border-blue-200 rounded-lg px-4 py-3 text-sm text-blue-800">
          <p className="font-medium text-blue-900 mb-2">Authentication Detection Summary</p>
          {scanFiles.filter((sf) => sf.authSummary || sf.authField).map((sf) => (
            <div key={sf.id} className="mb-3 last:mb-0">
              <div className="flex items-center gap-2 mb-1">
                <strong className="text-blue-900">{sf.name}</strong>
                <span className="text-xs text-blue-600">({sf.scannerType})</span>
                {sf.authSummary && (
                  <span className={`text-xs px-2 py-0.5 rounded ${sf.authSummary.compliant ? 'bg-green-100 text-green-700' : 'bg-orange-100 text-orange-700'}`}>
                    {sf.authSummary.compliant ? 'Compliant' : 'Non-Compliant'}
                  </span>
                )}
              </div>
              {sf.authSummary && sf.authSummary.totalHosts > 0 && (
                <div className="ml-2 text-xs space-y-0.5">
                  <div className="flex gap-4 text-blue-700">
                    <span>Hosts evaluated: <strong>{sf.authSummary.totalHosts}</strong></span>
                    {sf.authSummary.authenticatedHigh > 0 && (
                      <span className="text-green-700">Authenticated (high): <strong>{sf.authSummary.authenticatedHigh}</strong></span>
                    )}
                    {sf.authSummary.authenticatedMedLow > 0 && (
                      <span className="text-green-600">Authenticated (med/low): <strong>{sf.authSummary.authenticatedMedLow}</strong></span>
                    )}
                    {sf.authSummary.unauthenticated > 0 && (
                      <span className="text-red-600">Unauthenticated: <strong>{sf.authSummary.unauthenticated}</strong></span>
                    )}
                    {sf.authSummary.manualReview > 0 && (
                      <span className="text-orange-600">Manual review: <strong>{sf.authSummary.manualReview}</strong></span>
                    )}
                  </div>
                  {sf.authSummary.hostDetails && sf.authSummary.hostDetails.length > 0 && (
                    <button
                      onClick={() => setExpandedAuthFile(expandedAuthFile === sf.id ? null : sf.id)}
                      className="text-blue-600 hover:text-blue-800 underline text-xs mt-1"
                    >
                      {expandedAuthFile === sf.id ? 'Hide' : 'Show'} per-host details ({sf.authSummary.hostDetails.length} hosts)
                    </button>
                  )}
                  {expandedAuthFile === sf.id && sf.authSummary.hostDetails && (
                    <div className="mt-1 bg-white border border-blue-100 rounded p-2 max-h-48 overflow-y-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-left text-blue-800 border-b">
                            <th className="pr-2 pb-1">Host</th>
                            <th className="pr-2 pb-1">Status</th>
                            <th className="pr-2 pb-1">Confidence</th>
                            <th className="pb-1">Evidence</th>
                          </tr>
                        </thead>
                        <tbody>
                          {sf.authSummary.hostDetails.map((hd, idx) => (
                            <tr key={idx} className="border-b border-blue-50">
                              <td className="pr-2 py-0.5 font-mono">{hd.host}</td>
                              <td className="pr-2 py-0.5">
                                <span className={
                                  hd.authenticated === true ? 'text-green-600' :
                                  hd.authenticated === false ? 'text-red-600' :
                                  'text-orange-500'
                                }>
                                  {hd.authenticated === true ? 'Authenticated' :
                                   hd.authenticated === false ? 'Unauthenticated' :
                                   'Unknown'}
                                </span>
                              </td>
                              <td className="pr-2 py-0.5">
                                <span className={
                                  hd.confidence === 'high' ? 'text-green-700' :
                                  hd.confidence === 'medium' ? 'text-yellow-600' :
                                  hd.confidence === 'low' ? 'text-orange-500' :
                                  'text-red-500'
                                }>
                                  {hd.confidence}
                                </span>
                              </td>
                              <td className="py-0.5 text-gray-600">{hd.evidence}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
              {sf.authField && (
                <div className="ml-2 text-xs text-blue-600 mt-1">
                  Detection fields: {sf.authField}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Loaded files list */}
      {scanFiles.length > 0 && (
        <div className="mt-6 bg-white rounded-lg border shadow-sm">
          <div className="px-4 py-3 border-b bg-gray-50">
            <h3 className="text-sm font-semibold text-gray-700">
              Loaded Scan Files ({scanFiles.length})
            </h3>
          </div>
          <ul className="divide-y">
            {scanFiles.map((sf) => (
              <li key={sf.id} className="px-4 py-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <ScannerBadge scannerType={sf.scannerType} />
                    <span className="text-sm font-medium">{sf.name}</span>
                    <span className="text-xs text-gray-400">
                      {sf.findingCount} finding{sf.findingCount !== 1 ? 's' : ''}
                    </span>
                    {sf.authWarning ? (
                      <span
                        className="text-xs text-orange-600 bg-orange-50 px-2 py-0.5 rounded cursor-help"
                        title={`${sf.authDetails}${sf.authField ? `\nDetection fields: ${sf.authField}` : ''}`}
                      >
                        {sf.authSummary?.unauthenticated > 0 ? 'Unauthenticated' : 'Auth Unknown'}
                        {sf.authSummary?.manualReview > 0 && ` (${sf.authSummary.manualReview} manual review)`}
                      </span>
                    ) : sf.authDetails ? (
                      <span
                        className="text-xs text-green-600 bg-green-50 px-2 py-0.5 rounded cursor-help"
                        title={`${sf.authDetails}${sf.authField ? `\nDetection fields: ${sf.authField}` : ''}`}
                      >
                        Authenticated
                        {sf.authSummary && sf.authSummary.authenticatedMedLow > 0 && (
                          <span className="text-yellow-600 ml-1">
                            ({sf.authSummary.authenticatedMedLow} med/low confidence)
                          </span>
                        )}
                      </span>
                    ) : null}
                  </div>
                  <button
                    onClick={() => handleRemoveFile(sf.id)}
                    className="text-red-500 text-xs hover:text-red-700"
                  >
                    Remove
                  </button>
                </div>
                <div className="mt-2 flex items-center gap-4 flex-wrap">
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-gray-500">Scan Type:</label>
                    <select
                      value={sf.detectorType || ''}
                      onChange={(e) => updateScanFile(sf.id, { detectorType: e.target.value })}
                      className="text-xs border rounded px-2 py-1 bg-white"
                    >
                      <option value="">— Select —</option>
                      <option value="Infrastructure">Infrastructure</option>
                      <option value="Database">Database</option>
                      <option value="Web App">Web App</option>
                      <option value="Container">Container</option>
                    </select>
                    {!sf.detectorType && (
                      <span className="text-xs text-orange-500">Required for export</span>
                    )}
                  </div>
                  <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={!!sf.isRescan}
                      onChange={(e) => updateScanFile(sf.id, { isRescan: e.target.checked })}
                      className="rounded"
                    />
                    <span className={sf.isRescan ? 'text-blue-700 font-semibold' : ''}>
                      Rescan
                    </span>
                  </label>
                  {sf.isRescan && (
                    <span className="text-xs text-blue-600 bg-blue-50 px-2 py-0.5 rounded">
                      Baseline findings absent from this file → auto-RCDT
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Rescan mode explanation — shown when any file is marked as rescan */}
      {scanFiles.some((sf) => sf.isRescan) && (
        <div className="mt-3 bg-blue-50 border border-blue-200 rounded-lg px-4 py-3 text-xs text-blue-800">
          <p className="font-semibold text-blue-900 mb-1">Rescan mode active</p>
          <p>
            When you click Next, findings from <strong>baseline</strong> (non-rescan) files that do{' '}
            <strong>not</strong> appear in rescan files will be automatically marked as{' '}
            <em>Corrected During Testing (RCDT)</em>. Findings still present in the rescan remain
            open. New findings discovered only in the rescan are included as open findings.
          </p>
        </div>
      )}

      {/* Coverage & Authentication Summary — shown once scan files are loaded */}
      {scanFiles.length > 0 && (
        <div className="mt-4 bg-white rounded-lg border shadow-sm overflow-hidden">
          <div className="px-4 py-2 bg-gray-50 border-b flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-700">Coverage &amp; Authentication Summary</h3>
            {iiwAssets.length > 0 ? (
              <span className="text-xs text-gray-500">{iiwAssets.length} IIW assets loaded — coverage computed after matching</span>
            ) : (
              <span className="text-xs text-orange-500">No IIW loaded — upload in Step 2 for coverage tracking</span>
            )}
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-gray-500 border-b bg-gray-50">
                <th className="px-3 py-2 font-medium">Scanner File</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">Hosts</th>
                <th className="px-3 py-2 font-medium">Auth%</th>
                <th className="px-3 py-2 font-medium">Coverage%</th>
              </tr>
            </thead>
            <tbody>
              {scanFiles.map((sf) => {
                const authPct = getAuthPercent(sf.authSummary);
                const totalHosts = sf.authSummary?.totalHosts || 0;
                return (
                  <tr key={sf.id} className="border-b last:border-0">
                    <td className="px-3 py-2 font-medium truncate max-w-[180px]" title={sf.name}>{sf.name}</td>
                    <td className="px-3 py-2 text-gray-500">{sf.scannerType || '—'}</td>
                    <td className="px-3 py-2 text-gray-600">{totalHosts > 0 ? totalHosts : '—'}</td>
                    <td className="px-3 py-2">
                      {authPct !== null ? (
                        <span className={authPct === 100 ? 'text-green-600 font-semibold' : authPct >= 80 ? 'text-yellow-600 font-semibold' : 'text-red-600 font-semibold'}>
                          {authPct}%
                        </span>
                      ) : (
                        <span className="text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-gray-400 italic">
                      {iiwAssets.length > 0 ? 'Click Next to compute' : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Parse Error Recovery Modal (one failed file at a time) */}
      {failedFiles.length > 0 && !mapperState && (
        <ParseErrorModal
          failure={failedFiles[0]}
          onRetryWithMapper={() => handleRetryWithMapper(failedFiles[0])}
          onSkip={() => handleSkipFailure(failedFiles[0])}
        />
      )}

      {/* Field Mapper Modal */}
      {mapperState && (
        <FieldMapperModal
          csvHeaders={mapperState.csvHeaders}
          onConfirm={handleMapperConfirm}
          onCancel={() => setMapperState(null)}
        />
      )}

      {/* Navigation */}
      <div className="flex justify-between mt-6">
        <button
          onClick={prevStep}
          className="px-6 py-2 border rounded font-medium hover:bg-gray-50"
        >
          Back
        </button>
        <button
          onClick={handleProceed}
          disabled={!canProceed}
          className="px-6 py-2 bg-fedramp-blue text-white rounded font-medium hover:bg-blue-800 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Next: Review & Resolve
        </button>
      </div>
    </div>
  );
}
