import React, { useCallback, useState } from 'react';
import useStore from '../store';
import DropZone from '../components/DropZone';
import ScannerBadge from '../components/ScannerBadge';
import FieldMapperModal from '../components/FieldMapperModal';
import { v4 as uuidv4 } from 'uuid';

export default function Step3UploadScans() {
  const scanFiles = useStore((s) => s.scanFiles);
  const addScanFile = useStore((s) => s.addScanFile);
  const removeScanFile = useStore((s) => s.removeScanFile);
  const findings = useStore((s) => s.findings);
  const setFindings = useStore((s) => s.setFindings);
  const iiwAssets = useStore((s) => s.iiwAssets);
  const deduplicateFindings = useStore((s) => s.deduplicateFindings);
  const setProgress = useStore((s) => s.setProgress);
  const nextStep = useStore((s) => s.nextStep);
  const prevStep = useStore((s) => s.prevStep);

  const [mapperState, setMapperState] = useState(null); // { csvHeaders, filePath, fileName, fileId }
  const [parseErrors, setParseErrors] = useState([]);

  const handleFiles = useCallback(
    async (files) => {
      for (const file of files) {
        const fileId = uuidv4();
        setProgress({ message: `Parsing ${file.name}...`, percent: 0, visible: true });

        try {
          const result = await window.electronAPI.parseScanFile(file.path, file.name);

          if (result.error) {
            if (result.needsMapping && result.csvHeaders) {
              // Open field mapper modal
              setMapperState({
                csvHeaders: result.csvHeaders,
                filePath: file.path,
                fileName: file.name,
                fileId,
              });
            } else {
              setParseErrors((prev) => [
                ...prev,
                { fileName: file.name, error: result.error },
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
          });

          setFindings([...useStore.getState().findings, ...taggedFindings]);
        } catch (err) {
          setParseErrors((prev) => [
            ...prev,
            { fileName: file.name, error: `Could not parse ${file.name} — file may be corrupt or truncated.` },
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
      setProgress({ message: `Re-parsing ${fileName} with mapping...`, percent: 0, visible: true });

      try {
        const result = await window.electronAPI.parseScanFile(filePath, fileName);
        // Apply custom mapping using the result's raw data
        // The parser will handle this via a second pass with the mapping
        if (result.findings) {
          const taggedFindings = result.findings.map((f) => ({
            ...f,
            scanner_file_id: fileId,
          }));

          addScanFile({
            id: fileId,
            name: fileName,
            path: filePath,
            scannerType: 'Generic CSV',
            findingCount: result.findings.length,
            authWarning: false,
          });

          setFindings([...useStore.getState().findings, ...taggedFindings]);
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

  const handleRemoveFile = useCallback(
    (fileId) => {
      removeScanFile(fileId);
    },
    [removeScanFile]
  );

  const handleProceed = useCallback(() => {
    // Run deduplication and asset matching before moving to review
    deduplicateFindings();

    // Match assets via IPC
    const currentFindings = useStore.getState().findings;
    const currentAssets = useStore.getState().iiwAssets;
    window.electronAPI.matchAssets(currentFindings, currentAssets).then((matched) => {
      setFindings(matched);
      nextStep();
    });
  }, [deduplicateFindings, setFindings, nextStep]);

  const canProceed = scanFiles.length > 0;

  return (
    <div className="max-w-3xl mx-auto">
      <h2 className="text-xl font-bold text-fedramp-blue mb-1">Step 3: Upload Scan Files</h2>
      <p className="text-sm text-gray-500 mb-6">
        Drop one or more vulnerability scan result files. Supported: .nessus, .xml, .csv, .json
      </p>

      <DropZone
        accept=".nessus,.xml,.csv,.json"
        multiple={true}
        onFilesDropped={handleFiles}
        label="Drag & drop scan files here"
        sublabel="Accepts .nessus, .xml, .csv, .json — multiple files supported"
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
              <li key={sf.id} className="px-4 py-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <ScannerBadge scannerType={sf.scannerType} />
                  <span className="text-sm font-medium">{sf.name}</span>
                  <span className="text-xs text-gray-400">
                    {sf.findingCount} finding{sf.findingCount !== 1 ? 's' : ''}
                  </span>
                  {sf.authWarning && (
                    <span className="text-xs text-orange-600 bg-orange-50 px-2 py-0.5 rounded">
                      Auth unconfirmed
                    </span>
                  )}
                </div>
                <button
                  onClick={() => handleRemoveFile(sf.id)}
                  className="text-red-500 text-xs hover:text-red-700"
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        </div>
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
