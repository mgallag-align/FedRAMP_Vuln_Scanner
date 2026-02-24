import React, { useCallback } from 'react';
import useStore from '../store';
import DropZone from '../components/DropZone';

export default function Step2UploadIIW() {
  const iiwFile = useStore((s) => s.iiwFile);
  const iiwAssets = useStore((s) => s.iiwAssets);
  const iiwParseError = useStore((s) => s.iiwParseError);
  const setIIWData = useStore((s) => s.setIIWData);
  const setProgress = useStore((s) => s.setProgress);
  const nextStep = useStore((s) => s.nextStep);
  const prevStep = useStore((s) => s.prevStep);

  const handleFiles = useCallback(
    async (files) => {
      const file = files[0];
      if (!file) return;

      if (!file.name.endsWith('.xlsx') && !file.name.endsWith('.xls')) {
        setIIWData({ error: 'IIW must be an Excel file (.xlsx).' });
        return;
      }

      setProgress({ message: 'Parsing IIW...', percent: 0, visible: true });

      try {
        const result = await window.electronAPI.parseIIW(file.path);
        if (result.error) {
          setIIWData({ error: result.error });
        } else if (result.assets.length === 0) {
          setIIWData({
            error: 'IIW appears empty or unpopulated. Please upload a completed IIW.',
          });
        } else {
          setIIWData({ file: { name: file.name, path: file.path }, assets: result.assets });
        }
      } catch (err) {
        setIIWData({ error: `Failed to parse IIW: ${err.message}` });
      } finally {
        setProgress({ message: '', percent: 0, visible: false });
      }
    },
    [setIIWData, setProgress]
  );

  const canProceed = iiwAssets.length > 0 && !iiwParseError;

  // Count duplicates
  const uniqueIds = new Set(iiwAssets.map((a) => a.uniqueAssetId));
  const hasDuplicates = uniqueIds.size < iiwAssets.length;

  return (
    <div className="max-w-2xl mx-auto">
      <h2 className="text-xl font-bold text-fedramp-blue mb-1">Step 2: Upload IIW</h2>
      <p className="text-sm text-gray-500 mb-6">
        Upload the Integrated Inventory Workbook (SSP Appendix M) for this system.
      </p>

      <DropZone
        accept=".xlsx,.xls"
        multiple={false}
        onFilesDropped={handleFiles}
        label="Drag & drop the IIW file here"
        sublabel="Accepts .xlsx files"
      />

      {/* Error */}
      {iiwParseError && (
        <div className="error-banner mt-4">{iiwParseError}</div>
      )}

      {/* Success */}
      {iiwFile && !iiwParseError && (
        <div className="success-banner mt-4">
          <p className="font-medium">IIW loaded: {iiwFile.name}</p>
          <p className="text-sm mt-1">
            {iiwAssets.length} asset{iiwAssets.length !== 1 ? 's' : ''} found
          </p>
          {hasDuplicates && (
            <p className="text-sm text-orange-600 mt-1">
              Warning: Duplicate Unique Asset Identifiers detected. First occurrence will be used for matching.
            </p>
          )}
        </div>
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
          onClick={nextStep}
          disabled={!canProceed}
          className="px-6 py-2 bg-fedramp-blue text-white rounded font-medium hover:bg-blue-800 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Next: Upload Scans
        </button>
      </div>
    </div>
  );
}
