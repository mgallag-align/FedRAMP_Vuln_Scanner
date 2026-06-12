import React, { useState } from 'react';

/**
 * Modal shown when a scan file fails to parse.
 *
 * Offers a clear recovery path instead of a dead-end banner:
 *   - "Retry with Field Mapper" (only when the file is a tabular format the
 *     mapper can re-read) lets the assessor map columns manually.
 *   - "Skip File" dismisses the file and moves on.
 *   - "View details" reveals the raw error and the local log location for a
 *     bug report — no network involved.
 *
 * Props:
 *   failure: { fileName, error, errorDetail?, recoverable?, logPath? }
 *   onRetryWithMapper(): void   — only meaningful when failure.recoverable
 *   onSkip(): void
 */
export default function ParseErrorModal({ failure, onRetryWithMapper, onSkip }) {
  const [showDetails, setShowDetails] = useState(false);
  if (!failure) return null;

  const { fileName, error, errorDetail, recoverable, logPath } = failure;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-[560px] max-h-[80vh] overflow-auto">
        <div className="px-6 py-4 border-b bg-red-600 text-white rounded-t-lg">
          <h2 className="text-lg font-bold">Couldn’t read this scan file</h2>
          <p className="text-sm text-red-100 mt-1 break-all">{fileName}</p>
        </div>

        <div className="px-6 py-4 space-y-3">
          <p className="text-sm text-gray-700">{error}</p>

          {recoverable ? (
            <p className="text-sm text-gray-600">
              This looks like a tabular file. You can map its columns to the
              required RET fields manually and try again.
            </p>
          ) : (
            <p className="text-sm text-gray-600">
              This file type can’t be mapped manually. Confirm it’s a complete,
              uncorrupted export from a supported scanner, then re-upload it.
            </p>
          )}

          <button
            onClick={() => setShowDetails((v) => !v)}
            className="text-xs text-blue-600 hover:text-blue-800 underline"
          >
            {showDetails ? 'Hide' : 'View'} details
          </button>

          {showDetails && (
            <div className="bg-gray-50 border rounded p-3 text-xs text-gray-700 space-y-2">
              {errorDetail && (
                <pre className="whitespace-pre-wrap break-all max-h-40 overflow-auto font-mono">
                  {errorDetail}
                </pre>
              )}
              {logPath && (
                <p className="text-gray-500 break-all">
                  Logged to: <span className="font-mono">{logPath}</span>
                </p>
              )}
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t flex justify-end gap-3">
          <button
            onClick={onSkip}
            className="px-4 py-2 text-sm border rounded hover:bg-gray-50"
          >
            Skip File
          </button>
          {recoverable && (
            <button
              onClick={onRetryWithMapper}
              className="px-4 py-2 text-sm bg-fedramp-blue text-white rounded hover:bg-blue-800"
            >
              Retry with Field Mapper
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
