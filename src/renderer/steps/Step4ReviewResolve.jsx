import React, { useState, useCallback, useMemo } from 'react';
import { FixedSizeList as List } from 'react-window';
import useStore from '../store';
import FlagIcon from '../components/FlagIcon';
import ScannerBadge from '../components/ScannerBadge';

const RISK_LABELS = ['Critical', 'High', 'Moderate', 'Low'];
const SCAN_TYPES = ['VULNERABILITY', 'CONFIG_FINDING'];
const FLAG_FILTERS = ['all', 'unmatched', 'unauthenticated', 'clean'];

export default function Step4ReviewResolve() {
  const findings = useStore((s) => s.findings);
  const scanFiles = useStore((s) => s.scanFiles);
  const updateFinding = useStore((s) => s.updateFinding);
  const bulkUpdateFindings = useStore((s) => s.bulkUpdateFindings);
  const unauthAcknowledged = useStore((s) => s.unauthAcknowledged);
  const acknowledgeUnauth = useStore((s) => s.acknowledgeUnauth);
  const bulkAcknowledgeUnauth = useStore((s) => s.bulkAcknowledgeUnauth);
  const nextStep = useStore((s) => s.nextStep);
  const prevStep = useStore((s) => s.prevStep);
  const setFindings = useStore((s) => s.setFindings);
  const systemInfo = useStore((s) => s.systemInfo);

  // Filters
  const [filterScanner, setFilterScanner] = useState('all');
  const [filterFlag, setFilterFlag] = useState('all');
  const [filterRisk, setFilterRisk] = useState('all');
  const [filterScanType, setFilterScanType] = useState('all');

  // Selection
  const [selected, setSelected] = useState(new Set());

  // Exclude informational from display
  const nonInfoFindings = useMemo(
    () => findings.filter((f) => f.original_risk_rating !== 'Informational'),
    [findings]
  );

  const filtered = useMemo(() => {
    return nonInfoFindings.filter((f) => {
      if (filterScanner !== 'all' && f.scanner_file_id !== filterScanner) return false;
      if (filterRisk !== 'all' && f.original_risk_rating !== filterRisk) return false;
      if (filterScanType !== 'all' && f.scan_type !== filterScanType) return false;
      if (filterFlag === 'unmatched' && f.iiw_match_status !== 'UNMATCHED') return false;
      if (filterFlag === 'unauthenticated' && f.is_authenticated !== false) return false;
      if (filterFlag === 'clean' && (f.iiw_match_status === 'UNMATCHED' || f.is_authenticated === false))
        return false;
      return true;
    });
  }, [nonInfoFindings, filterScanner, filterFlag, filterRisk, filterScanType]);

  const toggleSelect = useCallback((cfoId) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(cfoId)) next.delete(cfoId);
      else next.add(cfoId);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelected(new Set(filtered.map((f) => f.cfo_id)));
  }, [filtered]);

  const clearSelection = useCallback(() => {
    setSelected(new Set());
  }, []);

  const bulkMarkRCDT = useCallback(() => {
    bulkUpdateFindings(Array.from(selected), { mark_as_rcdt: true });
    setSelected(new Set());
  }, [selected, bulkUpdateFindings]);

  const bulkAckUnauth = useCallback(() => {
    const unauthIds = Array.from(selected).filter((id) => {
      const f = findings.find((fi) => fi.cfo_id === id);
      return f && f.is_authenticated === false;
    });
    bulkAcknowledgeUnauth(unauthIds);
  }, [selected, findings, bulkAcknowledgeUnauth]);

  const handleProceed = useCallback(() => {
    // Generate IDs before export step
    const currentFindings = useStore.getState().findings;
    const si = useStore.getState().systemInfo;
    window.electronAPI
      .generateIds(currentFindings, {
        vulnPrefix: si.vulnPrefix,
        configPrefix: si.configPrefix,
        rcdtPrefix: si.rcdtPrefix,
      })
      .then((withIds) => {
        setFindings(withIds);
        nextStep();
      });
  }, [setFindings, nextStep]);

  // Unauthenticated findings needing acknowledgment
  const unauthUnacked = nonInfoFindings.filter(
    (f) => f.is_authenticated === false && !unauthAcknowledged.has(f.cfo_id)
  );

  // Row renderer for virtual list
  const ROW_HEIGHT = 48;

  const Row = useCallback(
    ({ index, style }) => {
      const f = filtered[index];
      const scanFile = scanFiles.find((sf) => sf.id === f.scanner_file_id);

      return (
        <div
          style={style}
          className={`flex items-center border-b text-sm ${
            selected.has(f.cfo_id) ? 'bg-blue-50' : index % 2 === 0 ? 'bg-white' : 'bg-gray-50'
          }`}
        >
          {/* Checkbox */}
          <div className="w-10 flex-shrink-0 text-center">
            <input
              type="checkbox"
              checked={selected.has(f.cfo_id)}
              onChange={() => toggleSelect(f.cfo_id)}
            />
          </div>
          {/* Flag */}
          <div className="w-10 flex-shrink-0 text-center">
            <FlagIcon status={f.iiw_match_status} isAuthenticated={f.is_authenticated} />
          </div>
          {/* Scanner */}
          <div className="w-36 flex-shrink-0 px-2 truncate">
            {scanFile && <ScannerBadge scannerType={scanFile.scannerType} />}
          </div>
          {/* Asset ID — editable */}
          <div className="w-44 flex-shrink-0 px-2">
            <input
              className="w-full text-xs border rounded px-1 py-0.5"
              value={f.asset_identifier || ''}
              onChange={(e) =>
                updateFinding(f.cfo_id, { asset_identifier: e.target.value })
              }
            />
          </div>
          {/* Weakness Name */}
          <div className="flex-1 px-2 truncate text-xs" title={f.weakness_name}>
            {f.weakness_name}
          </div>
          {/* Risk Rating */}
          <div className="w-24 flex-shrink-0 px-2 text-xs font-medium">
            <span
              className={
                f.original_risk_rating === 'Critical'
                  ? 'text-red-700'
                  : f.original_risk_rating === 'High'
                  ? 'text-orange-600'
                  : f.original_risk_rating === 'Moderate'
                  ? 'text-yellow-600'
                  : 'text-green-600'
              }
            >
              {f.original_risk_rating}
            </span>
          </div>
          {/* Scan Type */}
          <div className="w-28 flex-shrink-0 px-2 text-xs">
            {f.scan_type === 'CONFIG_FINDING' ? 'Config' : 'Vuln'}
          </div>
          {/* RCDT */}
          <div className="w-16 flex-shrink-0 text-center">
            <input
              type="checkbox"
              checked={!!f.mark_as_rcdt}
              onChange={(e) =>
                updateFinding(f.cfo_id, { mark_as_rcdt: e.target.checked })
              }
            />
          </div>
          {/* Comments */}
          <div className="w-48 flex-shrink-0 px-2">
            <input
              className="w-full text-xs border rounded px-1 py-0.5"
              placeholder="Comments..."
              value={f.assessor_comments || ''}
              onChange={(e) =>
                updateFinding(f.cfo_id, { assessor_comments: e.target.value })
              }
            />
          </div>
          {/* Acknowledge (for unauth) */}
          {f.is_authenticated === false && !unauthAcknowledged.has(f.cfo_id) && (
            <div className="w-20 flex-shrink-0 text-center">
              <button
                className="text-xs text-orange-600 underline"
                onClick={() => acknowledgeUnauth(f.cfo_id)}
              >
                Ack
              </button>
            </div>
          )}
        </div>
      );
    },
    [filtered, selected, scanFiles, unauthAcknowledged, toggleSelect, updateFinding, acknowledgeUnauth]
  );

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h2 className="text-xl font-bold text-fedramp-blue">Step 4: Review & Resolve</h2>
          <p className="text-sm text-gray-500">
            {filtered.length} of {nonInfoFindings.length} findings shown
          </p>
        </div>
      </div>

      {/* Unauthenticated warning banner */}
      {unauthUnacked.length > 0 && (
        <div className="warning-banner">
          <strong>UNAUTHENTICATED SCAN — Results May Be Incomplete:</strong>{' '}
          {unauthUnacked.length} finding(s) from unauthenticated scans require acknowledgment before export.
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-3">
        <select
          className="border rounded px-2 py-1 text-sm"
          value={filterScanner}
          onChange={(e) => setFilterScanner(e.target.value)}
        >
          <option value="all">All Scanners</option>
          {scanFiles.map((sf) => (
            <option key={sf.id} value={sf.id}>
              {sf.name}
            </option>
          ))}
        </select>
        <select
          className="border rounded px-2 py-1 text-sm"
          value={filterFlag}
          onChange={(e) => setFilterFlag(e.target.value)}
        >
          {FLAG_FILTERS.map((f) => (
            <option key={f} value={f}>
              {f === 'all' ? 'All Flags' : f.charAt(0).toUpperCase() + f.slice(1)}
            </option>
          ))}
        </select>
        <select
          className="border rounded px-2 py-1 text-sm"
          value={filterRisk}
          onChange={(e) => setFilterRisk(e.target.value)}
        >
          <option value="all">All Ratings</option>
          {RISK_LABELS.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <select
          className="border rounded px-2 py-1 text-sm"
          value={filterScanType}
          onChange={(e) => setFilterScanType(e.target.value)}
        >
          <option value="all">All Types</option>
          {SCAN_TYPES.map((t) => (
            <option key={t} value={t}>
              {t === 'VULNERABILITY' ? 'Vulnerability' : 'Config Finding'}
            </option>
          ))}
        </select>

        <div className="flex-1" />

        {/* Bulk actions */}
        <button
          onClick={selectAll}
          className="text-xs text-fedramp-blue underline"
        >
          Select All
        </button>
        <button
          onClick={clearSelection}
          className="text-xs text-gray-500 underline"
        >
          Clear
        </button>
        {selected.size > 0 && (
          <>
            <button
              onClick={bulkMarkRCDT}
              className="px-3 py-1 text-xs bg-fedramp-blue text-white rounded"
            >
              Mark {selected.size} as RCDT
            </button>
            <button
              onClick={bulkAckUnauth}
              className="px-3 py-1 text-xs bg-orange-500 text-white rounded"
            >
              Acknowledge Unauth
            </button>
          </>
        )}
      </div>

      {/* Table header */}
      <div className="flex items-center bg-fedramp-blue text-white text-xs font-medium rounded-t">
        <div className="w-10 flex-shrink-0 text-center py-2"></div>
        <div className="w-10 flex-shrink-0 text-center py-2">Flag</div>
        <div className="w-36 flex-shrink-0 px-2 py-2">Scanner</div>
        <div className="w-44 flex-shrink-0 px-2 py-2">Asset ID</div>
        <div className="flex-1 px-2 py-2">Weakness Name</div>
        <div className="w-24 flex-shrink-0 px-2 py-2">Risk</div>
        <div className="w-28 flex-shrink-0 px-2 py-2">Type</div>
        <div className="w-16 flex-shrink-0 text-center py-2">RCDT</div>
        <div className="w-48 flex-shrink-0 px-2 py-2">Comments</div>
      </div>

      {/* Virtual scrolling table body */}
      <div className="flex-1 border border-t-0 rounded-b bg-white">
        <List
          height={500}
          itemCount={filtered.length}
          itemSize={ROW_HEIGHT}
          width="100%"
        >
          {Row}
        </List>
      </div>

      {/* Navigation */}
      <div className="flex justify-between mt-4">
        <button
          onClick={prevStep}
          className="px-6 py-2 border rounded font-medium hover:bg-gray-50"
        >
          Back
        </button>
        <button
          onClick={handleProceed}
          className="px-6 py-2 bg-fedramp-blue text-white rounded font-medium hover:bg-blue-800"
        >
          Next: Export
        </button>
      </div>
    </div>
  );
}
