import { create } from 'zustand';
import { v4 as uuidv4 } from 'uuid';

const RISK_ORDER = { Critical: 0, High: 1, Moderate: 2, Low: 3 };

const useStore = create((set, get) => ({
  // ── Step 1: System Info ──
  systemInfo: {
    cspName: '',
    systemName: '',
    impactLevel: '',
    retDate: '',
    vulnPrefix: 'VS',
    configPrefix: 'CF',
    rcdtPrefix: 'RC',
  },
  setSystemInfo: (info) =>
    set((state) => ({ systemInfo: { ...state.systemInfo, ...info } })),

  // ── Step 2: IIW ──
  iiwFile: null,
  iiwAssets: [],
  iiwParseError: null,
  setIIWData: ({ file, assets, error }) =>
    set({ iiwFile: file || null, iiwAssets: assets || [], iiwParseError: error || null }),

  // ── Step 3: Scan Files ──
  scanFiles: [],
  addScanFile: (fileEntry) =>
    set((state) => ({ scanFiles: [...state.scanFiles, fileEntry] })),
  removeScanFile: (fileId) =>
    set((state) => ({
      scanFiles: state.scanFiles.filter((f) => f.id !== fileId),
      findings: state.findings.filter((f) => f.scanner_file_id !== fileId),
    })),
  updateScanFile: (fileId, updates) =>
    set((state) => ({
      scanFiles: state.scanFiles.map((f) =>
        f.id === fileId ? { ...f, ...updates } : f
      ),
    })),

  // ── Coverage (computed post-match in Step 3 handleProceed) ──
  coverage: null,
  setCoverage: (data) => set({ coverage: data }),

  // ── Findings (CFOs) ──
  findings: [],
  setFindings: (findings) => set({ findings }),
  updateFinding: (cfoId, updates) =>
    set((state) => ({
      findings: state.findings.map((f) =>
        f.cfo_id === cfoId ? { ...f, ...updates } : f
      ),
    })),
  bulkUpdateFindings: (cfoIds, updates) =>
    set((state) => ({
      findings: state.findings.map((f) =>
        cfoIds.includes(f.cfo_id) ? { ...f, ...updates } : f
      ),
    })),

  // ── Acknowledgments ──
  unauthAcknowledged: new Set(),
  acknowledgeUnauth: (cfoId) =>
    set((state) => {
      const next = new Set(state.unauthAcknowledged);
      next.add(cfoId);
      return { unauthAcknowledged: next };
    }),
  bulkAcknowledgeUnauth: (cfoIds) =>
    set((state) => {
      const next = new Set(state.unauthAcknowledged);
      cfoIds.forEach((id) => next.add(id));
      return { unauthAcknowledged: next };
    }),

  // ── Wizard Navigation ──
  currentStep: 0,
  setStep: (step) => set({ currentStep: step }),
  nextStep: () => set((state) => ({ currentStep: Math.min(state.currentStep + 1, 4) })),
  prevStep: () => set((state) => ({ currentStep: Math.max(state.currentStep - 1, 0) })),

  // ── Progress ──
  progress: { message: '', percent: 0, visible: false },
  setProgress: (progress) => set({ progress }),

  // ── Export Summary ──
  getExportSummary: () => {
    const state = get();
    const findings = state.findings.filter(
      (f) => f.original_risk_rating !== 'Informational'
    );
    const retFindings = findings.filter(
      (f) => f.scan_type === 'VULNERABILITY' && !f.mark_as_rcdt
    );
    const configFindings = findings.filter(
      (f) => f.scan_type === 'CONFIG_FINDING' && !f.mark_as_rcdt
    );
    const rcdtFindings = findings.filter((f) => f.mark_as_rcdt);
    const unmatched = findings.filter((f) => f.iiw_match_status === 'UNMATCHED');
    const ambiguous = findings.filter((f) => f.iiw_match_status === 'AMBIGUOUS');
    const unauthenticated = findings.filter((f) => f.is_authenticated === false);
    const unauthUnacknowledged = unauthenticated.filter(
      (f) => !state.unauthAcknowledged.has(f.cfo_id)
    );
    const informationalExcluded = state.findings.filter(
      (f) => f.original_risk_rating === 'Informational'
    ).length;

    // Dedup count
    const seen = new Set();
    let dedupCount = 0;
    state.findings.forEach((f) => {
      const key = `${f.asset_identifier}|${f.weakness_source_identifier}`;
      if (seen.has(key)) dedupCount++;
      else seen.add(key);
    });

    return {
      retCount: retFindings.length,
      configCount: configFindings.length,
      rcdtCount: rcdtFindings.length,
      unmatchedCount: unmatched.length,
      ambiguousCount: ambiguous.length,
      unauthCount: unauthenticated.length,
      unauthUnacknowledgedCount: unauthUnacknowledged.length,
      informationalExcluded,
      dedupCount,
      totalFindings: findings.length,
    };
  },

  // ── Deduplication ──
  deduplicateFindings: () =>
    set((state) => {
      const seen = new Map();
      const deduped = [];
      for (const f of state.findings) {
        const key = `${(f.asset_identifier || '').toLowerCase().trim()}|${(f.weakness_source_identifier || '').toLowerCase().trim()}`;
        if (!seen.has(key)) {
          seen.set(key, true);
          deduped.push(f);
        }
      }
      return { findings: deduped };
    }),

  // ── Vulnerability Mapper ──
  mapperView: false,
  setMapperView: (show) => set({ mapperView: show }),

  mapperSourceFile: null, // { name, path, headers, rows, totalRows }
  setMapperSourceFile: (data) => set({ mapperSourceFile: data }),

  mapperMappings: {}, // { targetField: sourceField }
  setMapperMappings: (mappings) => set({ mapperMappings: mappings }),
  setMapperMapping: (target, source) =>
    set((state) => ({
      mapperMappings: { ...state.mapperMappings, [target]: source },
    })),
  removeMapperMapping: (target) =>
    set((state) => {
      const next = { ...state.mapperMappings };
      delete next[target];
      return { mapperMappings: next };
    }),
  clearMapperMappings: () => set({ mapperMappings: {} }),

  mapperTemplates: JSON.parse(localStorage.getItem('mapperTemplates') || '[]'),
  saveMapperTemplate: (template) =>
    set((state) => {
      const existing = state.mapperTemplates.filter((t) => t.name !== template.name);
      const updated = [...existing, template];
      localStorage.setItem('mapperTemplates', JSON.stringify(updated));
      return { mapperTemplates: updated };
    }),
  deleteMapperTemplate: (name) =>
    set((state) => {
      const updated = state.mapperTemplates.filter((t) => t.name !== name);
      localStorage.setItem('mapperTemplates', JSON.stringify(updated));
      return { mapperTemplates: updated };
    }),
  loadMapperTemplate: (name) => {
    const state = get();
    const template = state.mapperTemplates.find((t) => t.name === name);
    if (template) {
      set({ mapperMappings: { ...template.mappings } });
    }
  },

  mapperTransformedRows: [],
  setMapperTransformedRows: (rows) => set({ mapperTransformedRows: rows }),

  resetMapper: () =>
    set({
      mapperSourceFile: null,
      mapperMappings: {},
      mapperTransformedRows: [],
    }),

  // ── Reset ──
  resetSession: () =>
    set({
      systemInfo: {
        cspName: '',
        systemName: '',
        impactLevel: '',
        retDate: '',
        vulnPrefix: 'VS',
        configPrefix: 'CF',
        rcdtPrefix: 'RC',
      },
      iiwFile: null,
      iiwAssets: [],
      iiwParseError: null,
      scanFiles: [],
      coverage: null,
      findings: [],
      unauthAcknowledged: new Set(),
      currentStep: 0,
      progress: { message: '', percent: 0, visible: false },
    }),
}));

export default useStore;
