import React from 'react';
import useStore from '../store';

export default function Step1SystemInfo() {
  const systemInfo = useStore((s) => s.systemInfo);
  const setSystemInfo = useStore((s) => s.setSystemInfo);
  const nextStep = useStore((s) => s.nextStep);

  const canProceed =
    systemInfo.cspName.trim() &&
    systemInfo.systemName.trim() &&
    systemInfo.impactLevel &&
    systemInfo.retDate &&
    systemInfo.vulnPrefix.trim() &&
    systemInfo.configPrefix.trim() &&
    systemInfo.rcdtPrefix.trim();

  return (
    <div className="max-w-2xl mx-auto">
      <h2 className="text-xl font-bold text-fedramp-blue mb-1">Step 1: System Information</h2>
      <p className="text-sm text-gray-500 mb-6">
        Enter the CSP and system details for this assessment engagement.
      </p>

      <div className="space-y-4 bg-white p-6 rounded-lg shadow-sm border">
        {/* CSP Name */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            CSP Name <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            className="w-full border rounded px-3 py-2 text-sm"
            placeholder="e.g., Acme Cloud Services"
            value={systemInfo.cspName}
            onChange={(e) => setSystemInfo({ cspName: e.target.value })}
          />
        </div>

        {/* System Name */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            System Name <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            className="w-full border rounded px-3 py-2 text-sm"
            placeholder="e.g., Acme GovCloud Platform"
            value={systemInfo.systemName}
            onChange={(e) => setSystemInfo({ systemName: e.target.value })}
          />
        </div>

        {/* Impact Level */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Impact Level <span className="text-red-500">*</span>
          </label>
          <select
            className="w-full border rounded px-3 py-2 text-sm"
            value={systemInfo.impactLevel}
            onChange={(e) => setSystemInfo({ impactLevel: e.target.value })}
          >
            <option value="">— Select —</option>
            <option value="Low">Low</option>
            <option value="Moderate">Moderate</option>
            <option value="High">High</option>
          </select>
        </div>

        {/* RET Date */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            RET Date <span className="text-red-500">*</span>
          </label>
          <input
            type="date"
            className="w-full border rounded px-3 py-2 text-sm"
            value={systemInfo.retDate}
            onChange={(e) => setSystemInfo({ retDate: e.target.value })}
          />
        </div>

        {/* ID Prefixes */}
        <div className="border-t pt-4 mt-4">
          <p className="text-sm font-medium text-gray-700 mb-3">RET ID Prefix Schema</p>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-xs text-gray-500 mb-1">
                Vulnerability Prefix <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                className="w-full border rounded px-3 py-2 text-sm uppercase"
                maxLength={4}
                placeholder="VS"
                value={systemInfo.vulnPrefix}
                onChange={(e) =>
                  setSystemInfo({ vulnPrefix: e.target.value.toUpperCase().replace(/[^A-Z]/g, '') })
                }
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">
                Config Finding Prefix <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                className="w-full border rounded px-3 py-2 text-sm uppercase"
                maxLength={4}
                placeholder="CF"
                value={systemInfo.configPrefix}
                onChange={(e) =>
                  setSystemInfo({ configPrefix: e.target.value.toUpperCase().replace(/[^A-Z]/g, '') })
                }
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">
                RCDT Prefix <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                className="w-full border rounded px-3 py-2 text-sm uppercase"
                maxLength={4}
                placeholder="RC"
                value={systemInfo.rcdtPrefix}
                onChange={(e) =>
                  setSystemInfo({ rcdtPrefix: e.target.value.toUpperCase().replace(/[^A-Z]/g, '') })
                }
              />
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="flex justify-end mt-6">
        <button
          onClick={nextStep}
          disabled={!canProceed}
          className="px-6 py-2 bg-fedramp-blue text-white rounded font-medium hover:bg-blue-800 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Next: Upload IIW
        </button>
      </div>
    </div>
  );
}
