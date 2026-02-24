import React from 'react';

const BADGE_CLASSES = {
  'Tenable Nessus': 'scanner-badge-nessus',
  'Qualys': 'scanner-badge-qualys',
  'Rapid7 InsightVM': 'scanner-badge-rapid7',
  'Prisma Cloud': 'scanner-badge-prisma',
  'SCAP/XCCDF': 'scanner-badge-scap',
  'Generic CSV': 'scanner-badge-csv',
  'Unknown': 'scanner-badge-csv',
};

export default function ScannerBadge({ scannerType }) {
  const cls = BADGE_CLASSES[scannerType] || 'scanner-badge-csv';
  return <span className={`scanner-badge ${cls}`}>{scannerType || 'Unknown'}</span>;
}
