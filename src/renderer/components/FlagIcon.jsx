import React from 'react';

export default function FlagIcon({ status, isAuthenticated }) {
  // Red = unmatched asset
  if (status === 'UNMATCHED') {
    return (
      <span className="flag-red" title="Asset ID not found in IIW" />
    );
  }
  // Purple = ambiguous — matched multiple IIW assets, needs resolution
  if (status === 'AMBIGUOUS') {
    return (
      <span className="flag-purple" title="Ambiguous — matched multiple IIW assets; resolve below" />
    );
  }
  // Orange = unauthenticated scan
  if (isAuthenticated === false) {
    return (
      <span className="flag-orange" title="Unauthenticated scan — results may be incomplete" />
    );
  }
  // Yellow = unknown auth status
  if (isAuthenticated === null) {
    return (
      <span className="flag-yellow" title="Authentication status unknown" />
    );
  }
  // Green = clean
  return <span className="flag-green" title="Clean" />;
}
