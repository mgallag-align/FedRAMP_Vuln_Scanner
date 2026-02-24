import React from 'react';

export default function ProgressBar({ message, percent }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm text-gray-600">{message}</span>
        <span className="text-sm text-gray-500">{Math.round(percent)}%</span>
      </div>
      <div className="progress-bar-track">
        <div className="progress-bar-fill" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}
