import React, { useState, useCallback, useRef } from 'react';

export default function DropZone({ accept, multiple, onFilesDropped, label, sublabel }) {
  const [isDragOver, setIsDragOver] = useState(false);
  const inputRef = useRef(null);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) {
        onFilesDropped(files);
      }
    },
    [onFilesDropped]
  );

  const handleClick = useCallback(() => {
    inputRef.current?.click();
  }, []);

  const handleFileInput = useCallback(
    (e) => {
      const files = Array.from(e.target.files);
      if (files.length > 0) {
        onFilesDropped(files);
      }
      // Reset input so the same file can be re-selected
      e.target.value = '';
    },
    [onFilesDropped]
  );

  return (
    <div
      className={`drop-zone ${isDragOver ? 'drop-zone-active' : ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={handleClick}
    >
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        accept={accept}
        multiple={multiple}
        onChange={handleFileInput}
      />
      <div className="flex flex-col items-center gap-2">
        <svg
          className={`w-12 h-12 ${isDragOver ? 'text-fedramp-blue' : 'text-gray-400'}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
          />
        </svg>
        <p className="text-gray-600 font-medium">{label || 'Drag & drop files here'}</p>
        <p className="text-gray-400 text-sm">{sublabel || 'or click to browse'}</p>
      </div>
    </div>
  );
}
