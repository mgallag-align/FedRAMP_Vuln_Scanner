import React from 'react';

export default function Stepper({ steps, currentStep }) {
  return (
    <div className="bg-white border-b px-6 py-3">
      <div className="flex items-center justify-between max-w-3xl mx-auto">
        {steps.map((label, idx) => {
          const isCompleted = idx < currentStep;
          const isActive = idx === currentStep;

          return (
            <React.Fragment key={idx}>
              <div className="flex items-center gap-2">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold border-2 ${
                    isCompleted
                      ? 'bg-green-500 border-green-500 text-white'
                      : isActive
                      ? 'bg-fedramp-blue border-fedramp-blue text-white'
                      : 'bg-white border-gray-300 text-gray-400'
                  }`}
                >
                  {isCompleted ? '\u2713' : idx + 1}
                </div>
                <span
                  className={`text-sm ${
                    isActive
                      ? 'text-fedramp-blue font-semibold'
                      : isCompleted
                      ? 'text-green-600 font-medium'
                      : 'text-gray-400'
                  }`}
                >
                  {label}
                </span>
              </div>
              {idx < steps.length - 1 && (
                <div
                  className={`flex-1 h-0.5 mx-3 ${
                    idx < currentStep ? 'bg-green-500' : 'bg-gray-200'
                  }`}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
