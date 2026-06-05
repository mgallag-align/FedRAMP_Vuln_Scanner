import React from 'react';
import useStore from './store';
import Stepper from './components/Stepper';
import ProgressBar from './components/ProgressBar';
import VulnerabilityMapper from './components/VulnerabilityMapper';
import Step1SystemInfo from './steps/Step1SystemInfo';
import Step2UploadIIW from './steps/Step2UploadIIW';
import Step3UploadScans from './steps/Step3UploadScans';
import Step4ReviewResolve from './steps/Step4ReviewResolve';
import Step5Export from './steps/Step5Export';

const STEPS = [
  { label: 'System Info', component: Step1SystemInfo },
  { label: 'Upload IIW', component: Step2UploadIIW },
  { label: 'Upload Scans', component: Step3UploadScans },
  { label: 'Review & Resolve', component: Step4ReviewResolve },
  { label: 'Export', component: Step5Export },
];

export default function App() {
  const currentStep = useStore((s) => s.currentStep);
  const progress = useStore((s) => s.progress);
  const mapperView = useStore((s) => s.mapperView);
  const setMapperView = useStore((s) => s.setMapperView);

  const StepComponent = STEPS[currentStep].component;

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-fedramp-blue text-white px-6 py-3 flex items-center justify-between shadow-md">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-bold tracking-wide">FedRAMP RET Tool</h1>
          <span className="text-xs bg-white/20 px-2 py-0.5 rounded">v1.0</span>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={() => setMapperView(!mapperView)}
            className={`text-xs px-3 py-1.5 rounded transition-colors ${
              mapperView
                ? 'bg-white text-fedramp-blue font-bold'
                : 'bg-white/20 text-white hover:bg-white/30'
            }`}
          >
            {mapperView ? 'Mapper Active' : 'Column Mapper'}
          </button>
          <span className="text-xs text-blue-200">
            Risk Exposure Table Automation — 3PAO Assessment Tool
          </span>
        </div>
      </header>

      {/* Show Mapper view or normal Wizard view */}
      {mapperView ? (
        <>
          {/* Progress bar */}
          {progress.visible && (
            <div className="px-6 py-2 bg-white border-b">
              <ProgressBar message={progress.message} percent={progress.percent} />
            </div>
          )}
          <main className="flex-1 overflow-auto">
            <VulnerabilityMapper />
          </main>
        </>
      ) : (
        <>
          {/* Stepper */}
          <Stepper steps={STEPS.map((s) => s.label)} currentStep={currentStep} />

          {/* Progress bar */}
          {progress.visible && (
            <div className="px-6 py-2 bg-white border-b">
              <ProgressBar message={progress.message} percent={progress.percent} />
            </div>
          )}

          {/* Step Content */}
          <main className="flex-1 overflow-auto px-6 py-4">
            <StepComponent />
          </main>
        </>
      )}
    </div>
  );
}
