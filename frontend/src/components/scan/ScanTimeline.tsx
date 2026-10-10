import React from 'react';
import { CheckCircle2, Circle, ArrowRight } from 'lucide-react';
import clsx from 'clsx';

export const ScanTimeline: React.FC = () => {
  const steps = [
    { id: 'discovery', label: 'Discovery' },
    { id: 'static', label: 'Static' },
    { id: 'risk', label: 'Risk' },
    { id: 'ai-review', label: 'AI Review' },
    { id: 'validation', label: 'Validation' },
    { id: 'correlation', label: 'Correlation' },
    { id: 'policy', label: 'Policy' },
  ];

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-xl p-6 mb-6">
      <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider mb-6">Scan Timeline</h3>
      <div className="flex items-center justify-between w-full relative">
        {steps.map((step, index) => (
          <React.Fragment key={step.id}>
            <div className="flex flex-col items-center relative z-10">
              <div className="w-8 h-8 rounded-full bg-primary/20 text-primary border border-primary flex items-center justify-center mb-2">
                <CheckCircle2 size={16} />
              </div>
              <span className="text-xs font-mono text-gray-400">{step.label}</span>
            </div>
            {index < steps.length - 1 && (
              <div className="flex-1 h-px bg-dark-600 mx-2 relative z-0">
                <div className="absolute inset-0 bg-primary w-full origin-left" />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};
