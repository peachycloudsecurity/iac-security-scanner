import React from 'react';
import { ScanState } from '@/types/scanner';
import { Loader2, CheckCircle2, XCircle, FileSearch, Circle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ScanStateIndicatorProps {
  state: ScanState;
  className?: string;
}

const stateConfig: Record<ScanState, {
  label: string;
  icon: React.ReactNode;
  className: string;
}> = {
  idle: {
    label: 'Ready to scan',
    icon: <Circle className="w-4 h-4" />,
    className: 'scan-state-idle',
  },
  parsing: {
    label: 'Parsing file...',
    icon: <Loader2 className="w-4 h-4 animate-spin" />,
    className: 'scan-state-parsing',
  },
  scanning: {
    label: 'Running security rules...',
    icon: <FileSearch className="w-4 h-4 animate-scan" />,
    className: 'scan-state-scanning',
  },
  completed: {
    label: 'Scan complete',
    icon: <CheckCircle2 className="w-4 h-4" />,
    className: 'scan-state-completed',
  },
  error: {
    label: 'Scan failed',
    icon: <XCircle className="w-4 h-4" />,
    className: 'scan-state-error',
  },
};

export function ScanStateIndicator({ state, className }: ScanStateIndicatorProps) {
  const config = stateConfig[state];
  
  return (
    <div className={cn('flex items-center gap-2', config.className, className)}>
      {config.icon}
      <span className="text-sm font-medium">{config.label}</span>
    </div>
  );
}
