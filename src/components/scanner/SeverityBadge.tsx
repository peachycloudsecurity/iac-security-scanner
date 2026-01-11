import React from 'react';
import { Severity } from '@/types/scanner';
import { cn } from '@/lib/utils';

interface SeverityBadgeProps {
  severity: Severity;
  count?: number;
  className?: string;
}

export function SeverityBadge({ severity, count, className }: SeverityBadgeProps) {
  const severityClasses: Record<Severity, string> = {
    HIGH: 'severity-high',
    MEDIUM: 'severity-medium',
    LOW: 'severity-low',
  };
  
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold',
      severityClasses[severity],
      className
    )}>
      {severity}
      {count !== undefined && (
        <span className="opacity-80">({count})</span>
      )}
    </span>
  );
}
