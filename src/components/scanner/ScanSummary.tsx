import React from 'react';
import { Finding, Severity } from '@/types/scanner';
import { SeverityBadge } from './SeverityBadge';
import { cn } from '@/lib/utils';
import { AlertTriangle, AlertCircle, Info, ShieldCheck } from 'lucide-react';

interface ScanSummaryProps {
  findings: Finding[];
  className?: string;
}

export function ScanSummary({ findings, className }: ScanSummaryProps) {
  const counts: Record<Severity, number> = {
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };
  
  findings.forEach(f => {
    counts[f.severity]++;
  });
  
  const total = findings.length;
  const hasIssues = total > 0;
  
  return (
    <div className={cn('scanner-card p-1', className)}>
      <div className="flex items-center gap-3 mb-1">
        {hasIssues ? (
          counts.HIGH > 0 ? (
            <AlertTriangle className="w-6 h-6 text-severity-high" />
          ) : counts.MEDIUM > 0 ? (
            <AlertCircle className="w-6 h-6 text-severity-medium" />
          ) : (
            <Info className="w-6 h-6 text-severity-low" />
          )
        ) : (
          <ShieldCheck className="w-6 h-6 text-success" />
        )}
        <div>
          <h3 className="text-lg font-semibold text-foreground">
            {hasIssues ? `${total} Issue${total !== 1 ? 's' : ''} Found` : 'No Issues Found'}
          </h3>
          <p className="text-sm text-muted-foreground">
            {hasIssues 
              ? (
                <>
                  Review the findings below for details and remediation steps. For full scan coverage, refer to{' '}
                  <a href="https://github.com/bridgecrewio/checkov" className="text-primary no-underline hover:text-primary/80">
                    Checkov
                  </a>{' '}
                  and{' '}
                  <a href="https://github.com/aquasecurity/tfsec" className="text-primary no-underline hover:text-primary/80">
                    tfsec
                  </a>.
                </>
              )
              : 'Your configuration passed all security checks.'}
          </p>
        </div>
      </div>
      
      {hasIssues && (
        <div className="flex flex-wrap gap-3">
          <SeverityBadge severity="HIGH" count={counts.HIGH} />
          <SeverityBadge severity="MEDIUM" count={counts.MEDIUM} />
          <SeverityBadge severity="LOW" count={counts.LOW} />
        </div>
      )}
    </div>
  );
}
