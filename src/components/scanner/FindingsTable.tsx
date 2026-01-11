import React, { useState } from 'react';
import { Finding, Severity } from '@/types/scanner';
import { SeverityBadge } from './SeverityBadge';
import { ChevronDown, ChevronUp, FileCode, MapPin } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

interface FindingsTableProps {
  findings: Finding[];
  className?: string;
}

export function FindingsTable({ findings, className }: FindingsTableProps) {
  const [filter, setFilter] = useState<Severity | 'ALL'>('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  
  const filteredFindings = filter === 'ALL' 
    ? findings 
    : findings.filter(f => f.severity === filter);
  
  const counts: Record<Severity | 'ALL', number> = {
    ALL: findings.length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
  };
  
  return (
    <div className={cn('scanner-card overflow-hidden', className)}>
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 p-4 border-b border-border bg-muted/30">
        <span className="text-sm font-medium text-muted-foreground mr-2">Filter:</span>
        {(['ALL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
          <Button
            key={sev}
            variant={filter === sev ? 'default' : 'outline'}
            size="sm"
            onClick={() => setFilter(sev)}
            className={cn(
              'text-xs',
              filter === sev && sev === 'HIGH' && 'bg-severity-high hover:bg-severity-high/90',
              filter === sev && sev === 'MEDIUM' && 'bg-severity-medium hover:bg-severity-medium/90 text-severity-medium-foreground',
              filter === sev && sev === 'LOW' && 'bg-severity-low hover:bg-severity-low/90'
            )}
          >
            {sev} ({counts[sev]})
          </Button>
        ))}
      </div>
      
      {/* Table */}
      <div className="overflow-x-auto">
        <div className="max-h-[320px] overflow-y-auto">
        <table className="w-full">
            <thead className="bg-muted/50 sticky top-0 z-10">
            <tr>
              <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                Rule ID
              </th>
              <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                Title
              </th>
              <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                Severity
              </th>
              <th className="text-left p-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide hidden md:table-cell">
                Resource
              </th>
              <th className="w-10"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-8 text-center text-muted-foreground">
                  No findings match the selected filter.
                </td>
              </tr>
            ) : (
              filteredFindings.map((finding, index) => (
                <React.Fragment key={`${finding.id}-${finding.fileName}-${index}`}>
                  <tr 
                    className={cn(
                      'hover:bg-muted/30 cursor-pointer transition-colors',
                      expandedId === finding.id && 'bg-muted/40'
                    )}
                    onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                  >
                    <td className="p-3">
                      <code className="text-xs font-mono text-primary">{finding.ruleId}</code>
                    </td>
                    <td className="p-3 text-sm text-foreground">{finding.title}</td>
                    <td className="p-3">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="p-3 hidden md:table-cell">
                      <span className="text-xs font-mono text-muted-foreground truncate max-w-[200px] block">
                        {finding.resourcePath || '-'}
                      </span>
                    </td>
                    <td className="p-3">
                      {expandedId === finding.id ? (
                        <ChevronUp className="w-4 h-4 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-muted-foreground" />
                      )}
                    </td>
                  </tr>
                  
                  {/* Expanded Details */}
                  {expandedId === finding.id && (
                    <tr>
                      <td colSpan={5} className="p-0">
                        <div className="p-4 bg-muted/20 border-t border-border space-y-3">
                          <div>
                            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">
                              Description
                            </h4>
                            <p className="text-sm text-foreground">{finding.description}</p>
                          </div>
                          
                          <div className="flex flex-wrap gap-4 text-sm">
                            {finding.fileName && (
                              <div className="flex items-center gap-1.5 text-muted-foreground">
                                <FileCode className="w-4 h-4" />
                                <span className="font-mono text-xs">{finding.fileName}</span>
                              </div>
                            )}
                            {finding.lineNumber && (
                              <div className="flex items-center gap-1.5 text-muted-foreground">
                                <MapPin className="w-4 h-4" />
                                <span>Line {finding.lineNumber}</span>
                              </div>
                            )}
                          </div>
                          
                          <div className="bg-success/10 border border-success/20 rounded-md p-3">
                            <h4 className="text-xs font-semibold text-success uppercase tracking-wide mb-1">
                              Remediation
                            </h4>
                            <p className="text-sm text-foreground">{finding.remediation}</p>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))
            )}
          </tbody>
        </table>
        </div>
      </div>
    </div>
  );
}

export function getFilteredFindings(findings: Finding[], filter: Severity | 'ALL'): Finding[] {
  return filter === 'ALL' ? findings : findings.filter(f => f.severity === filter);
}
