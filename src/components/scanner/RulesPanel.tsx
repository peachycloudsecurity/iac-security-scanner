import React, { useState } from 'react';
import { RuleExecution } from '@/types/scanner';
import { SeverityBadge } from './SeverityBadge';
import { ChevronDown, ChevronUp, CheckCircle2, SkipForward } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';

interface RulesPanelProps {
  ruleExecutions: RuleExecution[];
  className?: string;
}

export function RulesPanel({ ruleExecutions, className }: RulesPanelProps) {
  const [isOpen, setIsOpen] = useState(false);
  
  const executed = ruleExecutions.filter(r => r.status === 'executed');
  const skipped = ruleExecutions.filter(r => r.status === 'skipped');
  
  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen} className={className}>
      <CollapsibleTrigger asChild>
        <Button
          variant="ghost"
          className="w-full justify-between p-4 h-auto scanner-card hover:bg-muted/30"
        >
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-foreground">Rules Executed</span>
            <span className="text-xs text-muted-foreground">
              {executed.length} executed, {skipped.length} skipped
            </span>
          </div>
          {isOpen ? (
            <ChevronUp className="w-4 h-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="w-4 h-4 text-muted-foreground" />
          )}
        </Button>
      </CollapsibleTrigger>
      
      <CollapsibleContent>
        <div className="scanner-card mt-2 divide-y divide-border">
          {ruleExecutions.map((execution, index) => (
            <div
              key={`${execution.rule.id}-${index}`}
              className={cn(
                'p-3 flex items-start gap-3',
                execution.status === 'skipped' && 'opacity-60'
              )}
            >
              {execution.status === 'executed' ? (
                <CheckCircle2 className="w-4 h-4 text-success mt-0.5 shrink-0" />
              ) : (
                <SkipForward className="w-4 h-4 text-muted-foreground mt-0.5 shrink-0" />
              )}
              
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <code className="text-xs font-mono text-primary">{execution.rule.id}</code>
                  <SeverityBadge severity={execution.rule.severity} className="scale-90" />
                </div>
                <p className="text-sm text-foreground mb-1">{execution.rule.title}</p>
                <p className="text-xs text-muted-foreground">
                  Applies to: {execution.rule.applicableFileTypes.join(', ')}
                </p>
                {execution.reason && (
                  <p className="text-xs text-warning mt-1">{execution.reason}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}
