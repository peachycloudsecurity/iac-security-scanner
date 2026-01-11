import React from 'react';
import { Textarea } from '@/components/ui/textarea';

interface CodeInputProps {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
}

export function CodeInput({ value, onChange, disabled, placeholder }: CodeInputProps) {
  return (
    <div className="relative">
      <Textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        placeholder={placeholder || `# Paste your infrastructure code here...
# Supported formats:
# - Terraform (.tf)
# - Kubernetes manifests
# - Docker Compose
# - Dockerfile
# - JSON/YAML configurations`}
        className="font-mono text-sm min-h-[200px] bg-code-bg border-border resize-none
                   placeholder:text-muted-foreground/50 focus-visible:ring-primary/50"
        spellCheck={false}
      />
      {value && (
        <div className="absolute bottom-2 right-2 text-xs text-muted-foreground">
          {value.split('\n').length} lines
        </div>
      )}
    </div>
  );
}
