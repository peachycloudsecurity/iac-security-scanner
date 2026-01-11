import React from 'react';
import { Shield, Lock } from 'lucide-react';

export function TrustBadge() {
  return (
    <div className="flex flex-wrap items-center justify-center gap-4 py-3 px-4 bg-muted/30 rounded-lg border border-border">
      <div className="trust-badge">
        <Shield className="w-4 h-4" />
        <span>All analysis runs locally in your browser</span>
      </div>
      <div className="trust-badge">
        <Lock className="w-4 h-4" />
        <span>No files are uploaded or stored</span>
      </div>
    </div>
  );
}
