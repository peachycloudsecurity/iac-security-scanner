import React, { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Github, Loader2, AlertCircle } from 'lucide-react';

interface GitHubInputProps {
  onScan: (url: string) => void;
  isScanning: boolean;
}

export function GitHubInput({ onScan, isScanning }: GitHubInputProps) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!url.trim()) {
      setError('Please enter a GitHub repository URL');
      return;
    }

    // Basic URL validation
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      
      if (!['github.com', 'www.github.com'].includes(hostname)) {
        setError('Only GitHub.com repositories are allowed');
        return;
      }

      if (urlObj.protocol !== 'https:') {
        setError('Only HTTPS URLs are allowed');
        return;
      }

      // Check if it looks like a repo URL
      const pathParts = urlObj.pathname.split('/').filter(p => p);
      if (pathParts.length < 2) {
        setError('Invalid GitHub URL. Expected format: https://github.com/owner/repo');
        return;
      }

      onScan(url);
    } catch {
      setError('Invalid URL format');
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <label htmlFor="github-url" className="text-sm font-medium">
          Scan GitHub Repository via URL
        </label>
        <div className="relative min-h-[200px] bg-code-bg border border-border rounded-lg p-4 space-y-4">
          <form onSubmit={handleSubmit} className="flex gap-2">
            <Input
              id="github-url"
              type="url"
              placeholder="https://github.com/owner/repository"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setError(null);
              }}
              disabled={isScanning}
              className="flex-1 bg-background"
            />
            <Button type="submit" disabled={isScanning || !url.trim()}>
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Github className="w-4 h-4 mr-2" />
                  Scan Repository
                </>
              )}
            </Button>
          </form>

          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="text-xs text-muted-foreground space-y-1 mt-auto">
            <p>• Only public repositories from github.com are supported</p>
            <p>• All IaC files (Terraform, Kubernetes, Docker, CloudFormation) will be scanned</p>
            <p>• Large repositories may take several minutes to scan</p>
          </div>
        </div>
      </div>
    </div>
  );
}
