import React, { useState, useCallback, useEffect } from 'react';
import { ScanResult, ScanState } from '@/types/scanner';
import { runScan } from '@/engine/scanner';
import { detectFileType } from '@/utils/fileDetector';
import { generatePdfReport, generateMultiFilePdfReport } from '@/utils/pdfExport';
import { FileUpload } from './FileUpload';
import { CodeInput } from './CodeInput';
import { ExamplesPanel, Example } from './ExamplesPanel';
import { GitHubInput } from './GitHubInput';
import { FileTypeBadge } from './FileTypeBadge';
import { ScanStateIndicator } from './ScanStateIndicator';
import { ScanSummary } from './ScanSummary';
import { FindingsTable } from './FindingsTable';
import { RulesPanel } from './RulesPanel';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, Play, FileDown, RotateCcw, Upload, Code, BookOpen, Moon, Sun, Calendar, Coffee, ExternalLink, Youtube, Github, Loader2, FileCode, ChevronDown, ChevronUp, Lock, Heart } from 'lucide-react';
import { validateGitHubUrl, fetchGitHubRepoFiles, setRateLimitHandler, RateLimitHandler } from '@/utils/githubClient';
import { runMultiFileScan } from '@/engine/scanner';
import { MultiFileScanResult } from '@/types/scanner';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { SITE } from '@/config/site';

const APP_VERSION = '1.0.0';

export function Scanner() {
  const [inputMethod, setInputMethod] = useState<'upload' | 'paste' | 'examples' | 'github'>('upload');
  const [fileName, setFileName] = useState<string>('');
  const [code, setCode] = useState('');
  const [scanState, setScanState] = useState<ScanState>('idle');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [multiFileResult, setMultiFileResult] = useState<MultiFileScanResult | null>(null);
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [githubProgress, setGithubProgress] = useState<{ current: number; total: number; file?: string } | null>(null);
  const [githubStatus, setGithubStatus] = useState<string | null>(null);
  const [githubUrl, setGithubUrl] = useState<string>('');
  const [rateLimitDialog, setRateLimitDialog] = useState<{ open: boolean; resetTime: Date; waitMinutes: number; resolve: (value: boolean) => void } | null>(null);
  const [filesScannedExpanded, setFilesScannedExpanded] = useState(false);
  
  useEffect(() => {
    // Initialize theme from localStorage or default to dark
    const savedTheme = localStorage.getItem('cloudguard-theme');
    const prefersDark = savedTheme === 'dark' || (!savedTheme && true);
    setIsDarkMode(prefersDark);

    if (prefersDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }

    // Set up rate limit handler
    const rateLimitHandler: RateLimitHandler = async (resetTime, waitMinutes) => {
      return new Promise((resolve) => {
        setRateLimitDialog({
          open: true,
          resetTime,
          waitMinutes,
          resolve,
        });
      });
    };

    setRateLimitHandler(rateLimitHandler);

    // Cleanup on unmount
    return () => {
      setRateLimitHandler(null);
    };
  }, []);

  const toggleTheme = () => {
    const newMode = !isDarkMode;
    setIsDarkMode(newMode);

    if (newMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }

    localStorage.setItem('cloudguard-theme', newMode ? 'dark' : 'light');
  };
  
  const detectedType = code ? detectFileType(fileName || 'input.txt', code) : null;
  
  const handleFileSelect = useCallback((name: string, content: string) => {
    setFileName(name);
    setCode(content);
    setScanResult(null);
    setMultiFileResult(null);
    setScanState('idle');
  }, []);
  
  const handleCodeChange = useCallback((value: string) => {
    setCode(value);
    setScanResult(null);
    setMultiFileResult(null);
    setScanState('idle');
  }, []);
  
  const handleExampleSelect = useCallback((example: Example) => {
    setFileName(example.fileName);
    setCode(example.content);
    setScanResult(null);
    setMultiFileResult(null);
    setScanState('idle');
    // Switch to paste tab to show the selected example
    setInputMethod('paste');
  }, []);
  
  const handleScan = async () => {
    if (!code.trim()) return;
    
    setScanState('parsing');
    setMultiFileResult(null);
    const result = await runScan({
      fileName: fileName || 'input',
      content: code,
      onStateChange: setScanState,
    });
    
    setScanResult(result);
    setScanState(result.state);
  };

  const handleGitHubScan = async (url: string) => {
    setScanState('parsing');
    setScanResult(null);
    setMultiFileResult(null);
    setGithubProgress(null);
    setGithubUrl(url);

    try {
      // Validate URL
      const validation = validateGitHubUrl(url);
      if (!validation.valid || !validation.info) {
        setScanState('error');
        setMultiFileResult({
          state: 'error',
          files: [],
          totalFindings: 0,
          findingsBySeverity: { HIGH: 0, MEDIUM: 0, LOW: 0 },
          error: validation.error || 'Invalid GitHub URL',
          timestamp: new Date(),
        });
        return;
      }

      const { owner, repo } = validation.info;

      // Fetch files
      setScanState('parsing');
      setGithubStatus(null);
      const { files } = await fetchGitHubRepoFiles(
        owner, 
        repo, 
        undefined, 
        (current, total, currentFile) => {
          setGithubProgress({ current, total, file: currentFile });
        },
        (message) => {
          setGithubStatus(message);
        }
      );

      if (files.length === 0) {
        setScanState('error');
        setMultiFileResult({
          state: 'error',
          files: [],
          totalFindings: 0,
          findingsBySeverity: { HIGH: 0, MEDIUM: 0, LOW: 0 },
          error: 'No IaC files found in repository',
          timestamp: new Date(),
        });
        return;
      }

      // Scan all files
      setScanState('scanning');
      const result = await runMultiFileScan(
        files.map(f => ({ fileName: f.path, content: f.content })),
        (current, total, currentFile) => {
          setGithubProgress({ current, total, file: currentFile });
        }
      );

      setMultiFileResult(result);
      setScanState(result.state);
      setGithubProgress(null);
      setGithubStatus(null);
    } catch (error) {
      setScanState('error');
      let errorMessage = 'Failed to scan repository';
      
      if (error instanceof Error) {
        errorMessage = error.message;
        
        // Provide more helpful error messages
        if (errorMessage.includes('rate limit') || errorMessage.includes('Rate limit')) {
          errorMessage = 'GitHub API rate limit exceeded. Please wait a few minutes and try again. Large repositories may take longer to scan.';
        } else if (errorMessage.includes('Access denied') || errorMessage.includes('403')) {
          errorMessage = 'Access denied (403). The repository might be private, or you may have hit GitHub rate limits. Please try again in a few minutes.';
        } else if (errorMessage.includes('not found') || errorMessage.includes('404')) {
          errorMessage = 'Repository not found. Please check the URL and ensure it\'s a public repository.';
        }
      }
      
      setMultiFileResult({
        state: 'error',
        files: [],
        totalFindings: 0,
        findingsBySeverity: { HIGH: 0, MEDIUM: 0, LOW: 0 },
        error: errorMessage,
        timestamp: new Date(),
      });
      setGithubProgress(null);
      setGithubStatus(null);
    }
  };
  
  const handleRateLimitWait = () => {
    if (rateLimitDialog) {
      rateLimitDialog.resolve(true);
      setRateLimitDialog(null);
    }
  };

  const handleRateLimitStop = () => {
    if (rateLimitDialog) {
      rateLimitDialog.resolve(false);
      setRateLimitDialog(null);
    }
  };
  
  const handleReset = () => {
    setFileName('');
    setCode('');
    setScanResult(null);
    setMultiFileResult(null);
    setScanState('idle');
    setGithubProgress(null);
    setGithubStatus(null);
    if (rateLimitDialog) {
      rateLimitDialog.resolve(false);
      setRateLimitDialog(null);
    }
  };
  
  const handleExport = () => {
    if (scanResult) {
      generatePdfReport(scanResult);
    } else if (multiFileResult) {
      generateMultiFilePdfReport(multiFileResult, githubUrl);
    }
  };
  
  const isScanning = scanState === 'parsing' || scanState === 'scanning';
  const canScan = code.trim().length > 0 && !isScanning;
  
  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between gap-4">
            {/* Left: Logo + Nav Links */}
            <div className="flex items-center gap-4 sm:gap-6">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10 scanner-glow">
                  <Shield className="w-6 h-6 text-primary" />
                </div>
                <div className="hidden sm:block">
                  <h1 className="text-xl font-bold text-foreground">CloudGuard</h1>
                  <p className="text-xs text-muted-foreground">IaC Security Scanner v{APP_VERSION}</p>
                  <p className="text-xs text-muted-foreground/70">by Peachycloud Security</p>
                </div>
              </div>
              
              {/* Nav Links */}
              <nav className="hidden md:flex items-center gap-4">
                <a href="https://peachycloudsecurity.com" target="_blank" rel="noopener noreferrer" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                  Home
                </a>
                <a href="https://peachycloudsecurity.com/about" target="_blank" rel="noopener noreferrer" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                  About
                </a>
              </nav>
            </div>
            
            {/* Center: Scan State (mobile shows logo text here) */}
            <div className="flex items-center gap-3 sm:hidden">
              <span className="text-lg font-bold text-foreground">CloudGuard</span>
            </div>
            
            {/* Right: Actions */}
            <div className="flex items-center gap-2 sm:gap-3">
              <div className="hidden sm:flex items-center gap-2">
                <ScanStateIndicator state={scanState} />
                {detectedType && detectedType !== 'unknown' && (
                  <FileTypeBadge fileType={detectedType} />
                )}
              </div>
              
              {/* Theme Toggle */}
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleTheme}
                className="h-9 w-9"
                title={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'}
              >
                {isDarkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              </Button>
              
              {/* YouTube Follow */}
              <a
                href="https://www.youtube.com/@peachycloudsecurity"
                target="_blank"
                rel="noopener noreferrer"
                className="hidden sm:inline-flex"
              >
                <Button variant="ghost" size="sm" className="gap-1.5 text-muted-foreground hover:text-red-500">
                  <Youtube className="w-4 h-4" />
                  <span className="hidden lg:inline">Follow</span>
                </Button>
              </a>
              
              {/* Book a Session */}
              <a
                href="https://topmate.io/peachycloudsecurity"
                target="_blank"
                rel="noopener noreferrer"
                className="hidden sm:inline-flex"
              >
                <Button variant="ghost" size="sm" className="gap-1.5 text-muted-foreground hover:text-foreground">
                  <Calendar className="w-4 h-4" />
                  <span className="hidden lg:inline">Book a Session</span>
                </Button>
              </a>
              
              {/* Buy Me a Coffee */}
              <a
                href="https://github.com/sponsors/peachycloudsecurity"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button variant="ghost" size="icon" className="h-9 w-9 text-muted-foreground hover:text-amber-500" title="Sponsor on GitHub">
                  <Coffee className="w-4 h-4" />
                </Button>
              </a>
            </div>
          </div>
        </div>
      </header>
      
      {/* Main Content */}
      <main className="container mx-auto px-4 py-6 space-y-6 flex-1">
        {/* Mobile: Scan State */}
        <div className="flex sm:hidden items-center gap-2 justify-center">
          <ScanStateIndicator state={scanState} />
          {detectedType && detectedType !== 'unknown' && (
            <FileTypeBadge fileType={detectedType} />
          )}
        </div>
        
        {/* Page Title */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">IaC Security Scanner</h1>
          <p className="text-xl text-muted-foreground">
            Scan your Infrastructure as Code files for security vulnerabilities
          </p>
          
          <div className="flex flex-wrap items-center justify-center gap-4 mt-6 text-foreground">
            <div className="inline-flex items-center gap-2">
              <Shield className="w-4 h-4" />
              <span>All analysis runs locally in your browser</span>
            </div>
            <div className="inline-flex items-center gap-2">
              <Lock className="w-4 h-4" />
              <span>No files are uploaded or stored</span>
            </div>
          </div>
        </div>
        
        {/* Input Section */}
        <div className="scanner-card p-4 sm:p-6">
          <Tabs
            value={inputMethod}
            onValueChange={(v) => setInputMethod(v as 'upload' | 'paste' | 'examples' | 'github')}
          >
            <TabsList className="mb-4 bg-muted/50">
              <TabsTrigger value="upload" className="gap-2">
                <Upload className="w-4 h-4" />
                <span className="hidden sm:inline">Upload File</span>
                <span className="sm:hidden">Upload</span>
              </TabsTrigger>
              <TabsTrigger value="paste" className="gap-2">
                <Code className="w-4 h-4" />
                <span className="hidden sm:inline">Paste Code</span>
                <span className="sm:hidden">Paste</span>
              </TabsTrigger>
              <TabsTrigger value="examples" className="gap-2">
                <BookOpen className="w-4 h-4" />
                <span className="hidden sm:inline">Examples</span>
                <span className="sm:hidden">Examples</span>
              </TabsTrigger>
              <TabsTrigger value="github" className="gap-2">
                <Github className="w-4 h-4" />
                <span className="hidden sm:inline">GitHub Repo</span>
                <span className="sm:hidden">GitHub</span>
              </TabsTrigger>
            </TabsList>
            
            <TabsContent value="upload">
              <FileUpload onFileSelect={handleFileSelect} disabled={isScanning} />
            </TabsContent>
            
            <TabsContent value="paste">
              <CodeInput
                value={code}
                onChange={handleCodeChange}
                disabled={isScanning}
              />
            </TabsContent>

            <TabsContent value="examples">
              <ExamplesPanel onSelectExample={handleExampleSelect} />
            </TabsContent>

            <TabsContent value="github">
              <GitHubInput onScan={handleGitHubScan} isScanning={isScanning} />
              {githubProgress && (
                <div className="mt-4 p-4 bg-muted/30 rounded-lg border border-border space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin text-primary" />
                      <span className="text-sm font-medium">
                        {scanState === 'parsing' ? 'Fetching files from GitHub...' : 'Scanning files...'}
                      </span>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {githubProgress.current} / {githubProgress.total > 0 ? githubProgress.total : '?'}
                    </span>
                  </div>
                  
                  {githubStatus && (
                    <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                      <p className="text-xs font-medium text-yellow-600 dark:text-yellow-400">
                        {githubStatus}
                      </p>
                    </div>
                  )}
                  
                  {githubProgress.file && !githubStatus && (
                    <div className="space-y-1">
                      <p className="text-xs font-medium text-foreground">
                        {githubProgress.file}
                      </p>
                      {githubProgress.total > 0 && (
                        <p className="text-xs text-muted-foreground">
                          {Math.round((githubProgress.current / githubProgress.total) * 100)}% complete
                        </p>
                      )}
                    </div>
                  )}
                  
                  <div className="w-full bg-background rounded-full h-3 overflow-hidden">
                    <div
                      className="bg-primary h-3 rounded-full transition-all duration-300 flex items-center justify-end pr-1"
                      style={{ 
                        width: githubProgress.total > 0 
                          ? `${Math.min((githubProgress.current / githubProgress.total) * 100, 100)}%` 
                          : '10%'
                      }}
                    >
                      {githubProgress.total > 0 && (
                        <span className="text-[10px] text-primary-foreground font-medium">
                          {Math.round((githubProgress.current / githubProgress.total) * 100)}%
                        </span>
                      )}
                    </div>
                  </div>
                  
                  {scanState === 'parsing' && (
                    <div className="text-xs text-muted-foreground space-y-1">
                      <p>⏳ This may take several minutes for large repositories...</p>
                      <p>📊 Rate limiting is active to prevent API abuse</p>
                      <p>🌐 Your browser will make API calls to GitHub to fetch files (no data is sent to our servers)</p>
                    </div>
                  )}
                </div>
              )}
            </TabsContent>
          </Tabs>
          
          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3 mt-4 pt-4 border-t border-border">
            {inputMethod !== 'github' && (
            <Button
              onClick={handleScan}
              disabled={!canScan}
              className="gap-2"
              size="lg"
            >
              <Play className="w-4 h-4" />
              {isScanning ? 'Scanning...' : 'Run Scan'}
            </Button>
            )}
            
            {(scanResult || multiFileResult) && (
              <>
                <Button
                  variant="outline"
                  onClick={handleExport}
                  className="gap-2"
                >
                  <FileDown className="w-4 h-4" />
                  Export PDF
                </Button>
                <Button
                  variant="ghost"
                  onClick={handleReset}
                  className="gap-2"
                >
                  <RotateCcw className="w-4 h-4" />
                  Reset
                </Button>
              </>
            )}
          </div>
        </div>
        
        {/* Error Display */}
        {(scanState === 'error' && (scanResult?.error || multiFileResult?.error)) && (
          <div className="scanner-card p-4 border-severity-high/50 bg-severity-high/10">
            <h3 className="font-semibold text-severity-high mb-1">Scan Error</h3>
            <p className="text-sm text-foreground">{scanResult?.error || multiFileResult?.error}</p>
          </div>
        )}
        
        {/* Multi-File Results Section */}
        {multiFileResult && scanState === 'completed' && (
        <div className="space-y-3">
          {/* Aggregate all findings from all files - Same format as single file */}
            {(() => {
              const allFindings = multiFileResult.files.flatMap(f => f.findings);
              const filesWithFindings = multiFileResult.files.filter(f => f.findings.length > 0);
              const filesWithoutFindings = multiFileResult.files.filter(f => f.findings.length === 0 && !f.error);
              
              return (
                <>
                  <ScanSummary findings={allFindings} />
                  
                  {/* Per-file breakdown */}
                  {multiFileResult.files.length > 1 && (
                    <div className="scanner-card p-4">
                      <button
                        onClick={() => setFilesScannedExpanded(!filesScannedExpanded)}
                        className="w-full flex items-center gap-2 font-semibold text-foreground hover:text-primary transition-colors cursor-pointer py-1 mb-2"
                      >
                        {filesScannedExpanded ? (
                          <ChevronUp className="w-4 h-4" />
                        ) : (
                          <ChevronDown className="w-4 h-4" />
                        )}
                        <span>Files Scanned: {multiFileResult.files.length} files</span>
                      </button>
                      {filesScannedExpanded && (
                        <div className="max-h-96 overflow-y-scroll border border-border rounded-md p-3 bg-muted/20">
                          <div className="space-y-3 text-sm">
                            {filesWithFindings.length > 0 && (
                              <div>
                                <span className="font-medium text-foreground">Files with findings ({filesWithFindings.length}):</span>
                                <ul className="list-disc list-inside ml-2 mt-1 space-y-1">
                                  {filesWithFindings.map(f => (
                                    <li key={f.fileName} className="text-muted-foreground">
                                      {f.fileName} - {f.findings.length} finding{f.findings.length !== 1 ? 's' : ''}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {filesWithoutFindings.length > 0 && (
                              <div>
                                <span className="font-medium text-foreground">Files without findings ({filesWithoutFindings.length}):</span>
                                <ul className="list-disc list-inside ml-2 mt-1 space-y-1">
                                  {filesWithoutFindings.map(f => (
                                    <li key={f.fileName} className="text-muted-foreground">
                                      {f.fileName}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {multiFileResult.files.filter(f => f.error).length > 0 && (
                              <div>
                                <span className="font-medium text-destructive">Files with errors ({multiFileResult.files.filter(f => f.error).length}):</span>
                                <ul className="list-disc list-inside ml-2 mt-1 space-y-1">
                                  {multiFileResult.files.filter(f => f.error).map(f => (
                                    <li key={f.fileName} className="text-destructive">
                                      {f.fileName}: {f.error}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  
                  {allFindings.length > 0 && (
                    <FindingsTable findings={allFindings} />
                  )}
                  
                  <RulesPanel ruleExecutions={multiFileResult.files.flatMap(f => f.ruleExecutions || [])} />
                </>
              );
            })()}
          </div>
        )}

        {/* Single File Results Section */}
        {scanResult && scanState === 'completed' && !multiFileResult && (
          <div className="space-y-3">
            <ScanSummary findings={scanResult.findings} />
            
            {scanResult.findings.length > 0 && (
              <FindingsTable findings={scanResult.findings} />
            )}
            
            <RulesPanel ruleExecutions={scanResult.ruleExecutions} />
          </div>
        )}
      </main>
      
      {/* Subscribe / Waitlist CTA */}
      <section className="border-t border-border bg-card/30">
        <div className="container mx-auto px-4 py-6">
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 text-center">
            <p className="text-sm text-muted-foreground">Stay updated with new features and security rules</p>
            <div className="flex gap-3">
              <a
                href="https://www.youtube.com/@peachycloudsecurity"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button variant="outline" size="sm" className="gap-2">
                  <Youtube className="w-4 h-4" />
                  Subscribe
                </Button>
              </a>
              <a
                href="https://peachycloudsecurity.com"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button variant="secondary" size="sm" className="gap-2">
                  <ExternalLink className="w-4 h-4" />
                  Visit Website
                </Button>
              </a>
            </div>
          </div>
        </div>
      </section>
      
      {/* Footer */}
      <footer className="border-t border-border py-6 bg-background">
        <div className="container mx-auto px-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            {/* Footer Links */}
            <div className="flex items-center gap-6 text-sm">
              <a
                href="https://peachycloudsecurity.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                Website
              </a>
              <a
                href="https://github.com/peachycloudsecurity/iac-security-scanner"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors inline-flex items-center gap-1"
              >
                <Github className="w-4 h-4" />
                GitHub
              </a>
              <a
                href="https://topmate.io/peachycloudsecurity"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors inline-flex items-center gap-1"
              >
                <Calendar className="w-4 h-4" />
                Consultations
              </a>
            </div>
            
            {/* Branding Links */}
            <div className="flex items-center gap-4 text-xs">
              <a
                href="https://peachycloudsecurity.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground/70 hover:text-muted-foreground transition-colors inline-flex items-center gap-1"
              >
                Peachy Cloud Security
                <ExternalLink className="w-3 h-3" />
              </a>
              <a
                href="https://topmate.io/peachycloudsecurity"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground/70 hover:text-muted-foreground transition-colors inline-flex items-center gap-1"
              >
                <Calendar className="w-3 h-3" />
                1:1 Consultations
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
          
          {/* Bottom Line */}
          <div className="mt-4 pt-4 border-t border-border/50 text-center space-y-2">
            <p className="text-xs text-muted-foreground">
              CloudGuard Scanner • 100% Client-Side • No Data Leaves Your Browser
            </p>
            <p className="text-xs text-muted-foreground/70">
              Created by <span className="font-medium text-foreground">The Shukla Duo (Anjali & Divyanshu)</span> • 
              <a href="https://peachycloudsecurity.com" target="_blank" rel="noopener noreferrer" className="ml-1 hover:text-foreground transition-colors">
                Peachycloud Security
              </a>
            </p>
          </div>
        </div>
      </footer>

      {/* Rate Limit Confirmation Dialog */}
      <AlertDialog open={rateLimitDialog?.open || false} onOpenChange={(open) => {
        if (!open && rateLimitDialog) {
          handleRateLimitStop();
        }
      }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>GitHub API Rate Limit Exceeded</AlertDialogTitle>
            <AlertDialogDescription>
              You've hit the GitHub API rate limit. The rate limit will reset at{' '}
              <strong>{rateLimitDialog?.resetTime.toLocaleTimeString()}</strong>.
              <br /><br />
              Would you like to wait for the rate limit to reset ({rateLimitDialog?.waitMinutes} minutes) or stop the scan?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={handleRateLimitStop}>
              Stop Scan
            </AlertDialogCancel>
            <AlertDialogAction onClick={handleRateLimitWait}>
              Wait & Continue
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      
      {/* CTA Section - From main page */}
      <section className="py-8 sm:py-10 px-4 sm:px-6">
        <div className="max-w-2xl mx-auto text-center">
          <h2 className="text-xl sm:text-2xl lg:text-3xl font-bold mb-3 sm:mb-4">
            Ready to Level Up Your Cloud Security Skills?
          </h2>
          <p className="text-sm sm:text-base text-muted-foreground mb-4 sm:mb-6">
            Subscribe to get notified when new videos drop. Join thousands of
            security professionals learning cloud security the practical way.
          </p>
          <p className="text-base sm:text-lg font-semibold text-primary mb-3 sm:mb-4">@peachycloudsecurity</p>
          <div className="flex flex-wrap items-center justify-center gap-3 mb-4">
            <a href="https://peachycloudsecurity.com" target="_blank" rel="noopener noreferrer">
              <Button variant="outline" size="lg" className="gap-2">
                <ExternalLink className="h-5 w-5" />
                Visit Website
              </Button>
            </a>
            <a href="https://www.youtube.com/@peachycloudsecurity" target="_blank" rel="noopener noreferrer">
              <Button size="lg" className="gap-2 bg-red-600 hover:bg-red-700 text-white border-0">
                <Youtube className="h-5 w-5" />
                Subscribe on YouTube
              </Button>
            </a>
            <a href="https://topmate.io/peachycloudsecurity" target="_blank" rel="noopener noreferrer">
              <Button variant="outline" size="lg" className="gap-2">
                <Calendar className="h-5 w-5" />
                1:1 Consultations
              </Button>
            </a>
          </div>
          <div className="mt-4">
            <a
              href="https://github.com/sponsors/peachycloudsecurity"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-muted-foreground hover:text-red-500 transition-colors"
              aria-label="Sponsor on GitHub"
            >
              <Heart className="h-5 w-5" />
              <span className="text-sm">Sponsor On GitHub</span>
            </a>
          </div>
        </div>
      </section>
    </div>
  );
}
