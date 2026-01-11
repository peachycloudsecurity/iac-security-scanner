export type FileType = 
  | 'terraform'
  | 'json'
  | 'yaml'
  | 'kubernetes'
  | 'dockerfile'
  | 'docker-compose'
  | 'cloudformation'
  | 'unknown';

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export type ScanState = 'idle' | 'parsing' | 'scanning' | 'completed' | 'error';

export interface ParsedFile {
  fileName: string;
  fileType: FileType;
  content: string;
  parsed: unknown;
  lines: string[];
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  fileName: string;
  resourcePath?: string;
  lineNumber?: number;
  remediation: string;
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  applicableFileTypes: FileType[];
  evaluate: (parsedFile: ParsedFile) => Finding[];
}

export interface RuleExecution {
  rule: Rule;
  status: 'executed' | 'skipped';
  reason?: string;
}

export interface ScanResult {
  state: ScanState;
  parsedFile?: ParsedFile;
  findings: Finding[];
  ruleExecutions: RuleExecution[];
  error?: string;
  timestamp: Date;
}

export interface MultiFileScanResult {
  state: ScanState;
  files: Array<{
    fileName: string;
    fileType: FileType;
    findings: Finding[];
    parsedFile?: ParsedFile;
    ruleExecutions?: RuleExecution[];
    error?: string;
  }>;
  totalFindings: number;
  findingsBySeverity: {
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  error?: string;
  timestamp: Date;
}
