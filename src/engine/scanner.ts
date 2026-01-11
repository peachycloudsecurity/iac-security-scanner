import { FileType, ParsedFile, Finding, RuleExecution, ScanResult, ScanState, MultiFileScanResult } from '@/types/scanner';
import { detectFileType } from '@/utils/fileDetector';
import { parseFile } from '@/parsers';
import { ruleRegistry } from '@/rules';

export interface ScanOptions {
  fileName?: string;
  content: string;
  onStateChange?: (state: ScanState) => void;
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const { fileName = 'input', content, onStateChange } = options;
  const findings: Finding[] = [];
  const ruleExecutions: RuleExecution[] = [];
  
  const updateState = (state: ScanState) => {
    onStateChange?.(state);
  };
  
  try {
    // Phase 1: Detect file type
    updateState('parsing');
    await delay(100); // Small delay for UI feedback
    
    const fileType = detectFileType(fileName, content);
    
    if (fileType === 'unknown') {
      return {
        state: 'error',
        findings: [],
        ruleExecutions: [],
        error: 'Could not detect file type. Please ensure the file has a valid extension or recognizable content.',
        timestamp: new Date(),
      };
    }
    
    // Phase 2: Parse file
    let parsedFile: ParsedFile;
    try {
      parsedFile = parseFile(fileName, content, fileType);
    } catch (parseError) {
      return {
        state: 'error',
        findings: [],
        ruleExecutions: [],
        error: parseError instanceof Error ? parseError.message : 'Failed to parse file',
        timestamp: new Date(),
      };
    }
    
    // Phase 3: Run rules
    updateState('scanning');
    await delay(100);
    
    for (const rule of ruleRegistry) {
      const isApplicable = rule.applicableFileTypes.includes(fileType);
      
      if (isApplicable) {
        try {
          const ruleFindings = rule.evaluate(parsedFile);
          findings.push(...ruleFindings);
          ruleExecutions.push({
            rule,
            status: 'executed',
          });
        } catch (evalError) {
          ruleExecutions.push({
            rule,
            status: 'skipped',
            reason: `Evaluation error: ${evalError instanceof Error ? evalError.message : 'Unknown error'}`,
          });
        }
      } else {
        ruleExecutions.push({
          rule,
          status: 'skipped',
          reason: `Not applicable to ${fileType} files`,
        });
      }
    }
    
    updateState('completed');
    
    return {
      state: 'completed',
      parsedFile,
      findings,
      ruleExecutions,
      timestamp: new Date(),
    };
    
  } catch (error) {
    updateState('error');
    return {
      state: 'error',
      findings: [],
      ruleExecutions: [],
      error: error instanceof Error ? error.message : 'An unexpected error occurred',
      timestamp: new Date(),
    };
  }
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function getSeverityCounts(findings: Finding[]): Record<string, number> {
  return findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
}

/**
 * Scan multiple files and aggregate results
 */
export async function runMultiFileScan(
  files: Array<{ fileName: string; content: string }>,
  onProgress?: (current: number, total: number, currentFile?: string) => void
): Promise<MultiFileScanResult> {
  const allFindings: Finding[] = [];
  const fileResults: MultiFileScanResult['files'] = [];
  
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    onProgress?.(i + 1, files.length, file.fileName);
    
    try {
      const fileType = detectFileType(file.fileName, file.content);
      
      if (fileType === 'unknown') {
        fileResults.push({
          fileName: file.fileName,
          fileType: 'unknown',
          findings: [],
          error: 'Could not detect file type',
        });
        continue;
      }
      
      const parsedFile = parseFile(file.fileName, file.content, fileType);
      const fileFindings: Finding[] = [];
      const ruleExecutions: RuleExecution[] = [];
      
      // Run applicable rules
      for (const rule of ruleRegistry) {
        if (rule.applicableFileTypes.includes(fileType)) {
          try {
            const ruleFindings = rule.evaluate(parsedFile);
            fileFindings.push(...ruleFindings);
            ruleExecutions.push({
              rule,
              status: 'executed',
            });
          } catch (error) {
            // Skip rule if evaluation fails
            console.warn(`Rule ${rule.id} failed for ${file.fileName}:`, error);
            ruleExecutions.push({
              rule,
              status: 'skipped',
              reason: error instanceof Error ? error.message : 'Unknown error',
            });
          }
        } else {
          ruleExecutions.push({
            rule,
            status: 'skipped',
            reason: `Not applicable to ${fileType} files`,
          });
        }
      }
      
      fileResults.push({
        fileName: file.fileName,
        fileType,
        findings: fileFindings,
        parsedFile,
        ruleExecutions,
      });
      
      allFindings.push(...fileFindings);
    } catch (error) {
      fileResults.push({
        fileName: file.fileName,
        fileType: 'unknown',
        findings: [],
        error: error instanceof Error ? error.message : 'Failed to scan file',
      });
    }
  }
  
  // Calculate severity counts
  const findingsBySeverity = {
    HIGH: allFindings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: allFindings.filter(f => f.severity === 'MEDIUM').length,
    LOW: allFindings.filter(f => f.severity === 'LOW').length,
  };
  
  return {
    state: 'completed',
    files: fileResults,
    totalFindings: allFindings.length,
    findingsBySeverity,
    timestamp: new Date(),
  };
}
