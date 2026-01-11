import { Rule, Finding, ParsedFile } from '@/types/scanner';

export const yamlPlaceholderRule: Rule = {
  id: 'YAML-001',
  title: 'Potential Sensitive Data in YAML',
  description: 'YAML files may contain sensitive information like passwords or API keys.',
  severity: 'LOW',
  applicableFileTypes: ['yaml'],
  
  evaluate(parsedFile: ParsedFile): Finding[] {
    const findings: Finding[] = [];
    const content = parsedFile.content.toLowerCase();
    
    const sensitivePatterns = [
      { pattern: /password\s*[:=]\s*["']?[^"'\s]+["']?/gi, type: 'password' },
      { pattern: /api[_-]?key\s*[:=]\s*["']?[^"'\s]+["']?/gi, type: 'API key' },
      { pattern: /secret\s*[:=]\s*["']?[^"'\s]+["']?/gi, type: 'secret' },
    ];
    
    for (const { pattern, type } of sensitivePatterns) {
      const matches = content.match(pattern);
      if (matches) {
        // Find line numbers
        const lines = parsedFile.lines;
        for (let i = 0; i < lines.length; i++) {
          if (pattern.test(lines[i])) {
            findings.push({
              id: `${parsedFile.fileName}-line${i + 1}-${type}`,
              ruleId: this.id,
              title: `Potential ${type} detected`,
              description: `Line ${i + 1} may contain a hardcoded ${type}.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              lineNumber: i + 1,
              remediation: `Use environment variables or a secrets manager instead of hardcoding ${type}s.`,
            });
          }
        }
      }
    }
    
    return findings;
  },
};
