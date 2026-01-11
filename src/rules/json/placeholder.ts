import { Rule, Finding, ParsedFile } from '@/types/scanner';

export const jsonPlaceholderRule: Rule = {
  id: 'JSON-001',
  title: 'Potential Sensitive Data in JSON',
  description: 'JSON configuration files may contain sensitive information.',
  severity: 'LOW',
  applicableFileTypes: ['json'],
  
  evaluate(parsedFile: ParsedFile): Finding[] {
    const findings: Finding[] = [];
    
    const checkForSensitiveKeys = (obj: unknown, path: string = ''): void => {
      if (!obj || typeof obj !== 'object') return;
      
      const sensitiveKeys = ['password', 'secret', 'apiKey', 'api_key', 'token', 'credentials', 'private_key'];
      
      if (Array.isArray(obj)) {
        obj.forEach((item, index) => {
          checkForSensitiveKeys(item, `${path}[${index}]`);
        });
      } else {
        for (const [key, value] of Object.entries(obj)) {
          const currentPath = path ? `${path}.${key}` : key;
          
          const isSensitive = sensitiveKeys.some(sk => 
            key.toLowerCase().includes(sk.toLowerCase())
          );
          
          if (isSensitive && value && typeof value === 'string' && value.length > 0) {
            // Check if it looks like an actual value (not a placeholder or reference)
            const isPlaceholder = /^\$\{.*\}$|^<.*>$|^\{\{.*\}\}$/.test(value);
            
            if (!isPlaceholder) {
              findings.push({
                id: `${parsedFile.fileName}-${currentPath}`,
                ruleId: this.id,
                title: `Potential sensitive value in "${key}"`,
                description: `Key "${key}" at path "${currentPath}" may contain sensitive data.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: currentPath,
                remediation: 'Use environment variables or a secrets manager. Replace with ${ENV_VAR} placeholder.',
              });
            }
          }
          
          if (typeof value === 'object') {
            checkForSensitiveKeys(value, currentPath);
          }
        }
      }
    };
    
    try {
      checkForSensitiveKeys(parsedFile.parsed);
    } catch {
      // Ignore parsing errors in evaluation
    }
    
    return findings;
  },
};
