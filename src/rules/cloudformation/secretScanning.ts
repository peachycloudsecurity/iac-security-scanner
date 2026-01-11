import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface CloudFormationResource {
  Type: string;
  Properties?: Record<string, unknown>;
}

interface CloudFormationTemplate {
  AWSTemplateFormatVersion?: string;
  Resources?: Record<string, CloudFormationResource>;
  Parameters?: Record<string, unknown>;
  Outputs?: Record<string, unknown>;
}

function getProperty(resource: CloudFormationResource, path: string): unknown {
  const parts = path.split('/');
  let current: unknown = resource.Properties;
  
  for (const part of parts) {
    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  
  return current;
}

function checkForSecrets(text: string): boolean {
  const secretPatterns = [
    /AKIA[0-9A-Z]{16}/, // AWS Access Key ID
    /ASIA[0-9A-Z]{16}/, // AWS Session Token
    /[Pp]assword\s*[:=]\s*["']?[^"'\s]{8,}/,
    /[Ss]ecret[_-]?[Aa]ccess[_-]?[Kk]ey\s*[:=]\s*["']?[^"'\s]{20,}/,
    /[Aa][Pp][Ii][_-]?[Kk]ey\s*[:=]\s*["']?[^"'\s]{10,}/,
    /[Tt]oken\s*[:=]\s*["']?[^"'\s]{10,}/,
    /[Pp]rivate[_-]?[Kk]ey\s*[:=]\s*["']?-----BEGIN/,
    /BEGIN\s+(RSA\s+)?PRIVATE\s+KEY/,
  ];
  return secretPatterns.some(pattern => pattern.test(text));
}

export const cloudformationSecretScanningRules: Rule[] = [
  // Hardcoded Secrets in Parameters
  {
    id: 'CFN_SECRET_001',
    title: 'CloudFormation parameters contain no hardcoded secrets',
    description: 'CREDENTIAL EXPOSURE: Hardcoded secrets in parameter defaults are visible in stack templates, console, and git history. Never rotate.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      if (!parsed?.Parameters) return findings;

      for (const [paramName, param] of Object.entries(parsed.Parameters)) {
        if (typeof param === 'object' && param !== null) {
          const paramObj = param as Record<string, unknown>;
          const defaultValue = paramObj.Default;
          const noEcho = paramObj.NoEcho;
          
          if (typeof defaultValue === 'string' && defaultValue.length > 0) {
            if (checkForSecrets(defaultValue)) {
              findings.push({
                id: `${parsedFile.fileName}-parameter-${paramName}-hardcoded-secret`,
                ruleId: this.id,
                title: this.title,
                description: `CREDENTIAL LEAK: Parameter "${paramName}" has hardcoded secret in Default value${noEcho ? ' (NoEcho helps but still visible in template)' : ''}. Visible in CloudFormation console and git.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `Parameters/${paramName}`,
                remediation: 'Remove Default value. Use: 1) AWS Systems Manager Parameter Store 2) AWS Secrets Manager 3) Stack parameters (no default) 4) Dynamic references: {{resolve:secretsmanager:...}}.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // Hardcoded Secrets in Resource Properties
  {
    id: 'CFN_SECRET_002',
    title: 'CloudFormation resources contain no hardcoded secrets',
    description: 'CREDENTIAL EXPOSURE: Hardcoded secrets in resource properties are visible in stack templates, events, and git history. High risk of credential theft.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      if (!parsed?.Resources) return findings;

      const sensitiveProperties = ['password', 'secret', 'apiKey', 'accessKey', 'token', 'privateKey', 'credential', 'key'];

      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        const properties = resource.Properties || {};
        
        for (const [propName, propValue] of Object.entries(properties)) {
          const isSensitive = sensitiveProperties.some(sp => propName.toLowerCase().includes(sp.toLowerCase()));
          
          if (isSensitive && typeof propValue === 'string' && propValue.length > 0) {
            // Skip if it's a CloudFormation function (Ref, GetAtt, etc.)
            if (!propValue.match(/^\{\{|\!Ref|\!GetAtt|\!Sub|\!Join/) && checkForSecrets(propValue)) {
              findings.push({
                id: `${parsedFile.fileName}-${resourceName}-${propName}-hardcoded-secret`,
                ruleId: this.id,
                title: this.title,
                description: `CREDENTIAL LEAK: Resource "${resourceName}" has hardcoded secret in property "${propName}". Visible in CloudFormation events, console, and git history.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `Resources/${resourceName}/Properties/${propName}`,
                remediation: `Replace hardcoded value with: {{resolve:secretsmanager:secret-name:SecretString:key}} or use Parameters with NoEcho: true. Use AWS Secrets Manager for credential management.`,
              });
            }
          }
        }
      }
      return findings;
    },
  },
];
