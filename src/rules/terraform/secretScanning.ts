import { Rule, Finding, ParsedFile } from '@/types/scanner';
import { TerraformParsed, TerraformBlock } from '@/parsers/terraformParser';

function getAttrValue(attrs: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = attrs;
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
    /[Ss][Hh][Aa][Rr][Ee][Dd][_-]?[Ss]ecret\s*[:=]\s*["']?[^"'\s]{10,}/,
    /BEGIN\s+(RSA\s+)?PRIVATE\s+KEY/,
    /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
  ];
  return secretPatterns.some(pattern => pattern.test(text));
}

export const terraformSecretScanningRules: Rule[] = [
  // Hardcoded Secrets in Variables
  {
    id: 'TF_SECRET_001',
    title: 'Terraform variables contain no hardcoded secrets',
    description: 'CREDENTIAL EXPOSURE: Hardcoded secrets in variable defaults are committed to git, visible in state files, and never rotate. High risk of credential theft.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'variable') {
          const defaultValue = getAttrValue(block.attributes, 'default');
          if (typeof defaultValue === 'string' && checkForSecrets(defaultValue)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-hardcoded-secret`,
              ruleId: this.id,
              title: this.title,
              description: `CREDENTIAL LEAK: Variable "${block.name}" has hardcoded secret in default value. Visible in git history, Terraform state, and plan output.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `variable.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Remove default value. Use: 1) terraform.tfvars (gitignored) 2) Environment variables (TF_VAR_*) 3) AWS Secrets Manager 4) HashiCorp Vault.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Hardcoded Secrets in Outputs
  {
    id: 'TF_SECRET_002',
    title: 'Terraform outputs contain no sensitive data',
    description: 'SECRET LEAK: Outputs with secrets visible in terraform state, plan output, and CLI. Anyone with state access can retrieve credentials.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'output') {
          const value = getAttrValue(block.attributes, 'value');
          const sensitive = getAttrValue(block.attributes, 'sensitive');
          
          if (sensitive !== true) {
            const valueStr = typeof value === 'string' ? value : JSON.stringify(value || '');
            if (checkForSecrets(valueStr)) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-sensitive-output`,
                ruleId: this.id,
                title: this.title,
                description: `CREDENTIAL EXPOSURE: Output "${block.name}" contains secrets but is not marked sensitive. Visible in terraform state and plan output.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `output.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Add sensitive = true to output block. Better: Remove secret from output entirely. Use AWS Secrets Manager or Parameter Store for credential retrieval.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // Hardcoded Secrets in Locals
  {
    id: 'TF_SECRET_003',
    title: 'Terraform locals contain no hardcoded secrets',
    description: 'CREDENTIAL EXPOSURE: Hardcoded secrets in locals are committed to git and visible in all Terraform operations. Never expire or rotate.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'locals') {
          for (const [key, value] of Object.entries(block.attributes)) {
            const valueStr = typeof value === 'string' ? value : JSON.stringify(value || '');
            if (checkForSecrets(valueStr)) {
              findings.push({
                id: `${parsedFile.fileName}-locals-${key}-hardcoded-secret`,
                ruleId: this.id,
                title: this.title,
                description: `CREDENTIAL LEAK: Local "${key}" contains hardcoded secret. Visible in git history and Terraform state.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `locals.${key}`,
                lineNumber: block.startLine,
                remediation: 'Remove hardcoded secret from locals. Use: 1) Variables with tfvars 2) Data sources (aws_secretsmanager_secret_version) 3) External data sources.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // Hardcoded Secrets in Resource Attributes
  {
    id: 'TF_SECRET_004',
    title: 'Terraform resources contain no hardcoded secrets',
    description: 'CREDENTIAL EXPOSURE: Hardcoded secrets in resource attributes (passwords, keys, tokens) are committed to git and visible in state files.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      const sensitiveAttributes = ['password', 'secret', 'api_key', 'access_key', 'token', 'private_key', 'credential'];

      for (const block of parsed.blocks) {
        if (block.type === 'resource') {
          for (const [attrPath, value] of Object.entries(block.attributes)) {
            const isSensitive = sensitiveAttributes.some(sa => attrPath.toLowerCase().includes(sa));
            
            if (isSensitive && typeof value === 'string' && value.length > 0) {
              // Skip if it's a reference (starts with var., data., etc.)
              if (!value.match(/^(var\.|data\.|aws_|local\.)/) && checkForSecrets(value)) {
                findings.push({
                  id: `${parsedFile.fileName}-${block.name}-${attrPath}-hardcoded-secret`,
                  ruleId: this.id,
                  title: this.title,
                  description: `CREDENTIAL LEAK: Resource "${block.resourceType}.${block.name}" has hardcoded secret in "${attrPath}". Visible in git and Terraform state.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `${block.resourceType}.${block.name}.${attrPath}`,
                  lineNumber: block.startLine,
                  remediation: `Replace hardcoded value with: var.${attrPath} or data.aws_secretsmanager_secret_version.${attrPath}.secret_string. Use secrets manager or variables.`,
                });
              }
            }
          }
        }
      }
      return findings;
    },
  },
];
