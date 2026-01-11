import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface TerraformBlock {
  type: string;
  resourceType?: string;
  name: string;
  attributes: Record<string, unknown>;
  startLine: number;
}

interface TerraformParsed {
  blocks: TerraformBlock[];
}

function getAttrValue(attrs: Record<string, unknown>, key: string): unknown {
  const value = attrs[key];
  if (Array.isArray(value) && value.length > 0) {
    return value[0];
  }
  return value;
}

function isFalseOrMissing(value: unknown): boolean {
  return value === false || value === undefined || value === null;
}

export const terraformAwsBackupRules: Rule[] = [
  // RDS Deletion Protection
  {
    id: 'TF_AWS_BACKUP_001',
    title: 'RDS cluster deletion protection enabled',
    description: 'RDS clusters should have deletion protection enabled to prevent accidental deletion.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_rds_cluster') {
          const deletionProtection = getAttrValue(block.attributes, 'deletion_protection');
          if (isFalseOrMissing(deletionProtection)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-deletion-protection`,
              ruleId: this.id,
              title: this.title,
              description: `RDS cluster "${block.name}" does not have deletion protection enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_rds_cluster.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set deletion_protection to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // RDS Instance Deletion Protection
  {
    id: 'TF_AWS_BACKUP_002',
    title: 'RDS instance deletion protection enabled',
    description: 'RDS instances should have deletion protection enabled to prevent accidental deletion.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_db_instance') {
          const deletionProtection = getAttrValue(block.attributes, 'deletion_protection');
          if (isFalseOrMissing(deletionProtection)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-deletion-protection`,
              ruleId: this.id,
              title: this.title,
              description: `RDS instance "${block.name}" does not have deletion protection enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_db_instance.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set deletion_protection to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // RDS Backup Retention
  {
    id: 'TF_AWS_BACKUP_003',
    title: 'RDS backup retention configured',
    description: 'RDS instances should have backup retention configured for disaster recovery.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_db_instance') {
          const backupRetentionPeriod = getAttrValue(block.attributes, 'backup_retention_period');
          const backupRetentionPeriodNum = typeof backupRetentionPeriod === 'number' ? backupRetentionPeriod : 0;
          
          if (backupRetentionPeriodNum < 7) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-insufficient-backup`,
              ruleId: this.id,
              title: this.title,
              description: `RDS instance "${block.name}" has backup retention period less than 7 days (or not configured).`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_db_instance.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set backup_retention_period to at least 7 days.',
            });
          }
        }
      }
      return findings;
    },
  },
];
