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

export const terraformAwsLoggingRules: Rule[] = [
  // CloudTrail Log Validation
  {
    id: 'TF_AWS_LOG_001',
    title: 'CloudTrail log validation enabled',
    description: 'CloudTrail should have log file validation enabled to detect tampering.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_cloudtrail') {
          const enableLogFileValidation = getAttrValue(block.attributes, 'enable_log_file_validation');
          if (isFalseOrMissing(enableLogFileValidation)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-validation`,
              ruleId: this.id,
              title: this.title,
              description: `CloudTrail "${block.name}" does not have log file validation enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_cloudtrail.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set enable_log_file_validation to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // CloudTrail Multi-Region
  {
    id: 'TF_AWS_LOG_002',
    title: 'CloudTrail multi-region enabled',
    description: 'CloudTrail should be configured as multi-region to capture all API calls.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_cloudtrail') {
          const isMultiRegion = getAttrValue(block.attributes, 'is_multi_region_trail');
          if (isFalseOrMissing(isMultiRegion)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-not-multiregion`,
              ruleId: this.id,
              title: this.title,
              description: `CloudTrail "${block.name}" is not configured as multi-region.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_cloudtrail.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set is_multi_region_trail to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // CloudWatch Log Group Retention
  {
    id: 'TF_AWS_LOG_003',
    title: 'CloudWatch log retention configured',
    description: 'CloudWatch log groups should have retention periods configured to manage costs.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_cloudwatch_log_group') {
          const retentionInDays = getAttrValue(block.attributes, 'retention_in_days');
          if (isFalseOrMissing(retentionInDays)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-retention`,
              ruleId: this.id,
              title: this.title,
              description: `CloudWatch log group "${block.name}" does not have retention days specified.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_cloudwatch_log_group.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set retention_in_days to a value between 1 and 3653.',
            });
          }
        }
      }
      return findings;
    },
  },

  // S3 Access Logs
  {
    id: 'TF_AWS_LOG_004',
    title: 'S3 bucket access logging enabled',
    description: 'S3 buckets should have access logging enabled for security auditing.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket') {
          const logging = getAttrValue(block.attributes, 'logging');
          if (!logging) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-logging`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket "${block.name}" does not have access logging enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_s3_bucket.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add logging block with target_bucket and target_prefix.',
            });
          }
        }
      }
      return findings;
    },
  },

  // S3 Versioning
  {
    id: 'TF_AWS_LOG_005',
    title: 'S3 bucket versioning enabled',
    description: 'S3 buckets should have versioning enabled for data protection and recovery.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket') {
          const versioning = getAttrValue(block.attributes, 'versioning');
          if (!versioning || (typeof versioning === 'object' && 
              getAttrValue(versioning as Record<string, unknown>, 'enabled') !== true)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-versioning`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket "${block.name}" does not have versioning enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_s3_bucket.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add versioning block with enabled set to true.',
            });
          }
        }
      }
      return findings;
    },
  },
];
