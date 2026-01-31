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

export const terraformAwsMessagingRules: Rule[] = [
  // SNS Topic Encryption
  {
    id: 'TF_AWS_SNS_001',
    title: 'SNS topic encryption enabled',
    description: 'UNENCRYPTED DATA: SNS topic without encryption exposes message content in transit and at rest. AWS can read your messages. Compliance violation for PII/PHI data.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sns_topic') {
          const kmsMasterKeyId = getAttrValue(block.attributes, 'kms_master_key_id');
          if (isFalseOrMissing(kmsMasterKeyId)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-sns-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT MESSAGES: SNS topic "${block.name}" stores and transmits messages without encryption. Messages readable by AWS, not compliant with GDPR/HIPAA. Attackers with AWS access can read all messages.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_sns_topic.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add kms_master_key_id = aws_kms_key.sns_key.id to enable encryption at rest. Create KMS key: resource "aws_kms_key" "sns_key" { enable_key_rotation = true }',
            });
          }
        }
      }
      return findings;
    },
  },

  // SQS Queue Encryption
  {
    id: 'TF_AWS_SQS_001',
    title: 'SQS queue encryption enabled',
    description: 'UNENCRYPTED QUEUE: SQS queue without encryption stores message content in plaintext. AWS support and admins can read messages. Compliance violation.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sqs_queue') {
          const kmsMasterKeyId = getAttrValue(block.attributes, 'kms_master_key_id');
          const sseEnabled = getAttrValue(block.attributes, 'sqs_managed_sse_enabled');

          // Check if neither KMS nor SQS-managed SSE is enabled
          if (isFalseOrMissing(kmsMasterKeyId) && isFalseOrMissing(sseEnabled)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-sqs-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT QUEUE: SQS queue "${block.name}" stores messages without encryption. Messages persisted in plaintext on AWS disk. Vulnerable to AWS insider threats and compliance audits.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_sqs_queue.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add kms_master_key_id = aws_kms_key.sqs_key.id for customer-managed encryption OR set sqs_managed_sse_enabled = true for AWS-managed encryption.',
            });
          }
        }
      }
      return findings;
    },
  },

  // SQS Queue Policy Public Access
  {
    id: 'TF_AWS_SQS_003',
    title: 'SQS queue policy restricts public access',
    description: 'PUBLIC QUEUE ACCESS: Queue policy with Principal="*" allows anyone on internet to read/send messages. No authentication required.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sqs_queue_policy') {
          const policy = getAttrValue(block.attributes, 'policy');

          if (typeof policy === 'object' && policy !== null) {
            const policyDoc = policy as Record<string, unknown>;
            const statements = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');

            if (Array.isArray(statements)) {
              for (const stmt of statements) {
                if (typeof stmt !== 'object' || stmt === null) continue;
                const statement = stmt as Record<string, unknown>;
                const principal = getAttrValue(statement, 'Principal') || getAttrValue(statement, 'principal');
                const effect = getAttrValue(statement, 'Effect') || getAttrValue(statement, 'effect');

                if ((effect === 'Allow' || effect === 'allow') && principal === '*') {
                  findings.push({
                    id: `${parsedFile.fileName}-${block.name}-sqs-public-policy`,
                    ruleId: this.id,
                    title: this.title,
                    description: `ANONYMOUS ACCESS: SQS queue policy "${block.name}" allows Principal="*" - anyone can send/receive messages without AWS credentials. Queue data fully exposed to internet.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_sqs_queue_policy.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: 'Change Principal from "*" to specific ARN: "arn:aws:iam::ACCOUNT-ID:root" or use Condition with aws:SourceAccount/aws:SourceArn to restrict access.',
                  });
                  break;
                }
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // SNS Topic Policy Public Access
  {
    id: 'TF_AWS_SNS_003',
    title: 'SNS topic policy restricts public access',
    description: 'PUBLIC TOPIC: SNS topic with Principal="*" allows unauthenticated message publishing. Spam/abuse risk and potential data exfiltration vector.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sns_topic_policy') {
          const policy = getAttrValue(block.attributes, 'policy');

          if (typeof policy === 'object' && policy !== null) {
            const policyDoc = policy as Record<string, unknown>;
            const statements = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');

            if (Array.isArray(statements)) {
              for (const stmt of statements) {
                if (typeof stmt !== 'object' || stmt === null) continue;
                const statement = stmt as Record<string, unknown>;
                const principal = getAttrValue(statement, 'Principal') || getAttrValue(statement, 'principal');
                const effect = getAttrValue(statement, 'Effect') || getAttrValue(statement, 'effect');

                if ((effect === 'Allow' || effect === 'allow') && principal === '*') {
                  findings.push({
                    id: `${parsedFile.fileName}-${block.name}-sns-public-policy`,
                    ruleId: this.id,
                    title: this.title,
                    description: `SPAM RISK: SNS topic policy "${block.name}" allows Principal="*" - anyone can publish messages without authentication. Can be abused for message spam and AWS cost attacks.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_sns_topic_policy.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: 'Restrict Principal to specific service: "sns.amazonaws.com" or account: "arn:aws:iam::ACCOUNT-ID:root". Add Condition for additional security.',
                  });
                  break;
                }
              }
            }
          }
        }
      }
      return findings;
    },
  },
];
