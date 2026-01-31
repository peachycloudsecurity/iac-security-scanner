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

export const terraformAwsECRRules: Rule[] = [
  // ECR Image Scanning
  {
    id: 'TF_AWS_ECR_006',
    title: 'ECR repository image scanning enabled',
    description: 'NO VULNERABILITY SCANNING: ECR without scan_on_push means container images deployed with undetected CVEs. Critical vulnerabilities like Log4Shell, Heartbleed go unnoticed until exploited.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecr_repository') {
          const imageScanningConfig = getAttrValue(block.attributes, 'image_scanning_configuration');

          if (isFalseOrMissing(imageScanningConfig)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-ecr-no-scanning`,
              ruleId: this.id,
              title: this.title,
              description: `UNSCANNED IMAGES: ECR repository "${block.name}" has NO vulnerability scanning. Container images pushed without CVE detection. Deploying vulnerable base images, libraries with RCE exploits.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_ecr_repository.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add image_scanning_configuration { scan_on_push = true } to automatically scan all pushed images for CVEs. Review scan results before deployment.',
            });
          } else if (typeof imageScanningConfig === 'object' && imageScanningConfig !== null) {
            const scanOnPush = getAttrValue(imageScanningConfig as Record<string, unknown>, 'scan_on_push');
            if (scanOnPush === false) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-ecr-scanning-disabled`,
                ruleId: this.id,
                title: this.title,
                description: `SCANNING DISABLED: ECR repository "${block.name}" has image_scanning_configuration but scan_on_push = false. Vulnerability detection turned off.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_ecr_repository.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Set scan_on_push = true to enable automatic CVE scanning on every image push.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // ECR Repository Encryption
  {
    id: 'TF_AWS_ECR_007',
    title: 'ECR repository encryption with KMS',
    description: 'UNENCRYPTED IMAGES: ECR without KMS encryption stores container images with AWS-managed keys. Cannot control key rotation, audit key usage, or revoke access in security incidents.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecr_repository') {
          const encryptionConfig = getAttrValue(block.attributes, 'encryption_configuration');

          if (isFalseOrMissing(encryptionConfig)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-ecr-no-kms`,
              ruleId: this.id,
              title: this.title,
              description: `AWS-MANAGED KEYS: ECR repository "${block.name}" uses default AWS-managed encryption. Cannot audit who accessed images, rotate keys on-demand, or enforce key policies.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_ecr_repository.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add encryption_configuration { encryption_type = "KMS"; kms_key = aws_kms_key.ecr.arn } for customer-managed encryption with full audit trail.',
            });
          } else if (typeof encryptionConfig === 'object' && encryptionConfig !== null) {
            const config = Array.isArray(encryptionConfig) ? encryptionConfig[0] : encryptionConfig;
            if (typeof config === 'object' && config !== null) {
              const encryptionType = getAttrValue(config as Record<string, unknown>, 'encryption_type');
              if (encryptionType === 'AES256') {
                findings.push({
                  id: `${parsedFile.fileName}-${block.name}-ecr-aes256`,
                  ruleId: this.id,
                  title: this.title,
                  description: `DEFAULT ENCRYPTION: ECR repository "${block.name}" uses encryption_type = "AES256" (AWS-managed). Consider KMS for audit logging and key policy controls.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `aws_ecr_repository.${block.name}`,
                  lineNumber: block.startLine,
                  remediation: 'Upgrade to encryption_type = "KMS" with kms_key for CloudTrail audit logs of all image access.',
                });
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // ECR Repository Policy Public Access
  {
    id: 'TF_AWS_ECR_008',
    title: 'ECR repository policy restricts public access',
    description: 'PUBLIC CONTAINER REPO: ECR policy with Principal="*" allows anyone to pull/push images. Attackers can steal proprietary code, inject malicious images, or exfiltrate data.',
    severity: 'CRITICAL',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecr_repository_policy') {
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
                    id: `${parsedFile.fileName}-${block.name}-ecr-public-policy`,
                    ruleId: this.id,
                    title: this.title,
                    description: `REPOSITORY EXPOSED: ECR policy "${block.name}" allows Principal="*" - ANYONE can pull container images without authentication. Application source code, secrets in images fully public.`,
                    severity: 'CRITICAL',
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_ecr_repository_policy.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: 'IMMEDIATE ACTION: Change Principal from "*" to specific account ARN: "arn:aws:iam::ACCOUNT-ID:root" or restrict to specific IAM roles/users.',
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

  // ECR Image Tag Immutability
  {
    id: 'TF_AWS_ECR_009',
    title: 'ECR repository image tag immutability enabled',
    description: 'MUTABLE TAGS: Without tag immutability, attackers can overwrite "latest" or "v1.0" tags with malicious images. Supply chain attack - deployments pull trojaned containers.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecr_repository') {
          const imageTagMutability = getAttrValue(block.attributes, 'image_tag_mutability');

          if (imageTagMutability === 'MUTABLE' || isFalseOrMissing(imageTagMutability)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-ecr-mutable-tags`,
              ruleId: this.id,
              title: this.title,
              description: `TAG OVERWRITE RISK: ECR repository "${block.name}" allows image_tag_mutability = "MUTABLE". Compromised CI/CD can replace production:latest with backdoored image. Silent supply chain attack.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_ecr_repository.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set image_tag_mutability = "IMMUTABLE" to prevent tag overwrites. Use unique tags like git SHA: myapp:a1b2c3d instead of myapp:latest.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ECR Lifecycle Policy
  {
    id: 'TF_AWS_ECR_010',
    title: 'ECR repository has lifecycle policy',
    description: 'UNMANAGED IMAGES: ECR without lifecycle policy accumulates old vulnerable images forever. Storage costs increase, old CVE-ridden images remain pullable.',
    severity: 'LOW',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      const repositoriesWithLifecycle = new Set<string>();

      // First pass: collect repos with lifecycle policies
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecr_lifecycle_policy') {
          const repository = getAttrValue(block.attributes, 'repository');
          if (repository) {
            repositoriesWithLifecycle.add(String(repository));
          }
        }
      }

      // Second pass: check repos without lifecycle
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecr_repository') {
          const repoRef = `aws_ecr_repository.${block.name}`;
          if (!repositoriesWithLifecycle.has(repoRef) && !repositoriesWithLifecycle.has(block.name)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-ecr-no-lifecycle`,
              ruleId: this.id,
              title: this.title,
              description: `NO CLEANUP: ECR repository "${block.name}" missing lifecycle policy. Old images with known CVEs never deleted. Storage costs grow indefinitely.`,
              severity: 'LOW',
              fileName: parsedFile.fileName,
              resourcePath: `aws_ecr_repository.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Create aws_ecr_lifecycle_policy to auto-delete old images: Keep last 10 tagged images, delete untagged after 7 days.',
            });
          }
        }
      }
      return findings;
    },
  },
];
