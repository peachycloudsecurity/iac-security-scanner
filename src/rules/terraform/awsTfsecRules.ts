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

export const terraformTfsecRules: Rule[] = [
  // S3 Versioning (aws-s3-enable-versioning)
  {
    id: 'TF_AWS_S3_007',
    title: 'S3 bucket versioning enabled',
    description: 'NO VERSION CONTROL: S3 bucket without versioning loses deleted/modified files permanently. Ransomware can destroy all data without recovery option.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      const bucketsWithVersioning = new Set<string>();
      const allBuckets = new Set<string>();

      // First pass: collect all buckets and those with versioning
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket') {
          allBuckets.add(block.name);
        }
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket_versioning') {
          const bucket = getAttrValue(block.attributes, 'bucket');
          const status = getAttrValue(block.attributes, 'versioning_configuration');
          if (typeof status === 'object' && status !== null) {
            const statusObj = status as Record<string, unknown>;
            if (getAttrValue(statusObj, 'status') === 'Enabled') {
              if (typeof bucket === 'string') {
                const bucketName = bucket.includes('.') ? bucket.split('.')[1] : bucket;
                bucketsWithVersioning.add(bucketName);
              }
            }
          }
        }
      }

      // Check for buckets without versioning
      for (const bucketName of allBuckets) {
        if (!bucketsWithVersioning.has(bucketName)) {
          findings.push({
            id: `${parsedFile.fileName}-${bucketName}-no-versioning`,
            ruleId: this.id,
            title: this.title,
            description: `DATA LOSS RISK: Bucket "${bucketName}" has no versioning. Ransomware, accidental deletion, or malicious modification permanently destroys data with no recovery.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `aws_s3_bucket.${bucketName}`,
            lineNumber: 1,
            remediation: 'Add: aws_s3_bucket_versioning resource with versioning_configuration { status = "Enabled" } for data protection and ransomware recovery.',
          });
        }
      }
      return findings;
    },
  },

  // CloudFront HTTPS Enforcement (aws-cloudfront-enforce-https)
  {
    id: 'TF_AWS_CF_001',
    title: 'CloudFront distribution enforces HTTPS',
    description: 'UNENCRYPTED TRAFFIC: CloudFront allows HTTP traffic. User credentials, session tokens, and sensitive data transmitted in plaintext.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_cloudfront_distribution') {
          const defaultCacheBehavior = getAttrValue(block.attributes, 'default_cache_behavior');
          
          if (typeof defaultCacheBehavior === 'object' && defaultCacheBehavior !== null) {
            const behaviorObj = defaultCacheBehavior as Record<string, unknown>;
            const viewerProtocolPolicy = getAttrValue(behaviorObj, 'viewer_protocol_policy');
            
            if (viewerProtocolPolicy !== 'redirect-to-https' && viewerProtocolPolicy !== 'https-only') {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-http-allowed`,
                ruleId: this.id,
                title: this.title,
                description: `PLAINTEXT TRANSMISSION: Distribution "${block.name}" allows HTTP traffic. Credentials, authentication tokens, and user data transmitted without encryption.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_cloudfront_distribution.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Set default_cache_behavior: viewer_protocol_policy = "redirect-to-https" or "https-only" to force encrypted connections.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // EKS Secrets Encryption (aws-eks-encrypt-secrets)
  {
    id: 'TF_AWS_EKS_002',
    title: 'EKS cluster encrypts secrets at rest',
    description: 'UNENCRYPTED SECRETS: Kubernetes secrets stored in plaintext on etcd. Contains service account tokens, database passwords, API keys.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_eks_cluster') {
          const encryptionConfig = getAttrValue(block.attributes, 'encryption_config');
          
          let hasSecretsEncryption = false;
          if (Array.isArray(encryptionConfig)) {
            for (const config of encryptionConfig) {
              if (typeof config === 'object' && config !== null) {
                const configObj = config as Record<string, unknown>;
                const resources = getAttrValue(configObj, 'resources');
                if (Array.isArray(resources) && resources.includes('secrets')) {
                  hasSecretsEncryption = true;
                  break;
                }
              }
            }
          }
          
          if (!hasSecretsEncryption) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-secrets-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT SECRETS: EKS cluster "${block.name}" stores Kubernetes secrets unencrypted. Service tokens, database credentials, API keys readable from etcd backups.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_eks_cluster.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add encryption_config: { resources = ["secrets"], provider { key_arn = aws_kms_key.eks.arn } } to encrypt secrets at rest.',
            });
          }
        }
      }
      return findings;
    },
  },

  // EFS Encryption (aws-efs-enable-at-rest-encryption)
  {
    id: 'TF_AWS_EFS_001',
    title: 'EFS filesystem encryption at rest enabled',
    description: 'UNENCRYPTED FILE SYSTEM: EFS data stored in plaintext. Application files, user data, and shared storage readable from AWS infrastructure.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_efs_file_system') {
          const encrypted = getAttrValue(block.attributes, 'encrypted');
          
          if (isFalseOrMissing(encrypted)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT FILES: EFS filesystem "${block.name}" stores data unencrypted. Application files, user uploads, and shared data readable from AWS storage systems.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_efs_file_system.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add encrypted = true to enable at-rest encryption. Use kms_key_id = aws_kms_key.efs.arn for customer managed key control.',
            });
          }
        }
      }
      return findings;
    },
  },

  // SQS Queue Encryption (aws-sqs-enable-queue-encryption)
  {
    id: 'TF_AWS_SQS_002',
    title: 'SQS queue encryption enabled',
    description: 'UNENCRYPTED MESSAGES: SQS queue messages stored in plaintext. Application messages, job data, and sensitive payloads readable by AWS.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sqs_queue') {
          const kmsKeyId = getAttrValue(block.attributes, 'kms_master_key_id');
          
          if (!kmsKeyId) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT MESSAGES: Queue "${block.name}" stores messages unencrypted. Application data, job payloads, and sensitive information readable by AWS services.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_sqs_queue.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add kms_master_key_id = aws_kms_key.sqs.arn or kms_master_key_id = "alias/aws/sqs" for AWS managed key.',
            });
          }
        }
      }
      return findings;
    },
  },

  // SNS Topic Encryption (aws-sns-enable-topic-encryption)
  {
    id: 'TF_AWS_SNS_002',
    title: 'SNS topic encryption enabled',
    description: 'UNENCRYPTED NOTIFICATIONS: SNS messages stored in plaintext. Notification content, user data, and application events readable by AWS.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sns_topic') {
          const kmsKeyId = getAttrValue(block.attributes, 'kms_master_key_id');
          
          if (!kmsKeyId) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT NOTIFICATIONS: Topic "${block.name}" stores messages unencrypted. Notification content, user data, and webhook payloads readable by AWS.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_sns_topic.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add kms_master_key_id = aws_kms_key.sns.arn for customer managed key encryption of messages.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ECR Image Scanning (aws-ecr-enable-image-scans)
  {
    id: 'TF_AWS_ECR_002',
    title: 'ECR repository enables image scanning',
    description: 'NO VULNERABILITY SCANNING: ECR images not scanned for CVEs. Containers may contain known exploitable vulnerabilities.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecr_repository') {
          const imageScanningConfig = getAttrValue(block.attributes, 'image_scanning_configuration');
          
          let scanOnPush = false;
          if (typeof imageScanningConfig === 'object' && imageScanningConfig !== null) {
            const scanObj = imageScanningConfig as Record<string, unknown>;
            scanOnPush = getAttrValue(scanObj, 'scan_on_push') === true;
          }
          
          if (!scanOnPush) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-image-scanning`,
              ruleId: this.id,
              title: this.title,
              description: `VULNERABLE IMAGES: Repository "${block.name}" doesn't scan for CVEs. Containers may contain known exploitable vulnerabilities like RCE, privilege escalation.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_ecr_repository.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add image_scanning_configuration { scan_on_push = true } to automatically scan images for vulnerabilities on push.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ECR Immutable Tags (aws-ecr-enforce-immutable-repository)
  {
    id: 'TF_AWS_ECR_003',
    title: 'ECR repository uses immutable tags',
    description: 'MUTABLE TAGS: ECR tags can be overwritten. Attacker can push malicious image with same tag, affecting all deployments using that tag.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecr_repository') {
          const imageTagMutability = getAttrValue(block.attributes, 'image_tag_mutability');
          
          if (imageTagMutability !== 'IMMUTABLE') {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-mutable-tags`,
              ruleId: this.id,
              title: this.title,
              description: `TAG HIJACKING: Repository "${block.name}" allows tag overwriting. Attacker can push malicious image with existing tag, affecting all services using that image version.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_ecr_repository.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set image_tag_mutability = "IMMUTABLE" to prevent tag overwriting. Use semantic versioning with unique tags for each build.',
            });
          }
        }
      }
      return findings;
    },
  },

  // EKS Control Plane Logging (aws-eks-enable-control-plane-logging)
  {
    id: 'TF_AWS_EKS_003',
    title: 'EKS cluster enables control plane logging',
    description: 'NO AUDIT TRAIL: EKS control plane actions not logged. Cannot detect unauthorized kubectl access, privilege escalation, or API abuse.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_eks_cluster') {
          const enabledClusterLogTypes = getAttrValue(block.attributes, 'enabled_cluster_log_types');
          
          const requiredLogTypes = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'];
          let hasAllLogs = false;
          
          if (Array.isArray(enabledClusterLogTypes)) {
            hasAllLogs = requiredLogTypes.every(logType => enabledClusterLogTypes.includes(logType));
          }
          
          if (!hasAllLogs) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-incomplete-logging`,
              ruleId: this.id,
              title: this.title,
              description: `NO SECURITY AUDIT: Cluster "${block.name}" missing control plane logs. Cannot detect unauthorized access, privilege escalation, or malicious kubectl commands.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_eks_cluster.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"] for complete audit trail.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Default VPC Usage (aws-vpc-no-default-vpc)
  {
    id: 'TF_AWS_VPC_001',
    title: 'Resources avoid default VPC usage',
    description: 'DEFAULT VPC RISK: Default VPC has permissive settings, public subnets, and internet gateway. All regions accessible, poor network isolation.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      // Check for resources that might use default VPC
      const riskyResources = [
        'aws_instance',
        'aws_rds_instance', 
        'aws_elasticache_cluster',
        'aws_elasticsearch_domain'
      ];

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && riskyResources.includes(block.resourceType || '')) {
          const vpcSecurityGroupIds = getAttrValue(block.attributes, 'vpc_security_group_ids');
          const subnetId = getAttrValue(block.attributes, 'subnet_id');
          const subnetIds = getAttrValue(block.attributes, 'subnet_ids');
          const vpcId = getAttrValue(block.attributes, 'vpc_id');
          
          // If no explicit VPC configuration, likely using default VPC
          if (!vpcSecurityGroupIds && !subnetId && !subnetIds && !vpcId) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-default-vpc`,
              ruleId: this.id,
              title: this.title,
              description: `DEFAULT VPC: Resource "${block.name}" likely uses default VPC with permissive network settings, public subnets, and internet gateway access.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${block.resourceType}.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Create custom VPC: aws_vpc, aws_subnet (private), aws_security_group with least-privilege rules. Specify vpc_security_group_ids and subnet_id.',
            });
          }
        }
      }
      return findings;
    },
  },

  // CloudTrail Multi-Region (aws-cloudtrail-enable-all-regions)
  {
    id: 'TF_AWS_CT_001',
    title: 'CloudTrail enables multi-region logging',
    description: 'REGIONAL BLIND SPOTS: Single-region CloudTrail misses activity in other regions. Attackers can operate in unmonitored regions.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_cloudtrail') {
          const includeGlobalServiceEvents = getAttrValue(block.attributes, 'include_global_service_events');
          const isMultiRegionTrail = getAttrValue(block.attributes, 'is_multi_region_trail');
          
          if (isFalseOrMissing(includeGlobalServiceEvents) || isFalseOrMissing(isMultiRegionTrail)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-single-region`,
              ruleId: this.id,
              title: this.title,
              description: `MONITORING GAPS: CloudTrail "${block.name}" doesn't monitor all regions. Attackers can operate in unmonitored regions without detection.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_cloudtrail.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set is_multi_region_trail = true and include_global_service_events = true to monitor all regions and global services (IAM, STS, CloudFront).',
            });
          }
        }
      }
      return findings;
    },
  },

  // KMS Auto Rotation (aws-kms-auto-rotate-keys)
  {
    id: 'TF_AWS_KMS_002',
    title: 'KMS key enables automatic rotation',
    description: 'NO KEY ROTATION: KMS key never rotates. Long-lived keys increase risk if compromised. Old encrypted data remains vulnerable.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_kms_key') {
          const enableKeyRotation = getAttrValue(block.attributes, 'enable_key_rotation');
          
          if (isFalseOrMissing(enableKeyRotation)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-rotation`,
              ruleId: this.id,
              title: this.title,
              description: `STATIC ENCRYPTION KEY: Key "${block.name}" has no automatic rotation. If key compromised, all historical encrypted data remains vulnerable.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_kms_key.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add enable_key_rotation = true to rotate key material annually. Update applications to handle key rotation gracefully.',
            });
          }
        }
      }
      return findings;
    },
  },

  // EC2 Root Block Device Encryption (aws-ec2-enable-at-rest-encryption)
  {
    id: 'TF_AWS_EC2_005',
    title: 'EC2 root block device encryption enabled',
    description: 'UNENCRYPTED ROOT DISK: EC2 root volume stores OS, application data, logs, and temporary files in plaintext. Data readable from EBS snapshots.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_instance') {
          const rootBlockDevice = getAttrValue(block.attributes, 'root_block_device');
          
          let isRootEncrypted = false;
          if (typeof rootBlockDevice === 'object' && rootBlockDevice !== null) {
            const rootObj = rootBlockDevice as Record<string, unknown>;
            isRootEncrypted = getAttrValue(rootObj, 'encrypted') === true;
          }
          
          // If no root_block_device specified, defaults to unencrypted
          if (!isRootEncrypted) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-unencrypted-root-device`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT ROOT VOLUME: Instance "${block.name}" root block device not encrypted. OS files, application data, logs, and swap files readable from EBS snapshots and underlying storage.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_instance.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add root_block_device { encrypted = true } to encrypt root volume. Use kms_key_id = aws_kms_key.ebs.arn for customer managed key.',
            });
          }
          
          // Also check ebs_block_device for additional volumes
          const ebsBlockDevice = getAttrValue(block.attributes, 'ebs_block_device');
          if (Array.isArray(ebsBlockDevice)) {
            for (const device of ebsBlockDevice) {
              if (typeof device === 'object' && device !== null) {
                const deviceObj = device as Record<string, unknown>;
                const deviceEncrypted = getAttrValue(deviceObj, 'encrypted');
                if (deviceEncrypted !== true) {
                  findings.push({
                    id: `${parsedFile.fileName}-${block.name}-unencrypted-additional-ebs`,
                    ruleId: this.id,
                    title: this.title,
                    description: `PLAINTEXT EBS VOLUME: Instance "${block.name}" has unencrypted additional EBS volume. Application data stored in plaintext, readable from snapshots.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_instance.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: 'Set encrypted = true in all ebs_block_device configurations.',
                  });
                  break; // Only report once per instance
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