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

// Helper to get attribute value (handles arrays and direct values)
function getAttrValue(attrs: Record<string, unknown>, key: string): unknown {
  const value = attrs[key];
  if (Array.isArray(value) && value.length > 0) {
    return value[0];
  }
  return value;
}

// Helper to check if value is false or missing
function isFalseOrMissing(value: unknown): boolean {
  return value === false || value === undefined || value === null;
}

// Helper to check if encryption is enabled
function isEncryptionEnabled(attrs: Record<string, unknown>, encryptionKey: string): boolean {
  const encryption = getAttrValue(attrs, encryptionKey);
  if (typeof encryption === 'boolean') return encryption;
  if (typeof encryption === 'object' && encryption !== null) {
    // Check for server_side_encryption_configuration or similar nested structures
    return true; // Assume enabled if structure exists
  }
  return false;
}

// Helper to check security group ingress for specific port
function checkSecurityGroupIngress(
  block: TerraformBlock,
  parsedFile: ParsedFile,
  ruleId: string,
  title: string,
  port: number,
  severity: 'HIGH' | 'MEDIUM' | 'LOW'
): Finding[] {
  const findings: Finding[] = [];
  const ingress = getAttrValue(block.attributes, 'ingress');
  const type = getAttrValue(block.attributes, 'type');
  
  const checkPort = (fromPort: unknown, toPort: unknown, cidrBlocks: unknown): boolean => {
    const from = typeof fromPort === 'number' ? fromPort : 0;
    const to = typeof toPort === 'number' ? toPort : 0;
    const portInRange = (from <= port && port <= to) || (from === 0 && to === 65535);
    
    if (portInRange && Array.isArray(cidrBlocks) && cidrBlocks.includes('0.0.0.0/0')) {
      return true;
    }
    return false;
  };
  
  if (block.resourceType === 'aws_security_group_rule' || block.resourceType === 'aws_vpc_security_group_ingress_rule') {
    if (type === 'ingress' || type === undefined) {
      const fromPort = getAttrValue(block.attributes, 'from_port');
      const toPort = getAttrValue(block.attributes, 'to_port');
      const cidrBlocks = getAttrValue(block.attributes, 'cidr_blocks') || getAttrValue(block.attributes, 'cidr_ipv4');
      
      if (checkPort(fromPort, toPort, cidrBlocks)) {
        findings.push({
          id: `${parsedFile.fileName}-${block.name}-port${port}-open`,
          ruleId,
          title,
          description: `Security group rule "${block.name}" allows unrestricted access to port ${port} from the internet.`,
          severity,
          fileName: parsedFile.fileName,
          resourcePath: `${block.resourceType}.${block.name}`,
          lineNumber: block.startLine,
          remediation: 'Restrict cidr_blocks to specific IP addresses or remove the rule.',
        });
      }
    }
  } else {
    // Handle ingress as nested block(s) - can be object or array of objects
    const ingressRules: unknown[] = [];
    if (Array.isArray(ingress)) {
      ingressRules.push(...ingress);
    } else if (ingress && typeof ingress === 'object') {
      ingressRules.push(ingress);
    }
    
    for (const rule of ingressRules) {
      if (typeof rule === 'object' && rule !== null) {
        const ruleObj = rule as Record<string, unknown>;
        const fromPort = ruleObj.from_port;
        const toPort = ruleObj.to_port;
        const cidrBlocks = ruleObj.cidr_blocks || ruleObj.cidr_ipv4;
        
        if (checkPort(fromPort, toPort, cidrBlocks)) {
          findings.push({
            id: `${parsedFile.fileName}-${block.name}-port${port}-open`,
            ruleId,
            title,
            description: `Security group "${block.name}" allows unrestricted access to port ${port} from the internet.`,
            severity,
            fileName: parsedFile.fileName,
            resourcePath: `aws_security_group.${block.name}`,
            lineNumber: block.startLine,
            remediation: 'Restrict cidr_blocks to specific IP addresses or remove the ingress rule.',
          });
          break;
        }
      }
    }
  }
  
  return findings;
}

export const terraformAwsSecurityRules: Rule[] = [
  // S3 Encryption
  {
    id: 'TF_AWS_S3_001',
    title: 'S3 bucket encryption enabled',
    description: 'S3 buckets should have server-side encryption enabled to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket') {
          const serverSideEncryptionConfig = getAttrValue(block.attributes, 'server_side_encryption_configuration');
          if (!serverSideEncryptionConfig) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket "${block.name}" does not have server-side encryption enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_s3_bucket.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add server_side_encryption_configuration block with SSEAlgorithm set to AES256 or aws:kms.',
            });
          }
        }
      }
      return findings;
    },
  },

  // RDS Encryption
  {
    id: 'TF_AWS_RDS_001',
    title: 'RDS encryption at rest enabled',
    description: 'RDS instances should have encryption enabled to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_db_instance') {
          const storageEncrypted = getAttrValue(block.attributes, 'storage_encrypted');
          if (isFalseOrMissing(storageEncrypted)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `RDS instance "${block.name}" does not have storage encryption enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_db_instance.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set storage_encrypted to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // RDS Publicly Accessible
  {
    id: 'TF_AWS_RDS_002',
    title: 'RDS instance not publicly accessible',
    description: 'RDS instances should not be publicly accessible to prevent unauthorized access.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_db_instance') {
          const publiclyAccessible = getAttrValue(block.attributes, 'publicly_accessible');
          if (publiclyAccessible === true) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-publicly-accessible`,
              ruleId: this.id,
              title: this.title,
              description: `RDS instance "${block.name}" is publicly accessible.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_db_instance.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set publicly_accessible to false.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Security Group Unrestricted Ingress Port 22
  {
    id: 'TF_AWS_SG_001',
    title: 'Security group blocks SSH from internet',
    description: 'Security groups should not allow unrestricted SSH access from the internet.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_security_group' || 
             block.resourceType === 'aws_security_group_rule' ||
             block.resourceType === 'aws_vpc_security_group_ingress_rule')) {
          findings.push(...checkSecurityGroupIngress(block, parsedFile, this.id, this.title, 22, 'HIGH'));
        }
      }
      return findings;
    },
  },

  // Security Group Unrestricted Ingress Port 80
  {
    id: 'TF_AWS_SG_002',
    title: 'Security group blocks HTTP from internet',
    description: 'Security groups should not allow unrestricted HTTP access from the internet.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_security_group' || 
             block.resourceType === 'aws_security_group_rule' ||
             block.resourceType === 'aws_vpc_security_group_ingress_rule')) {
          findings.push(...checkSecurityGroupIngress(block, parsedFile, this.id, this.title, 80, 'MEDIUM'));
        }
      }
      return findings;
    },
  },

  // Security Group Unrestricted Ingress Port 3389
  {
    id: 'TF_AWS_SG_003',
    title: 'Security group blocks RDP from internet',
    description: 'Security groups should not allow unrestricted RDP access from the internet.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_security_group' || 
             block.resourceType === 'aws_security_group_rule' ||
             block.resourceType === 'aws_vpc_security_group_ingress_rule')) {
          findings.push(...checkSecurityGroupIngress(block, parsedFile, this.id, this.title, 3389, 'HIGH'));
        }
      }
      return findings;
    },
  },

  // DynamoDB Encryption
  {
    id: 'TF_AWS_DDB_001',
    title: 'DynamoDB table encryption enabled',
    description: 'DynamoDB tables should have encryption enabled to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_dynamodb_table') {
          const serverSideEncryption = getAttrValue(block.attributes, 'server_side_encryption');
          if (!serverSideEncryption || (typeof serverSideEncryption === 'object' && 
              getAttrValue(serverSideEncryption as Record<string, unknown>, 'enabled') !== true)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `DynamoDB table "${block.name}" does not have encryption enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_dynamodb_table.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add server_side_encryption block with enabled set to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // EBS Encryption
  {
    id: 'TF_AWS_EBS_001',
    title: 'EBS volume encryption enabled',
    description: 'EBS volumes should be encrypted to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ebs_volume') {
          const encrypted = getAttrValue(block.attributes, 'encrypted');
          if (isFalseOrMissing(encrypted)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `EBS volume "${block.name}" is not encrypted.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_ebs_volume.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set encrypted to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // S3 Block Public ACLs
  {
    id: 'TF_AWS_S3_002',
    title: 'S3 bucket blocks public ACLs',
    description: 'S3 buckets should block public ACLs to prevent unauthorized public access.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket_public_access_block') {
          const blockPublicAcls = getAttrValue(block.attributes, 'block_public_acls');
          if (isFalseOrMissing(blockPublicAcls)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-public-acls`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket public access block "${block.name}" does not have block_public_acls enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_s3_bucket_public_access_block.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set block_public_acls to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // S3 Block Public Policy
  {
    id: 'TF_AWS_S3_003',
    title: 'S3 bucket blocks public policies',
    description: 'S3 buckets should block public policies to prevent unauthorized public access.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket_public_access_block') {
          const blockPublicPolicy = getAttrValue(block.attributes, 'block_public_policy');
          if (isFalseOrMissing(blockPublicPolicy)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-public-policy`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket public access block "${block.name}" does not have block_public_policy enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_s3_bucket_public_access_block.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set block_public_policy to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // S3 Ignore Public ACLs
  {
    id: 'TF_AWS_S3_004',
    title: 'S3 bucket ignores public ACLs',
    description: 'S3 buckets should ignore public ACLs to prevent unauthorized public access.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket_public_access_block') {
          const ignorePublicAcls = getAttrValue(block.attributes, 'ignore_public_acls');
          if (isFalseOrMissing(ignorePublicAcls)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-ignore-acls`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket public access block "${block.name}" does not have ignore_public_acls enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_s3_bucket_public_access_block.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set ignore_public_acls to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // S3 Restrict Public Buckets
  {
    id: 'TF_AWS_S3_005',
    title: 'S3 bucket restricts public access',
    description: 'S3 buckets should restrict public buckets to prevent unauthorized public access.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket_public_access_block') {
          const restrictPublicBuckets = getAttrValue(block.attributes, 'restrict_public_buckets');
          if (isFalseOrMissing(restrictPublicBuckets)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-restrict-buckets`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket public access block "${block.name}" does not have restrict_public_buckets enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_s3_bucket_public_access_block.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set restrict_public_buckets to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // EC2 Public IP
  {
    id: 'TF_AWS_EC2_001',
    title: 'EC2 instance without public IP',
    description: 'EC2 instances should not have public IP addresses to reduce attack surface.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_instance' || block.resourceType === 'aws_launch_template')) {
          if (block.resourceType === 'aws_instance') {
            const associatePublicIpAddress = getAttrValue(block.attributes, 'associate_public_ip_address');
            if (associatePublicIpAddress === true) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-public-ip`,
                ruleId: this.id,
                title: this.title,
                description: `EC2 instance "${block.name}" has public IP address enabled.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_instance.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Set associate_public_ip_address to false.',
              });
            }
          } else if (block.resourceType === 'aws_launch_template') {
            const networkInterfaces = getAttrValue(block.attributes, 'network_interfaces');
            if (Array.isArray(networkInterfaces) && networkInterfaces.length > 0) {
              const firstNI = networkInterfaces[0];
              if (typeof firstNI === 'object' && firstNI !== null) {
                const ni = firstNI as Record<string, unknown>;
                if (ni.associate_public_ip_address === true) {
                  findings.push({
                    id: `${parsedFile.fileName}-${block.name}-public-ip`,
                    ruleId: this.id,
                    title: this.title,
                    description: `Launch template "${block.name}" has public IP address enabled.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_launch_template.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: 'Set associate_public_ip_address to false in network_interfaces.',
                  });
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
