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

function isFalseOrMissing(value: unknown): boolean {
  return value === false || value === undefined || value === null;
}

// Helper to check S3 PublicAccessBlockConfiguration
function checkS3PublicAccessBlock(
  resource: CloudFormationResource,
  resourceName: string,
  parsedFile: ParsedFile,
  ruleId: string,
  title: string,
  property: string,
  severity: 'HIGH' | 'MEDIUM' | 'LOW'
): Finding[] {
  const findings: Finding[] = [];
  const value = getProperty(resource, `PublicAccessBlockConfiguration/${property}`);
  
  if (isFalseOrMissing(value)) {
    findings.push({
      id: `${parsedFile.fileName}-${resourceName}-${property.toLowerCase()}`,
      ruleId,
      title,
      description: `S3 bucket "${resourceName}" does not have ${property} enabled.`,
      severity,
      fileName: parsedFile.fileName,
      resourcePath: `Resources/${resourceName}`,
      remediation: `Add PublicAccessBlockConfiguration with ${property} set to true.`,
    });
  }
  
  return findings;
}

export const cloudformationAwsSecurityRules: Rule[] = [
  // S3 Block Public ACLs
  {
    id: 'CFN_AWS_S3_001',
    title: 'S3 bucket blocks public ACLs',
    description: 'S3 buckets should block public ACLs to prevent unauthorized public access.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::S3::Bucket') {
          findings.push(...checkS3PublicAccessBlock(resource, resourceName, parsedFile, this.id, this.title, 'BlockPublicAcls', 'HIGH'));
        }
      }
      return findings;
    },
  },

  // S3 Block Public Policy
  {
    id: 'CFN_AWS_S3_002',
    title: 'S3 bucket blocks public policies',
    description: 'S3 buckets should block public policies to prevent unauthorized public access.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::S3::Bucket') {
          findings.push(...checkS3PublicAccessBlock(resource, resourceName, parsedFile, this.id, this.title, 'BlockPublicPolicy', 'HIGH'));
        }
      }
      return findings;
    },
  },

  // S3 Ignore Public ACLs
  {
    id: 'CFN_AWS_S3_003',
    title: 'S3 bucket ignores public ACLs',
    description: 'S3 buckets should ignore public ACLs to prevent unauthorized public access.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::S3::Bucket') {
          findings.push(...checkS3PublicAccessBlock(resource, resourceName, parsedFile, this.id, this.title, 'IgnorePublicAcls', 'HIGH'));
        }
      }
      return findings;
    },
  },

  // S3 Restrict Public Buckets
  {
    id: 'CFN_AWS_S3_004',
    title: 'S3 bucket restricts public access',
    description: 'S3 buckets should restrict public buckets to prevent unauthorized public access.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::S3::Bucket') {
          findings.push(...checkS3PublicAccessBlock(resource, resourceName, parsedFile, this.id, this.title, 'RestrictPublicBuckets', 'HIGH'));
        }
      }
      return findings;
    },
  },

  // S3 Versioning
  {
    id: 'CFN_AWS_S3_005',
    title: 'S3 bucket versioning enabled',
    description: 'S3 buckets should have versioning enabled for data protection and recovery.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::S3::Bucket') {
          const versioningStatus = getProperty(resource, 'VersioningConfiguration/Status');
          
          if (versioningStatus !== 'Enabled') {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-versioning`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket "${resourceName}" does not have versioning enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Add VersioningConfiguration with Status set to Enabled.',
            });
          }
        }
      }
      return findings;
    },
  },

  // S3 Access Logs
  {
    id: 'CFN_AWS_S3_006',
    title: 'S3 bucket access logging enabled',
    description: 'S3 buckets should have access logging enabled for security auditing.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::S3::Bucket') {
          const loggingConfig = getProperty(resource, 'LoggingConfiguration');
          
          if (!loggingConfig) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-logging`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket "${resourceName}" does not have access logging enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Add LoggingConfiguration with DestinationBucketName and LogFilePrefix.',
            });
          }
        }
      }
      return findings;
    },
  },

  // S3 Encryption
  {
    id: 'CFN_AWS_S3_007',
    title: 'S3 bucket encryption enabled',
    description: 'S3 buckets should have server-side encryption enabled to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::S3::Bucket') {
          const encryption = getProperty(resource, 'BucketEncryption');
          
          if (!encryption) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `S3 bucket "${resourceName}" does not have server-side encryption enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Add BucketEncryption with ServerSideEncryptionConfiguration.',
            });
          }
        }
      }
      return findings;
    },
  },

  // RDS Encryption
  {
    id: 'CFN_AWS_RDS_001',
    title: 'RDS encryption at rest enabled',
    description: 'RDS instances should have encryption enabled to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::RDS::DBInstance') {
          const storageEncrypted = getProperty(resource, 'StorageEncrypted');
          
          if (isFalseOrMissing(storageEncrypted)) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `RDS instance "${resourceName}" does not have storage encryption enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Set StorageEncrypted to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // RDS Publicly Accessible
  {
    id: 'CFN_AWS_RDS_002',
    title: 'RDS instance not publicly accessible',
    description: 'RDS instances should not be publicly accessible to prevent unauthorized access.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::RDS::DBInstance') {
          const publiclyAccessible = getProperty(resource, 'PubliclyAccessible');
          
          if (publiclyAccessible === true) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-publicly-accessible`,
              ruleId: this.id,
              title: this.title,
              description: `RDS instance "${resourceName}" is publicly accessible.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Set PubliclyAccessible to false.',
            });
          }
        }
      }
      return findings;
    },
  },

  // DynamoDB Encryption
  {
    id: 'CFN_AWS_DDB_001',
    title: 'DynamoDB table encryption enabled',
    description: 'DynamoDB tables should have encryption enabled to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::DynamoDB::Table') {
          const sseSpecification = getProperty(resource, 'SSESpecification');
          const sseEnabled = getProperty(resource, 'SSESpecification/SSEEnabled');
          
          if (!sseSpecification || isFalseOrMissing(sseEnabled)) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `DynamoDB table "${resourceName}" does not have encryption enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Add SSESpecification with SSEEnabled set to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Lambda Function Not Public
  {
    id: 'CFN_AWS_LAMBDA_001',
    title: 'Lambda function not publicly accessible',
    description: 'Lambda functions should not be publicly accessible to prevent unauthorized invocations.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::Lambda::Permission') {
          const principal = getProperty(resource, 'Principal');
          
          if (principal === '*' || principal === 'arn:aws:iam::*:*') {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-public-access`,
              ruleId: this.id,
              title: this.title,
              description: `Lambda permission "${resourceName}" allows public access (Principal: *).`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Restrict Principal to specific AWS accounts or services.',
            });
          }
        }
      }
      return findings;
    },
  },

  // SQS Encryption
  {
    id: 'CFN_AWS_SQS_001',
    title: 'SQS queue encryption enabled',
    description: 'SQS queues should have encryption enabled to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::SQS::Queue') {
          const kmsKeyId = getProperty(resource, 'KmsMasterKeyId');
          
          if (!kmsKeyId) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `SQS queue "${resourceName}" does not have encryption enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Add KmsMasterKeyId to enable encryption.',
            });
          }
        }
      }
      return findings;
    },
  },

  // SNS Encryption
  {
    id: 'CFN_AWS_SNS_001',
    title: 'SNS topic encryption enabled',
    description: 'SNS topics should have encryption enabled to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::SNS::Topic') {
          const kmsKeyId = getProperty(resource, 'KmsMasterKeyId');
          
          if (!kmsKeyId) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `SNS topic "${resourceName}" does not have encryption enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Add KmsMasterKeyId to enable encryption.',
            });
          }
        }
      }
      return findings;
    },
  },

  // EBS Encryption
  {
    id: 'CFN_AWS_EBS_001',
    title: 'EBS volume encryption enabled',
    description: 'EBS volumes should be encrypted to protect data at rest.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::EC2::Volume') {
          const encrypted = getProperty(resource, 'Encrypted');
          
          if (isFalseOrMissing(encrypted)) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `EBS volume "${resourceName}" is not encrypted.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Set Encrypted to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // EC2 Public IP
  {
    id: 'CFN_AWS_EC2_001',
    title: 'EC2 instance without public IP',
    description: 'EC2 instances should not have public IP addresses to reduce attack surface.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::EC2::Instance' || resource.Type === 'AWS::EC2::LaunchTemplate') {
          const props = resource.Properties || {};
          
          // Check NetworkInterfaces for Instance
          if (resource.Type === 'AWS::EC2::Instance' && Array.isArray(props.NetworkInterfaces)) {
            for (const ni of props.NetworkInterfaces) {
              if (typeof ni === 'object' && ni !== null) {
                const niObj = ni as Record<string, unknown>;
                if (niObj.AssociatePublicIpAddress === true) {
                  findings.push({
                    id: `${parsedFile.fileName}-${resourceName}-public-ip`,
                    ruleId: this.id,
                    title: this.title,
                    description: `EC2 instance "${resourceName}" has public IP address enabled.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `Resources/${resourceName}`,
                    remediation: 'Set AssociatePublicIpAddress to false or remove it.',
                  });
                  break;
                }
              }
            }
          }
          
          // Check LaunchTemplateData for LaunchTemplate
          if (resource.Type === 'AWS::EC2::LaunchTemplate') {
            const launchData = props.LaunchTemplateData;
            if (typeof launchData === 'object' && launchData !== null) {
              const data = launchData as Record<string, unknown>;
              if (Array.isArray(data.NetworkInterfaces)) {
                for (const ni of data.NetworkInterfaces) {
                  if (typeof ni === 'object' && ni !== null) {
                    const niObj = ni as Record<string, unknown>;
                    if (niObj.AssociatePublicIpAddress === true) {
                      findings.push({
                        id: `${parsedFile.fileName}-${resourceName}-public-ip`,
                        ruleId: this.id,
                        title: this.title,
                        description: `Launch template "${resourceName}" has public IP address enabled.`,
                        severity: this.severity,
                        fileName: parsedFile.fileName,
                        resourcePath: `Resources/${resourceName}`,
                        remediation: 'Set AssociatePublicIpAddress to false in LaunchTemplateData.',
                      });
                      break;
                    }
                  }
                }
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // RDS Multi-AZ
  {
    id: 'CFN_AWS_RDS_003',
    title: 'RDS Multi-AZ enabled',
    description: 'RDS instances should have Multi-AZ enabled for high availability.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::RDS::DBInstance') {
          const props = resource.Properties || {};
          const engine = props.Engine;
          const multiAZ = getProperty(resource, 'MultiAZ');
          
          // Aurora doesn't require MultiAZ (it's replicated by default)
          if (typeof engine === 'string' && engine.toLowerCase().includes('aurora')) {
            continue;
          }
          
          if (isFalseOrMissing(multiAZ)) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-multiaz`,
              ruleId: this.id,
              title: this.title,
              description: `RDS instance "${resourceName}" does not have Multi-AZ enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Set MultiAZ to true for high availability.',
            });
          }
        }
      }
      return findings;
    },
  },
];

// Helper to check Security Group ingress for specific port
function checkSecurityGroupIngress(
  resource: CloudFormationResource,
  resourceName: string,
  parsedFile: ParsedFile,
  ruleId: string,
  title: string,
  port: number,
  severity: 'HIGH' | 'MEDIUM' | 'LOW'
): Finding[] {
  const findings: Finding[] = [];
  const props = resource.Properties || {};
  
  let rules: unknown[] = [];
  
  if (resource.Type === 'AWS::EC2::SecurityGroup') {
    const ingress = props.SecurityGroupIngress;
    if (Array.isArray(ingress)) {
      rules = ingress;
    }
  } else if (resource.Type === 'AWS::EC2::SecurityGroupIngress') {
    rules = [props];
  }
  
  for (const rule of rules) {
    if (typeof rule !== 'object' || rule === null) continue;
    const ruleObj = rule as Record<string, unknown>;
    
    const fromPort = typeof ruleObj.FromPort === 'number' ? ruleObj.FromPort : 
                     typeof ruleObj.FromPort === 'string' ? parseInt(ruleObj.FromPort, 10) : 0;
    const toPort = typeof ruleObj.ToPort === 'number' ? ruleObj.ToPort :
                   typeof ruleObj.ToPort === 'string' ? parseInt(ruleObj.ToPort, 10) : 0;
    
    if (fromPort <= port && port <= toPort) {
      const cidrIp = ruleObj.CidrIp;
      const cidrIpv6 = ruleObj.CidrIpv6;
      
      if (cidrIp === '0.0.0.0/0' || 
          cidrIpv6 === '::/0' || 
          cidrIpv6 === '0000:0000:0000:0000:0000:0000:0000:0000/0') {
        findings.push({
          id: `${parsedFile.fileName}-${resourceName}-port${port}-open`,
          ruleId,
          title,
          description: `Security group "${resourceName}" allows unrestricted access to port ${port} from the internet.`,
          severity,
          fileName: parsedFile.fileName,
          resourcePath: `Resources/${resourceName}`,
          remediation: 'Restrict CidrIp to specific IP addresses or remove the rule.',
        });
        break;
      }
    }
  }
  
  return findings;
}

export const cloudformationAwsNetworkRules: Rule[] = [
  // Security Group Unrestricted Ingress Port 22
  {
    id: 'CFN_AWS_SG_001',
    title: 'Security group blocks SSH from internet',
    description: 'Security groups should not allow unrestricted SSH access from the internet.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::EC2::SecurityGroup' || resource.Type === 'AWS::EC2::SecurityGroupIngress') {
          findings.push(...checkSecurityGroupIngress(resource, resourceName, parsedFile, this.id, this.title, 22, 'HIGH'));
        }
      }
      return findings;
    },
  },

  // Security Group Unrestricted Ingress Port 80
  {
    id: 'CFN_AWS_SG_002',
    title: 'Security group blocks HTTP from internet',
    description: 'Security groups should not allow unrestricted HTTP access from the internet.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::EC2::SecurityGroup' || resource.Type === 'AWS::EC2::SecurityGroupIngress') {
          findings.push(...checkSecurityGroupIngress(resource, resourceName, parsedFile, this.id, this.title, 80, 'MEDIUM'));
        }
      }
      return findings;
    },
  },

  // Security Group Unrestricted Ingress Port 3389
  {
    id: 'CFN_AWS_SG_003',
    title: 'Security group blocks RDP from internet',
    description: 'Security groups should not allow unrestricted RDP access from the internet.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::EC2::SecurityGroup' || resource.Type === 'AWS::EC2::SecurityGroupIngress') {
          findings.push(...checkSecurityGroupIngress(resource, resourceName, parsedFile, this.id, this.title, 3389, 'HIGH'));
        }
      }
      return findings;
    },
  },
];

// Helper to check IAM policy for wildcard actions
function checkIAMPolicyWildcard(policyDoc: unknown): boolean {
  if (typeof policyDoc !== 'object' || policyDoc === null) return false;
  
  const policy = policyDoc as Record<string, unknown>;
  const statements = policy.Statement;
  
  if (!Array.isArray(statements)) return false;
  
  for (const stmt of statements) {
    if (typeof stmt !== 'object' || stmt === null) continue;
    const statement = stmt as Record<string, unknown>;
    const effect = statement.Effect;
    const actions = statement.Action;
    
    if (effect === 'Allow') {
      if (Array.isArray(actions) && actions.includes('*')) {
        return true;
      } else if (typeof actions === 'string' && actions === '*') {
        return true;
      }
    }
  }
  
  return false;
}

export const cloudformationAwsIAMRules: Rule[] = [
  // IAM Star Action Policy
  {
    id: 'CFN_AWS_IAM_001',
    title: 'IAM policy blocks wildcard actions',
    description: 'IAM policies should not allow wildcard actions which grant full administrative privileges.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (['AWS::IAM::Policy', 'AWS::IAM::Group', 'AWS::IAM::Role', 'AWS::IAM::User'].includes(resource.Type)) {
          const props = resource.Properties || {};
          
          // Check PolicyDocument for Policy resources
          if (resource.Type === 'AWS::IAM::Policy' && props.PolicyDocument) {
            if (checkIAMPolicyWildcard(props.PolicyDocument)) {
              findings.push({
                id: `${parsedFile.fileName}-${resourceName}-wildcard-policy`,
                ruleId: this.id,
                title: this.title,
                description: `IAM policy "${resourceName}" allows wildcard actions.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `Resources/${resourceName}`,
                remediation: 'Replace wildcard actions with specific, least-privilege actions.',
              });
            }
          }
          
          // Check Policies array for Group, Role, User
          if (['AWS::IAM::Group', 'AWS::IAM::Role', 'AWS::IAM::User'].includes(resource.Type) && Array.isArray(props.Policies)) {
            for (const policy of props.Policies) {
              if (typeof policy === 'object' && policy !== null) {
                const policyObj = policy as Record<string, unknown>;
                if (policyObj.PolicyDocument && checkIAMPolicyWildcard(policyObj.PolicyDocument)) {
                  findings.push({
                    id: `${parsedFile.fileName}-${resourceName}-wildcard-policy`,
                    ruleId: this.id,
                    title: this.title,
                    description: `IAM ${resource.Type} "${resourceName}" has a policy with wildcard actions.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `Resources/${resourceName}`,
                    remediation: 'Replace wildcard actions with specific, least-privilege actions.',
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

  // IAM Role Allows Public Assume
  {
    id: 'CFN_AWS_IAM_002',
    title: 'IAM role restricts assume role principals',
    description: 'IAM roles should not allow public assume to prevent unauthorized access.',
    severity: 'HIGH',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::IAM::Role') {
          const props = resource.Properties || {};
          const assumeRolePolicy = props.AssumeRolePolicyDocument;
          
          if (typeof assumeRolePolicy === 'object' && assumeRolePolicy !== null) {
            const policy = assumeRolePolicy as Record<string, unknown>;
            const statements = policy.Statement;
            
            if (Array.isArray(statements)) {
              for (const stmt of statements) {
                if (typeof stmt !== 'object' || stmt === null) continue;
                const statement = stmt as Record<string, unknown>;
                const principal = statement.Principal;
                
                if (typeof principal === 'object' && principal !== null) {
                  const principalObj = principal as Record<string, unknown>;
                  const aws = principalObj.AWS;
                  
                  if (Array.isArray(aws) && aws.includes('*')) {
                    findings.push({
                      id: `${parsedFile.fileName}-${resourceName}-public-assume`,
                      ruleId: this.id,
                      title: this.title,
                      description: `IAM role "${resourceName}" allows any principal to assume it.`,
                      severity: this.severity,
                      fileName: parsedFile.fileName,
                      resourcePath: `Resources/${resourceName}`,
                      remediation: 'Restrict the Principal to specific AWS accounts or services.',
                    });
                    break;
                  }
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

// CloudFormation Logging Rules
export const cloudformationAwsLoggingRules: Rule[] = [
  // CloudTrail Log Validation
  {
    id: 'CFN_AWS_LOG_001',
    title: 'CloudTrail log validation enabled',
    description: 'CloudTrail should have log file validation enabled to detect tampering.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::CloudTrail::Trail') {
          const enableLogFileValidation = getProperty(resource, 'EnableLogFileValidation');
          
          if (isFalseOrMissing(enableLogFileValidation)) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-validation`,
              ruleId: this.id,
              title: this.title,
              description: `CloudTrail "${resourceName}" does not have log file validation enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Set EnableLogFileValidation to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // CloudTrail Multi-Region
  {
    id: 'CFN_AWS_LOG_002',
    title: 'CloudTrail multi-region enabled',
    description: 'CloudTrail should be configured as multi-region to capture all API calls.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::CloudTrail::Trail') {
          const isMultiRegion = getProperty(resource, 'IsMultiRegionTrail');
          
          if (isFalseOrMissing(isMultiRegion)) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-not-multiregion`,
              ruleId: this.id,
              title: this.title,
              description: `CloudTrail "${resourceName}" is not configured as multi-region.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Set IsMultiRegionTrail to true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // CloudWatch Log Group Retention
  {
    id: 'CFN_AWS_LOG_003',
    title: 'CloudWatch log retention configured',
    description: 'CloudWatch log groups should have retention periods configured to manage costs.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::Logs::LogGroup') {
          const retentionInDays = getProperty(resource, 'RetentionInDays');
          
          if (isFalseOrMissing(retentionInDays)) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-retention`,
              ruleId: this.id,
              title: this.title,
              description: `CloudWatch log group "${resourceName}" does not have retention days specified.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Set RetentionInDays to a value between 1 and 3653.',
            });
          }
        }
      }
      return findings;
    },
  },
];

// CloudFormation Backup Rules
export const cloudformationAwsBackupRules: Rule[] = [
  // RDS Deletion Protection
  {
    id: 'CFN_AWS_BACKUP_001',
    title: 'RDS instance deletion protection enabled',
    description: 'RDS instances should have deletion protection enabled to prevent accidental deletion.',
    severity: 'MEDIUM',
    applicableFileTypes: ['cloudformation'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as CloudFormationTemplate;
      
      if (!parsed?.Resources) return findings;
      
      for (const [resourceName, resource] of Object.entries(parsed.Resources)) {
        if (resource.Type === 'AWS::RDS::DBInstance') {
          const deletionProtection = getProperty(resource, 'DeletionProtection');
          
          if (isFalseOrMissing(deletionProtection)) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-no-deletion-protection`,
              ruleId: this.id,
              title: this.title,
              description: `RDS instance "${resourceName}" does not have deletion protection enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `Resources/${resourceName}`,
              remediation: 'Set DeletionProtection to true.',
            });
          }
        }
      }
      return findings;
    },
  },
];
