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

function checkForSecrets(text: string): boolean {
  const secretPatterns = [
    /AKIA[0-9A-Z]{16}/g, // AWS Access Key
    /aws_secret_access_key\s*=\s*["\']([^"\']+)["\']/gi,
    /password\s*=\s*["\']([^"\']+)["\']/gi,
    /secret\s*=\s*["\']([^"\']+)["\']/gi,
    /token\s*=\s*["\']([^"\']+)["\']/gi,
    /api_key\s*=\s*["\']([^"\']+)["\']/gi,
    /private_key\s*=\s*["\']([^"\']+)["\']/gi,
  ];
  
  return secretPatterns.some(pattern => pattern.test(text));
}

export const terraformAwsCriticalSecurityRules: Rule[] = [
  // KMS Key Wildcard Principal (CKV_AWS_33)
  {
    id: 'TF_AWS_KMS_001',
    title: 'KMS key policy blocks wildcard principal',
    description: 'KMS ENCRYPTION BYPASS: Principal="*" allows ANYONE to use encryption key. Attacker can decrypt all encrypted data (RDS, S3, EBS) without key access.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_kms_key') {
          const policy = getAttrValue(block.attributes, 'policy');
          
          if (typeof policy === 'object' && policy !== null) {
            const policyDoc = policy as Record<string, unknown>;
            const statements = getAttrValue(policyDoc, 'Statement');
            
            if (Array.isArray(statements)) {
              for (const stmt of statements) {
                if (typeof stmt !== 'object' || stmt === null) continue;
                const statement = stmt as Record<string, unknown>;
                const principal = getAttrValue(statement, 'Principal');
                const effect = getAttrValue(statement, 'Effect');
                
                if (effect === 'Allow' || effect === 'allow') {
                  if (principal === '*' || 
                      (typeof principal === 'object' && principal !== null)) {
                    const principalObj = principal as Record<string, unknown>;
                    const aws = getAttrValue(principalObj, 'AWS');
                    
                    if (aws === '*' || (Array.isArray(aws) && aws.includes('*'))) {
                      findings.push({
                        id: `${parsedFile.fileName}-${block.name}-kms-wildcard-principal`,
                        ruleId: this.id,
                        title: this.title,
                        description: `ENCRYPTION COMPROMISE: KMS key "${block.name}" allows Principal="*" - anyone can decrypt encrypted data (RDS, S3, EBS) using this key.`,
                        severity: this.severity,
                        fileName: parsedFile.fileName,
                        resourcePath: `aws_kms_key.${block.name}`,
                        lineNumber: block.startLine,
                        remediation: 'Replace Principal="*" with specific account: "arn:aws:iam::ACCOUNT-ID:root" or service: "ec2.amazonaws.com". Add Condition blocks for additional restrictions.',
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

  // EC2 Hard-coded Secrets (CKV_AWS_46)
  {
    id: 'TF_AWS_EC2_002',
    title: 'EC2 user data contains no hardcoded secrets',
    description: 'CREDENTIAL EXPOSURE: Hardcoded secrets in user_data are visible in EC2 console, logs, CloudTrail, and instance metadata. Never expire.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_instance' ||
             block.resourceType === 'aws_launch_template' ||
             block.resourceType === 'aws_launch_configuration')) {
          const userData = getAttrValue(block.attributes, 'user_data');
          
          if (typeof userData === 'string' && checkForSecrets(userData)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-hardcoded-secrets`,
              ruleId: this.id,
              title: this.title,
              description: `EXPOSED CREDENTIALS: ${block.resourceType} "${block.name}" has hardcoded secrets in user_data. Visible in EC2 console, CloudTrail logs, and instance metadata.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${block.resourceType}.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Remove hardcoded secrets. Use: 1) AWS Systems Manager Parameter Store 2) AWS Secrets Manager 3) IAM roles 4) Environment variables from secure source.',
            });
          }
        }
      }
      return findings;
    },
  },

  // IMDS v1 Disabled (CKV_AWS_79)
  {
    id: 'TF_AWS_EC2_003',
    title: 'EC2 instance disables IMDSv1',
    description: 'SSRF TO CREDENTIAL THEFT: IMDSv1 allows HTTP requests (no authentication). SSRF attacks can steal EC2 role credentials remotely.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_instance') {
          const metadataOptions = getAttrValue(block.attributes, 'metadata_options');
          
          let imdsv1Enabled = true; // Default is enabled
          
          if (typeof metadataOptions === 'object' && metadataOptions !== null) {
            const metadataObj = metadataOptions as Record<string, unknown>;
            const httpTokens = getAttrValue(metadataObj, 'http_tokens');
            if (httpTokens === 'required') {
              imdsv1Enabled = false;
            }
          }
          
          if (imdsv1Enabled) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-imdsv1-enabled`,
              ruleId: this.id,
              title: this.title,
              description: `SSRF VULNERABILITY: Instance "${block.name}" allows IMDSv1 (HTTP without auth). SSRF attacks can steal role credentials via http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_instance.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add: metadata_options { http_tokens = "required" } to enforce IMDSv2 (requires authentication headers).',
            });
          }
        }
      }
      return findings;
    },
  },

  // Lambda Environment Credentials (CKV_AWS_45)
  {
    id: 'TF_AWS_LAMBDA_002',
    title: 'Lambda environment has no hardcoded credentials',
    description: 'CREDENTIAL LEAK: Environment variables with secrets visible in Lambda console, logs, CloudTrail. Accessible to anyone with function read permissions.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_lambda_function') {
          const environment = getAttrValue(block.attributes, 'environment');
          
          if (typeof environment === 'object' && environment !== null) {
            const envObj = environment as Record<string, unknown>;
            const variables = getAttrValue(envObj, 'variables');
            
            if (typeof variables === 'object' && variables !== null) {
              const varsObj = variables as Record<string, unknown>;
              
              for (const [varName, varValue] of Object.entries(varsObj)) {
                if (typeof varValue === 'string' && checkForSecrets(varValue)) {
                  findings.push({
                    id: `${parsedFile.fileName}-${block.name}-env-credentials`,
                    ruleId: this.id,
                    title: this.title,
                    description: `EXPOSED SECRETS: Function "${block.name}" has hardcoded credentials in environment variable "${varName}". Visible in Lambda console and accessible via function metadata.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_lambda_function.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: `Remove "${varName}" from environment variables. Use: 1) AWS Secrets Manager with automatic rotation 2) SSM Parameter Store 3) IAM roles for AWS service access.`,
                  });
                  break; // Only report once per function
                }
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // EKS Public Access (CKV_AWS_37)
  {
    id: 'TF_AWS_EKS_001',
    title: 'EKS cluster API server not publicly accessible',
    description: 'PUBLIC K8S API: Kubernetes API server accessible from internet. Attackers can attempt credential attacks, API abuse, and cluster reconnaissance.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_eks_cluster') {
          const vpcConfig = getAttrValue(block.attributes, 'vpc_config');
          
          let isPublic = true; // Default is public
          
          if (typeof vpcConfig === 'object' && vpcConfig !== null) {
            const vpcObj = vpcConfig as Record<string, unknown>;
            const endpointPrivateAccess = getAttrValue(vpcObj, 'endpoint_private_access');
            const endpointPublicAccess = getAttrValue(vpcObj, 'endpoint_public_access');
            
            if (endpointPublicAccess === false && endpointPrivateAccess === true) {
              isPublic = false;
            }
          }
          
          if (isPublic) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-public-api`,
              ruleId: this.id,
              title: this.title,
              description: `EXPOSED K8S API: Cluster "${block.name}" API server accessible from internet. Vulnerable to authentication attacks, unauthorized kubectl access, and cluster enumeration.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_eks_cluster.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set vpc_config: endpoint_public_access = false, endpoint_private_access = true. Access via VPN, bastion, or VPC peering only.',
            });
          }
        }
      }
      return findings;
    },
  },

  // API Gateway Method Without Auth (CKV2_AWS_70)
  {
    id: 'TF_AWS_API_001',
    title: 'API Gateway method requires authentication',
    description: 'UNAUTHENTICATED API: API Gateway method allows anonymous access. Anyone can invoke API endpoints, potentially causing DoS, data access, or abuse.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_api_gateway_method') {
          const authorization = getAttrValue(block.attributes, 'authorization');
          const apiKeyRequired = getAttrValue(block.attributes, 'api_key_required');
          const httpMethod = getAttrValue(block.attributes, 'http_method');
          
          // Skip OPTIONS methods (CORS preflight)
          if (httpMethod === 'OPTIONS') continue;
          
          if (authorization === 'NONE' && apiKeyRequired !== true) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-auth`,
              ruleId: this.id,
              title: this.title,
              description: `ANONYMOUS API ACCESS: Method "${block.name}" has authorization="NONE" and no API key required. Anyone can invoke this endpoint without credentials.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_api_gateway_method.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set authorization = "AWS_IAM" or "COGNITO_USER_POOLS" or set api_key_required = true. For public APIs, add rate limiting and WAF protection.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Secrets Manager Secret Encryption
  {
    id: 'TF_AWS_SECRETS_001',
    title: 'Secrets Manager secret uses customer managed KMS key',
    description: 'DEFAULT KMS KEY: Secrets encrypted with AWS managed key. AWS has access to decrypt secrets. No key rotation control.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_secretsmanager_secret') {
          const kmsKeyId = getAttrValue(block.attributes, 'kms_key_id');
          
          if (!kmsKeyId) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-default-kms`,
              ruleId: this.id,
              title: this.title,
              description: `AWS MANAGED ENCRYPTION: Secret "${block.name}" uses default AWS managed KMS key. AWS can decrypt your secrets. No control over key rotation or access policies.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_secretsmanager_secret.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add kms_key_id = aws_kms_key.example.arn to use customer managed key. Create KMS key with restricted access policy.',
            });
          }
        }
      }
      return findings;
    },
  },
];