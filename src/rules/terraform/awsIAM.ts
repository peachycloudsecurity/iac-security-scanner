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

function checkPolicyDocument(policy: unknown): { hasWildcard: boolean; hasAdmin: boolean } {
  const result = { hasWildcard: false, hasAdmin: false };
  
  if (typeof policy !== 'object' || policy === null) return result;
  
  const policyDoc = policy as Record<string, unknown>;
  const statements = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');
  
  if (!Array.isArray(statements)) return result;
  
  for (const stmt of statements) {
    if (typeof stmt !== 'object' || stmt === null) continue;
    const statement = stmt as Record<string, unknown>;
    const actions = getAttrValue(statement, 'Action') || getAttrValue(statement, 'action');
    const effect = getAttrValue(statement, 'Effect') || getAttrValue(statement, 'effect');
    
    if (effect === 'Allow' || effect === 'allow') {
      if (Array.isArray(actions)) {
        if (actions.includes('*') || actions.includes('*:*')) {
          result.hasWildcard = true;
        }
        if (actions.some((a: unknown) => 
          typeof a === 'string' && (a.includes('*') || a.toLowerCase().includes('admin'))
        )) {
          result.hasAdmin = true;
        }
      } else if (typeof actions === 'string') {
        if (actions === '*' || actions === '*:*') {
          result.hasWildcard = true;
        }
        if (actions.toLowerCase().includes('admin')) {
          result.hasAdmin = true;
        }
      }
    }
  }
  
  return result;
}

export const terraformAwsIAMRules: Rule[] = [
  // IAM Policy with Wildcard Actions
  {
    id: 'TF_AWS_IAM_001',
    title: 'IAM policy blocks wildcard actions',
    description: 'ADMIN ACCESS: Action = "*" grants ALL AWS service permissions across entire account. Equivalent to root access - can create users, modify billing, delete everything.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_iam_policy' || 
             block.resourceType === 'aws_iam_role_policy' ||
             block.resourceType === 'aws_iam_user_policy' ||
             block.resourceType === 'aws_iam_group_policy')) {
          const policy = getAttrValue(block.attributes, 'policy') || 
                        getAttrValue(block.attributes, 'policy_document');
          
          const { hasWildcard } = checkPolicyDocument(policy);
          
          if (hasWildcard) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-wildcard-policy`,
              ruleId: this.id,
              title: this.title,
              description: `FULL ADMIN ACCESS: Policy "${block.name}" contains Action="*" granting ALL AWS permissions. This is equivalent to root access - can create/delete anything in the account.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${block.resourceType}.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Replace Action="*" with specific actions like ["s3:GetObject", "ec2:DescribeInstances"]. Use AWS managed policies like ReadOnlyAccess if broad read access needed.',
            });
          }
        }
      }
      return findings;
    },
  },

  // IAM User with Access Keys
  {
    id: 'TF_AWS_IAM_002',
    title: 'IAM user with access keys detected',
    description: 'CREDENTIAL RISK: Access keys are permanent credentials (never rotate automatically). Perfect for attacker persistence - stolen keys work indefinitely unlike temporary role tokens.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iam_access_key') {
          findings.push({
            id: `${parsedFile.fileName}-${block.name}-access-key`,
            ruleId: this.id,
            title: this.title,
            description: `PERSISTENCE RISK: Access key "${block.name}" creates permanent credentials that never expire. Stolen keys provide indefinite access without MFA enforcement.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `aws_iam_access_key.${block.name}`,
            lineNumber: block.startLine,
            remediation: 'DELETE this access key. Use IAM roles with STS AssumeRole instead. For applications: use EC2 instance profiles or ECS task roles. For CLI: use aws sso login.',
          });
        }
      }
      return findings;
    },
  },

  // IAM Role Allows Public Assume
  {
    id: 'TF_AWS_IAM_003',
    title: 'IAM role restricts assume role principals',
    description: 'PUBLIC ASSUME: Principal="*" allows ANYONE on internet to assume this role. No authentication required - just need to know role ARN.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iam_role') {
          const assumeRolePolicy = getAttrValue(block.attributes, 'assume_role_policy');
          const statements = getAttrValue(assumeRolePolicy as Record<string, unknown>, 'Statement') ||
                           getAttrValue(assumeRolePolicy as Record<string, unknown>, 'statement');
          
          if (Array.isArray(statements)) {
            for (const stmt of statements) {
              if (typeof stmt !== 'object' || stmt === null) continue;
              const statement = stmt as Record<string, unknown>;
              const principal = getAttrValue(statement, 'Principal') || getAttrValue(statement, 'principal');
              
              if (typeof principal === 'object' && principal !== null) {
                const principalObj = principal as Record<string, unknown>;
                const aws = getAttrValue(principalObj, 'AWS') || getAttrValue(principalObj, 'aws');
                
                if (Array.isArray(aws) && aws.includes('*')) {
                  findings.push({
                    id: `${parsedFile.fileName}-${block.name}-public-assume`,
                    ruleId: this.id,
                    title: this.title,
                    description: `ANONYMOUS ACCESS: Role "${block.name}" allows Principal="*" - anyone on internet can assume this role without authentication. Just needs role ARN to gain access.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_iam_role.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: 'Change Principal from "*" to specific account: "arn:aws:iam::ACCOUNT-ID:root" or service: "ec2.amazonaws.com". Add ExternalId condition for cross-account access.',
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

  // IAM Policy with Wildcard Resources
  {
    id: 'TF_AWS_IAM_004',
    title: 'IAM policy blocks wildcard resources',
    description: 'RESOURCE WILDCARD: Resource="*" grants access to ALL resources in ALL regions/accounts. Can read, modify, delete any S3 bucket, EC2 instance, IAM user, etc.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_iam_policy' || 
             block.resourceType === 'aws_iam_role_policy' ||
             block.resourceType === 'aws_iam_user_policy' ||
             block.resourceType === 'aws_iam_group_policy')) {
          const policy = getAttrValue(block.attributes, 'policy') || 
                        getAttrValue(block.attributes, 'policy_document');
          
          if (typeof policy === 'object' && policy !== null) {
            const policyDoc = policy as Record<string, unknown>;
            const statements = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');
            
            if (Array.isArray(statements)) {
              for (const stmt of statements) {
                if (typeof stmt !== 'object' || stmt === null) continue;
                const statement = stmt as Record<string, unknown>;
                const resources = getAttrValue(statement, 'Resource') || getAttrValue(statement, 'resource');
                const effect = getAttrValue(statement, 'Effect') || getAttrValue(statement, 'effect');
                
                if ((effect === 'Allow' || effect === 'allow') && resources) {
                  if (Array.isArray(resources) && resources.includes('*')) {
                    findings.push({
                      id: `${parsedFile.fileName}-${block.name}-wildcard-resource`,
                      ruleId: this.id,
                      title: this.title,
                      description: `IAM policy "${block.name}" allows access to all resources using wildcard.`,
                      severity: this.severity,
                      fileName: parsedFile.fileName,
                      resourcePath: `${block.resourceType}.${block.name}`,
                      lineNumber: block.startLine,
                      remediation: 'Replace wildcard resources with specific resource ARNs.',
                    });
                    break;
                  } else if (typeof resources === 'string' && resources === '*') {
                    findings.push({
                      id: `${parsedFile.fileName}-${block.name}-wildcard-resource`,
                      ruleId: this.id,
                      title: this.title,
                      description: `IAM policy "${block.name}" allows access to all resources using wildcard.`,
                      severity: this.severity,
                      fileName: parsedFile.fileName,
                      resourcePath: `${block.resourceType}.${block.name}`,
                      lineNumber: block.startLine,
                      remediation: 'Replace wildcard resources with specific resource ARNs.',
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

  // IAM Admin Policy
  {
    id: 'TF_AWS_IAM_005',
    title: 'IAM policies attached to groups or roles',
    description: 'MANAGEMENT OVERHEAD: Direct user policy attachments create permission sprawl. Hard to audit who has what access. No centralized policy management.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iam_user_policy') {
          findings.push({
            id: `${parsedFile.fileName}-${block.name}-user-policy`,
            ruleId: this.id,
            title: this.title,
            description: `PERMISSION SPRAWL: Policy "${block.name}" directly attached to user. Creates management overhead and audit complexity. Users should inherit permissions through groups/roles.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `aws_iam_user_policy.${block.name}`,
            lineNumber: block.startLine,
            remediation: 'Create IAM group: aws_iam_group → attach policy to group → add user to group. Or use IAM roles with aws_iam_role_policy_attachment for better security.',
          });
        }
      }
      return findings;
    },
  },

  // CKV_AWS_274: AdministratorAccess Policy
  {
    id: 'TF_AWS_IAM_006',
    title: 'IAM entities using AdministratorAccess policy',
    description: 'AWS MANAGED ADMIN POLICY: AdministratorAccess grants FULL permissions to everything in AWS account. Equivalent to root user access.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      const adminAccessArns = [
        'arn:aws:iam::aws:policy/AdministratorAccess',
        'arn:aws:iam::aws:policy/AdministratorAccess-AWSElasticBeanstalk',
      ];

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_iam_user_policy_attachment' ||
             block.resourceType === 'aws_iam_role_policy_attachment' ||
             block.resourceType === 'aws_iam_group_policy_attachment')) {
          const policyArn = getAttrValue(block.attributes, 'policy_arn');
          const policyArnStr = String(policyArn || '');
          
                // Check if AdministratorAccess policy is attached
                if (adminAccessArns.some(arn => typeof policyArnStr === 'string' && policyArnStr.includes('AdministratorAccess'))) {
            const entityType = block.resourceType.includes('user') ? 'user' : 
                             block.resourceType.includes('role') ? 'role' : 'group';
            const entityName = getAttrValue(block.attributes, entityType) || block.name;
            
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-admin-access`,
              ruleId: this.id,
              title: this.title,
            description: `FULL ADMIN: ${entityType} "${entityName}" has AdministratorAccess policy - can create/delete users, modify billing, access all data, delete entire infrastructure.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `${block.resourceType}.${block.name}`,
            lineNumber: block.startLine,
            remediation: 'Remove "arn:aws:iam::aws:policy/AdministratorAccess". Create custom policy with only needed permissions like ["s3:ListBucket", "ec2:DescribeInstances"].',
            });
          }
        }
      }
      return findings;
    },
  },

  // CKV_AWS_355: Wildcard Resource in Policy (more specific check)
  {
    id: 'TF_AWS_IAM_007',
    title: 'IAM policy statement with wildcard resource',
    description: 'STATEMENT WILDCARD: Individual policy statements with Resource="*" bypass least-privilege. Grants access to ALL resources for allowed actions.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_iam_policy' || 
             block.resourceType === 'aws_iam_role_policy' ||
             block.resourceType === 'aws_iam_user_policy' ||
             block.resourceType === 'aws_iam_group_policy')) {
          const policy = getAttrValue(block.attributes, 'policy') || 
                        getAttrValue(block.attributes, 'policy_document');
          
          if (typeof policy === 'object' && policy !== null) {
            const policyDoc = policy as Record<string, unknown>;
            const statements = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');
            
            if (Array.isArray(statements)) {
              for (const stmt of statements) {
                if (typeof stmt !== 'object' || stmt === null) continue;
                const statement = stmt as Record<string, unknown>;
                const resources = getAttrValue(statement, 'Resource') || getAttrValue(statement, 'resource');
                const effect = getAttrValue(statement, 'Effect') || getAttrValue(statement, 'effect');
                
                if ((effect === 'Allow' || effect === 'allow') && resources) {
                  const resourceArray = Array.isArray(resources) ? resources : [resources];
                  if (resourceArray.some((r: unknown) => r === '*' || (typeof r === 'string' && r.trim() === '*'))) {
                    findings.push({
                      id: `${parsedFile.fileName}-${block.name}-wildcard-resource-statement`,
                      ruleId: this.id,
                      title: this.title,
                      description: `OVERPERMISSIVE STATEMENT: Policy "${block.name}" has statement with Resource="*" - actions can target ANY resource in account without restrictions.`,
                      severity: this.severity,
                      fileName: parsedFile.fileName,
                      resourcePath: `${block.resourceType}.${block.name}`,
                      lineNumber: block.startLine,
                      remediation: 'Change Resource from "*" to specific ARNs. Example: Resource = ["arn:aws:s3:::specific-bucket/*"] or add conditions like aws:RequestedRegion.',
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

  // IAM Policy with Dangerous Privilege Escalation Actions
  {
    id: 'TF_AWS_IAM_008',
    title: 'IAM policy allows dangerous privilege escalation actions',
    description: 'PRIVESC ACTIONS: Actions like iam:CreateUser, iam:AttachUserPolicy, iam:CreateRole enable creating new privileged identities. With Resource="*" can create Admin users.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      // Dangerous actions that can lead to privilege escalation
      const dangerousActions = [
        'iam:CreateUser',
        'iam:AttachUserPolicy',
        'iam:PutUserPolicy',
        'iam:CreateAccessKey',
        'iam:CreateLoginProfile',
        'iam:UpdateLoginProfile',
        'iam:AddUserToGroup',
        'iam:CreateRole',
        'iam:AttachRolePolicy',
        'iam:PutRolePolicy',
        'iam:UpdateAssumeRolePolicy',
        'sts:AssumeRole',
        'iam:CreatePolicy',
        'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion',
      ];

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_iam_policy' || 
             block.resourceType === 'aws_iam_role_policy' ||
             block.resourceType === 'aws_iam_user_policy' ||
             block.resourceType === 'aws_iam_group_policy')) {
          const policy = getAttrValue(block.attributes, 'policy') || 
                        getAttrValue(block.attributes, 'policy_document');
          
          if (typeof policy === 'object' && policy !== null) {
            const policyDoc = policy as Record<string, unknown>;
            const statements = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');
            
            if (Array.isArray(statements)) {
              for (const stmt of statements) {
                if (typeof stmt !== 'object' || stmt === null) continue;
                const statement = stmt as Record<string, unknown>;
                const actions = getAttrValue(statement, 'Action') || getAttrValue(statement, 'action');
                const effect = getAttrValue(statement, 'Effect') || getAttrValue(statement, 'effect');
                const resources = getAttrValue(statement, 'Resource') || getAttrValue(statement, 'resource');
                
                if (effect === 'Allow' || effect === 'allow') {
                  const actionArray = Array.isArray(actions) ? actions : [actions];
                  const hasWildcardResource = Array.isArray(resources) 
                    ? resources.includes('*') 
                    : resources === '*';
                  
                  // Check if policy has dangerous actions with wildcard resource
                  const hasDangerousAction = actionArray.some((action: unknown) => {
                    if (typeof action !== 'string') return false;
                    return dangerousActions.some(dangerous => 
                      action.toLowerCase().includes(dangerous.toLowerCase()) ||
                      action === '*' ||
                      action === '*:*'
                    );
                  });

                  if (hasDangerousAction && hasWildcardResource) {
                    findings.push({
                      id: `${parsedFile.fileName}-${block.name}-dangerous-privesc-actions`,
                      ruleId: this.id,
                      title: this.title,
                      description: `PRIVILEGE CREATION: Policy "${block.name}" allows creating new privileged identities with Resource="*". Can create Admin users, attach Admin policies, create login profiles for backdoor access.`,
                      severity: this.severity,
                      fileName: parsedFile.fileName,
                      resourcePath: `${block.resourceType}.${block.name}`,
                      lineNumber: block.startLine,
                      remediation: 'Remove iam:CreateUser, iam:AttachUserPolicy, iam:CreateRole OR restrict Resource to specific paths like ["arn:aws:iam::account:user/specific-prefix/*"]. Add conditions to prevent Admin policy attachments.',
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

  // IAM Role without External ID for Cross-Account Access
  {
    id: 'TF_AWS_IAM_009',
    title: 'IAM role allows cross-account access without external ID',
    description: 'CONFUSED DEPUTY: Cross-account role without ExternalId allows any principal in trusted account to assume role. Third-party can abuse your trust relationship.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iam_role') {
          const assumeRolePolicy = getAttrValue(block.attributes, 'assume_role_policy');
          const statements = getAttrValue(assumeRolePolicy as Record<string, unknown>, 'Statement') ||
                           getAttrValue(assumeRolePolicy as Record<string, unknown>, 'statement');
          
          if (Array.isArray(statements)) {
            for (const stmt of statements) {
              if (typeof stmt !== 'object' || stmt === null) continue;
              const statement = stmt as Record<string, unknown>;
              const principal = getAttrValue(statement, 'Principal') || getAttrValue(statement, 'principal');
              const condition = getAttrValue(statement, 'Condition') || getAttrValue(statement, 'condition');
              
              // Check if principal is another AWS account (not service)
              if (typeof principal === 'object' && principal !== null) {
                const principalObj = principal as Record<string, unknown>;
                const aws = getAttrValue(principalObj, 'AWS') || getAttrValue(principalObj, 'aws');
                
                // Check if it's a cross-account ARN (contains account ID, not service)
                const isCrossAccount = Array.isArray(aws) 
                  ? aws.some((a: unknown) => typeof a === 'string' && (/^\d{12}$/.test(a) || a.includes('arn:aws:iam::')))
                  : typeof aws === 'string' && (/^\d{12}$/.test(aws) || aws.includes('arn:aws:iam::'));
                
                if (isCrossAccount) {
                  // Check for external ID condition
                  const hasExternalId = condition && typeof condition === 'object' && 
                    (getAttrValue(condition as Record<string, unknown>, 'StringEquals') ||
                     getAttrValue(condition as Record<string, unknown>, 'StringLike'));
                  
                  if (!hasExternalId) {
                    findings.push({
                      id: `${parsedFile.fileName}-${block.name}-no-external-id`,
                      ruleId: this.id,
                      title: this.title,
                    description: `CONFUSED DEPUTY: Role "${block.name}" trusts external account without ExternalId. Any user in trusted account can assume role - no additional verification required.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_iam_role.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: 'Add external ID: Condition = { StringEquals = { "sts:ExternalId" = "unique-secret-string" } }. Share ExternalId securely with trusted party only.',
                    });
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

  // IAM Password Policy Strength
  {
    id: 'TF_AWS_IAM_010',
    title: 'IAM password policy enforces strong passwords',
    description: 'WEAK PASSWORDS: IAM without strong password policy allows simple passwords like "Password123". Brute-force attacks succeed quickly. No MFA enforcement.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iam_account_password_policy') {
          const minLength = getAttrValue(block.attributes, 'minimum_password_length');
          const requireNumbers = getAttrValue(block.attributes, 'require_numbers');
          const requireSymbols = getAttrValue(block.attributes, 'require_symbols');
          const requireUppercase = getAttrValue(block.attributes, 'require_uppercase_characters');
          const requireLowercase = getAttrValue(block.attributes, 'require_lowercase_characters');

          const weaknesses: string[] = [];

          if (!minLength || (typeof minLength === 'number' && minLength < 14)) {
            weaknesses.push('minimum_password_length < 14');
          }
          if (!requireNumbers) {
            weaknesses.push('require_numbers not enforced');
          }
          if (!requireSymbols) {
            weaknesses.push('require_symbols not enforced');
          }
          if (!requireUppercase) {
            weaknesses.push('require_uppercase_characters not enforced');
          }
          if (!requireLowercase) {
            weaknesses.push('require_lowercase_characters not enforced');
          }

          if (weaknesses.length > 0) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-weak-password-policy`,
              ruleId: this.id,
              title: this.title,
              description: `WEAK POLICY: IAM password policy "${block.name}" has weaknesses: ${weaknesses.join(', ')}. Users can set easily crackable passwords. Credential stuffing attacks succeed.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_iam_account_password_policy.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set minimum_password_length = 14, require_numbers = true, require_symbols = true, require_uppercase_characters = true, require_lowercase_characters = true.',
            });
          }
        }
      }
      return findings;
    },
  },

  // IAM Root Account MFA
  {
    id: 'TF_AWS_IAM_011',
    title: 'IAM root account has MFA enabled',
    description: 'ROOT WITHOUT MFA: Root account without MFA means single password compromise = full account takeover. Can delete everything, modify billing, create backdoor users.',
    severity: 'CRITICAL',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      // Check if any MFA device is configured for root
      let hasRootMFA = false;
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iam_virtual_mfa_device') {
          const virtualMfaName = getAttrValue(block.attributes, 'virtual_mfa_device_name');
          if (virtualMfaName === 'root-account-mfa-device') {
            hasRootMFA = true;
            break;
          }
        }
      }

      // If no password policy or MFA found, add finding
      if (!hasRootMFA) {
        findings.push({
          id: `${parsedFile.fileName}-root-no-mfa`,
          ruleId: this.id,
          title: this.title,
          description: `ROOT ACCOUNT RISK: No MFA configured for root account in Terraform. Root credentials with only password = single point of failure. Phishing attack = full AWS account compromise.`,
          severity: 'CRITICAL',
          fileName: parsedFile.fileName,
          resourcePath: 'root_account',
          lineNumber: 1,
          remediation: 'MANUAL ACTION REQUIRED: Enable MFA for root account via AWS Console > My Security Credentials > Multi-factor authentication (MFA). Use hardware token for maximum security. Never use root for daily operations.',
        });
      }
      return findings;
    },
  },

  // IAM User MFA Enforcement
  {
    id: 'TF_AWS_IAM_012',
    title: 'IAM users require MFA for console access',
    description: 'NO MFA ENFORCEMENT: IAM users without MFA requirement can log in with password only. Phishing, credential leaks, brute-force all bypass authentication.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      // Check if there's a policy that denies actions without MFA
      let hasMFAPolicy = false;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' &&
            (block.resourceType === 'aws_iam_policy' ||
             block.resourceType === 'aws_iam_group_policy')) {
          const policy = getAttrValue(block.attributes, 'policy');

          if (typeof policy === 'object' && policy !== null) {
            const policyDoc = policy as Record<string, unknown>;
            const statements = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');

            if (Array.isArray(statements)) {
              for (const stmt of statements) {
                if (typeof stmt !== 'object' || stmt === null) continue;
                const statement = stmt as Record<string, unknown>;
                const condition = getAttrValue(statement, 'Condition') || getAttrValue(statement, 'condition');

                if (condition && typeof condition === 'object') {
                  const condObj = condition as Record<string, unknown>;
                  const boolIfExists = getAttrValue(condObj, 'BoolIfExists');
                  if (boolIfExists && typeof boolIfExists === 'object') {
                    const mfaAuth = getAttrValue(boolIfExists as Record<string, unknown>, 'aws:MultiFactorAuthPresent');
                    if (mfaAuth === true) {
                      hasMFAPolicy = true;
                      break;
                    }
                  }
                }
              }
            }
          }
        }
      }

      if (!hasMFAPolicy) {
        findings.push({
          id: `${parsedFile.fileName}-no-mfa-enforcement`,
          ruleId: this.id,
          title: this.title,
          description: `MFA NOT REQUIRED: No IAM policy found requiring MFA for user actions. Console users can authenticate with password only - vulnerable to phishing and credential theft.`,
          severity: this.severity,
          fileName: parsedFile.fileName,
          resourcePath: 'iam_policies',
          lineNumber: 1,
          remediation: 'Create IAM policy: Effect = "Deny", Action = "*", Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } } and attach to all user groups.',
        });
      }
      return findings;
    },
  },
];
