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
    description: 'IAM policies should not grant full administrative access using wildcard actions.',
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
              description: `IAM policy "${block.name}" allows wildcard actions which grants full administrative privileges.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${block.resourceType}.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Replace wildcard actions with specific, least-privilege actions.',
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
    title: 'IAM users without access keys',
    description: 'IAM users should not have access keys to follow security best practices.',
    severity: 'MEDIUM',
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
            description: `IAM access key "${block.name}" is created. Consider using IAM roles instead.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `aws_iam_access_key.${block.name}`,
            lineNumber: block.startLine,
            remediation: 'Use IAM roles with temporary credentials instead of access keys.',
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
    description: 'IAM roles should not allow public assume to prevent unauthorized access.',
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
                    description: `IAM role "${block.name}" allows any principal to assume it.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `aws_iam_role.${block.name}`,
                    lineNumber: block.startLine,
                    remediation: 'Restrict the Principal to specific AWS accounts or services.',
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
    description: 'IAM policies should not grant access to all resources using wildcard resource.',
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
    description: 'IAM policies should be attached to groups or roles, not directly to users.',
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
            description: `IAM policy "${block.name}" is attached directly to a user. Attach policies to groups or roles instead.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `aws_iam_user_policy.${block.name}`,
            lineNumber: block.startLine,
            remediation: 'Attach policies to IAM groups or roles instead of directly to users.',
          });
        }
      }
      return findings;
    },
  },
];
