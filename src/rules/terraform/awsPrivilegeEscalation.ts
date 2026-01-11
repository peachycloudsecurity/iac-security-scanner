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

interface PolicyStatement {
  Action?: unknown;
  Resource?: unknown;
  Effect?: unknown;
  Condition?: Record<string, unknown>;
}

function getAttrValue(attrs: Record<string, unknown>, key: string): unknown {
  const value = attrs[key];
  if (Array.isArray(value) && value.length > 0) {
    return value[0];
  }
  return value;
}

function parsePolicyDocument(policy: unknown): PolicyStatement[] {
  const statements: PolicyStatement[] = [];
  
  // Handle string (might be JSON string from jsonencode)
  if (typeof policy === 'string') {
    try {
      policy = JSON.parse(policy);
    } catch {
      // Not valid JSON, return empty
      return statements;
    }
  }
  
  // Handle _raw content from parser
  if (typeof policy === 'object' && policy !== null) {
    const policyObj = policy as Record<string, unknown>;
    if (policyObj._raw && typeof policyObj._raw === 'string') {
      try {
        policy = JSON.parse(policyObj._raw);
      } catch {
        // Try to extract JSON from HCL-like structure
        try {
          policy = convertRawToJson(policyObj._raw);
        } catch {
          return statements;
        }
      }
    }
  }
  
  if (typeof policy !== 'object' || policy === null) return statements;
  
  const policyDoc = policy as Record<string, unknown>;
  
  // Check if it's already a statement array (direct Statement)
  if (Array.isArray(policyDoc.Statement)) {
    for (const stmt of policyDoc.Statement) {
      if (typeof stmt === 'object' && stmt !== null) {
        statements.push(stmt as PolicyStatement);
      }
    }
    return statements;
  }
  
  // Get Statement from policy document
  const stmts = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');
  
  if (Array.isArray(stmts)) {
    for (const stmt of stmts) {
      if (typeof stmt === 'object' && stmt !== null) {
        statements.push(stmt as PolicyStatement);
      }
    }
  } else if (typeof stmts === 'object' && stmts !== null) {
    // Single statement (not array)
    statements.push(stmts as PolicyStatement);
  }
  
  return statements;
}

// Helper to convert raw HCL-like content to JSON
function convertRawToJson(raw: string): Record<string, unknown> {
  // Simple extraction - look for Version and Statement
  const result: Record<string, unknown> = {};
  
  // Extract Version
  const versionMatch = raw.match(/Version\s*=\s*"([^"]+)"/);
  if (versionMatch) {
    result.Version = versionMatch[1];
  }
  
  // Extract Statement array - handle multi-line arrays
  const statementStart = raw.indexOf('Statement');
  if (statementStart !== -1) {
    const statements: PolicyStatement[] = [];
    const afterStatement = raw.substring(statementStart);
    
    // Find all statement blocks { ... } - handle nested braces
    let braceDepth = 0;
    let inStatement = false;
    let currentStatement = '';
    
    for (let i = 0; i < afterStatement.length; i++) {
      const char = afterStatement[i];
      
      if (char === '{') {
        if (braceDepth === 0) {
          inStatement = true;
          currentStatement = '';
        }
        braceDepth++;
        if (inStatement) currentStatement += char;
      } else if (char === '}') {
        if (inStatement) currentStatement += char;
        braceDepth--;
        if (braceDepth === 0 && inStatement) {
          // Complete statement found
          const stmt = parseStatementFromRaw(currentStatement);
          if (stmt && Object.keys(stmt).length > 0) {
            statements.push(stmt);
          }
          inStatement = false;
          currentStatement = '';
        }
      } else if (inStatement) {
        currentStatement += char;
      }
    }
    
    if (statements.length > 0) {
      result.Statement = statements;
    }
  }
  
  return result;
}

// Parse a single statement from raw HCL block
function parseStatementFromRaw(block: string): PolicyStatement | null {
  const stmt: PolicyStatement = {};
  
  // Extract Action - handle multi-line arrays
  const actionStart = block.indexOf('Action');
  if (actionStart !== -1) {
    const actionSection = block.substring(actionStart);
    // Match Action = [ ... ] with multi-line support
    const actionMatch = actionSection.match(/Action\s*=\s*\[([^\]]+)\]/s);
    if (actionMatch) {
      const actionsStr = actionMatch[1];
      const actions = actionsStr
        .split(',')
        .map(a => a.trim().replace(/^"|"$/g, ''))
        .filter(a => a);
      stmt.Action = actions.length === 1 ? actions[0] : actions;
    }
  }
  
  // Extract Effect
  const effectMatch = block.match(/Effect\s*=\s*"([^"]+)"/);
  if (effectMatch) {
    stmt.Effect = effectMatch[1];
  }
  
  // Extract Resource
  const resourceMatch = block.match(/Resource\s*=\s*"([^"]+)"/);
  if (resourceMatch) {
    stmt.Resource = resourceMatch[1];
  }
  
  // Extract Condition
  const conditionStart = block.indexOf('Condition');
  if (conditionStart !== -1) {
    const conditionSection = block.substring(conditionStart);
    const stringEqualsMatch = conditionSection.match(/StringEquals\s*=\s*\{[^}]*\}/);
    if (stringEqualsMatch) {
      const condition: Record<string, unknown> = {};
      const passedToServiceMatch = stringEqualsMatch[0].match(/iam:PassedToService\s*=\s*"([^"]+)"/);
      if (passedToServiceMatch) {
        condition.StringEquals = {
          'iam:PassedToService': passedToServiceMatch[1]
        };
        stmt.Condition = condition;
      }
    }
  }
  
  return Object.keys(stmt).length > 0 ? stmt : null;
}

function hasAction(statement: PolicyStatement, actionPattern: string | RegExp): boolean {
  const actions = statement.Action;
  if (!actions) return false;
  
  const actionArray = Array.isArray(actions) ? actions : [actions];
  return actionArray.some((action: unknown) => {
    if (typeof action !== 'string') return false;
    if (typeof actionPattern === 'string') {
      return action.toLowerCase().includes(actionPattern.toLowerCase());
    }
    return actionPattern.test(action);
  });
}

function hasWildcardResource(statement: PolicyStatement): boolean {
  const resources = statement.Resource;
  if (!resources) return false;
  
  const resourceArray = Array.isArray(resources) ? resources : [resources];
  return resourceArray.some((resource: unknown) => {
    return typeof resource === 'string' && resource === '*';
  });
}

function hasPassedToServiceCondition(statement: PolicyStatement): boolean {
  const condition = statement.Condition;
  if (!condition || typeof condition !== 'object') return false;
  
  const conditionObj = condition as Record<string, unknown>;
  const passedToService = getAttrValue(conditionObj, 'iam:PassedToService') || 
                          getAttrValue(conditionObj, 'StringEquals') ||
                          getAttrValue(conditionObj, 'StringLike');
  
  if (typeof passedToService === 'object' && passedToService !== null) {
    const passedToServiceObj = passedToService as Record<string, unknown>;
    return !!getAttrValue(passedToServiceObj, 'iam:PassedToService');
  }
  
  return false;
}

export const terraformAwsPrivilegeEscalationRules: Rule[] = [
  // iam:PassRole with Resource="*"
  {
    id: 'TF_AWS_PRIV_001',
    title: 'IAM PassRole with wildcard resource',
    description: 'ATTACK VECTOR: iam:PassRole with Resource="*" allows passing ANY role in the account to services like EC2/Lambda. Attacker can pass highly privileged roles (Admin, IAM write) to compromise services and steal credentials.',
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
          
          if (!policy) {
            console.log(`[TF_AWS_PRIV_001] No policy found for ${block.resourceType}.${block.name}`);
            continue;
          }
          
          const statements = parsePolicyDocument(policy);
          
          if (statements.length === 0) continue;
          
          for (const statement of statements) {
            if (statement.Effect === 'Allow' || statement.Effect === 'allow') {
              if (hasAction(statement, 'iam:PassRole') && hasWildcardResource(statement)) {
                findings.push({
                  id: `${parsedFile.fileName}-${block.name}-passrole-wildcard`,
                  ruleId: this.id,
                  title: this.title,
                  description: `CRITICAL RISK: Policy "${block.name}" allows iam:PassRole to ANY role ("*"). Attacker can pass Admin/privileged roles to EC2 instances, extract credentials from IMDS, and escalate to full account access.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `${block.resourceType}.${block.name}`,
                  lineNumber: block.startLine,
                  remediation: 'Replace Resource="*" with specific role ARNs: ["arn:aws:iam::ACCOUNT:role/specific-role-name"] AND add Condition: StringEquals: "iam:PassedToService": "ec2.amazonaws.com"',
                });
                break;
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // Missing iam:PassedToService Condition on PassRole
  {
    id: 'TF_AWS_PRIV_002',
    title: 'Missing PassedToService condition on PassRole',
    description: 'ATTACK VECTOR: iam:PassRole without iam:PassedToService condition allows passing roles to ANY AWS service (EC2, Lambda, ECS, Glue, etc). Attacker can abuse unintended services to extract role credentials.',
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
          
          const statements = parsePolicyDocument(policy);
          
          for (const statement of statements) {
            if (statement.Effect === 'Allow' || statement.Effect === 'allow') {
              if (hasAction(statement, 'iam:PassRole') && !hasPassedToServiceCondition(statement)) {
                findings.push({
                  id: `${parsedFile.fileName}-${block.name}-passrole-no-condition`,
                  ruleId: this.id,
                  title: this.title,
                  description: `PRIVESC RISK: Policy "${block.name}" allows passing roles to ANY AWS service. Attacker can abuse Lambda, ECS, or other compute services to extract role credentials instead of just EC2.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `${block.resourceType}.${block.name}`,
                  lineNumber: block.startLine,
                  remediation: 'Add specific condition: Condition = { StringEquals = { "iam:PassedToService" = "ec2.amazonaws.com" } } to restrict role passing to only EC2 service.',
                });
                break;
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // Composite Privilege Escalation: ec2:RunInstances + iam:PassRole
  {
    id: 'TF_AWS_PRIV_003',
    title: 'Composite privilege escalation via EC2 and PassRole',
    description: 'CRITICAL ATTACK CHAIN: ec2:RunInstances + iam:PassRole = Launch EC2 with any role → Access instance metadata (IMDS) → Extract role credentials → Full account compromise. Many scanners miss this cross-policy risk.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      // Collect all policies and their statements
      const policyMap = new Map<string, { block: TerraformBlock; statements: PolicyStatement[] }>();
      const userPolicies = new Map<string, string[]>(); // user name -> policy names
      const rolePolicies = new Map<string, string[]>(); // role name -> policy names
      const processedEntities = new Set<string>(); // Track processed entities to avoid duplicates

      // First pass: collect all policies
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_iam_policy' || 
             block.resourceType === 'aws_iam_role_policy' ||
             block.resourceType === 'aws_iam_user_policy' ||
             block.resourceType === 'aws_iam_group_policy')) {
          const policy = getAttrValue(block.attributes, 'policy') || 
                        getAttrValue(block.attributes, 'policy_document');
          const statements = parsePolicyDocument(policy);
          policyMap.set(block.name, { block, statements });
        }

        // Track policy attachments - handle Terraform references like aws_iam_policy.example.arn
        if (block.type === 'resource' && block.resourceType === 'aws_iam_user_policy_attachment') {
          const user = getAttrValue(block.attributes, 'user');
          const policyArn = getAttrValue(block.attributes, 'policy_arn');
          if (user && policyArn) {
            const userStr = String(user);
            const policyArnStr = String(policyArn);
            
            // Extract policy resource name from Terraform reference
            // Handle: aws_iam_policy.fn1-privesc3-partial.arn -> fn1-privesc3-partial
            // Handle: aws_iam_policy["fn1-privesc3-partial"].arn -> fn1-privesc3-partial
            let policyName = policyArnStr;
            
            // Check for Terraform resource reference pattern
            const tfRefMatch = policyArnStr.match(/aws_iam_policy[\["]?([^"\[\]\.]+)[\]"]?\.arn/);
            if (tfRefMatch) {
              policyName = tfRefMatch[1];
            } else if (policyArnStr.includes('.')) {
              const parts = policyArnStr.split('.');
              if (parts.length >= 2 && parts[0] === 'aws_iam_policy') {
                policyName = parts[1];
              } else if (policyArnStr.includes('/')) {
                policyName = policyArnStr.split('/').pop() || policyArnStr;
              }
            } else if (policyArnStr.includes('/')) {
              policyName = policyArnStr.split('/').pop() || policyArnStr;
            } else if (policyArnStr.startsWith('arn:')) {
              policyName = policyArnStr.split(':').pop() || policyArnStr;
            }
            
            // Also extract user name if it's a Terraform reference
            let userName = userStr;
            const userRefMatch = userStr.match(/aws_iam_user[\["]?([^"\[\]\.]+)[\]"]?\.name/);
            if (userRefMatch) {
              userName = userRefMatch[1];
            } else if (userStr.includes('.')) {
              const parts = userStr.split('.');
              if (parts.length >= 2 && parts[0] === 'aws_iam_user') {
                userName = parts[1];
              }
            }
            
            if (!userPolicies.has(userName)) userPolicies.set(userName, []);
            userPolicies.get(userName)!.push(policyName);
            // Also add variations for matching
            userPolicies.get(userName)!.push(policyArnStr);
            if (policyName !== policyArnStr) {
              userPolicies.get(userName)!.push(`aws_iam_policy.${policyName}`);
            }
          }
        }

        if (block.type === 'resource' && block.resourceType === 'aws_iam_role_policy_attachment') {
          const role = getAttrValue(block.attributes, 'role');
          const policyArn = getAttrValue(block.attributes, 'policy_arn');
          if (role && policyArn) {
            const roleStr = String(role);
            const policyArnStr = String(policyArn);
            
            // Extract policy resource name from Terraform reference
            let policyName = policyArnStr;
            const tfRefMatch = policyArnStr.match(/aws_iam_policy[\["]?([^"\[\]\.]+)[\]"]?\.arn/);
            if (tfRefMatch) {
              policyName = tfRefMatch[1];
            } else if (policyArnStr.includes('.')) {
              const parts = policyArnStr.split('.');
              if (parts.length >= 2 && parts[0] === 'aws_iam_policy') {
                policyName = parts[1];
              } else if (policyArnStr.includes('/')) {
                policyName = policyArnStr.split('/').pop() || policyArnStr;
              }
            } else if (policyArnStr.includes('/')) {
              policyName = policyArnStr.split('/').pop() || policyArnStr;
            } else if (policyArnStr.startsWith('arn:')) {
              policyName = policyArnStr.split(':').pop() || policyArnStr;
            }
            
            // Extract role name if it's a Terraform reference
            let roleName = roleStr;
            const roleRefMatch = roleStr.match(/aws_iam_role[\["]?([^"\[\]\.]+)[\]"]?\.name/);
            if (roleRefMatch) {
              roleName = roleRefMatch[1];
            } else if (roleStr.includes('.')) {
              const parts = roleStr.split('.');
              if (parts.length >= 2 && parts[0] === 'aws_iam_role') {
                roleName = parts[1];
              }
            }
            
            if (!rolePolicies.has(roleName)) rolePolicies.set(roleName, []);
            rolePolicies.get(roleName)!.push(policyName);
            // Also add variations for matching
            rolePolicies.get(roleName)!.push(policyArnStr);
            if (policyName !== policyArnStr) {
              rolePolicies.get(roleName)!.push(`aws_iam_policy.${policyName}`);
            }
          }
        }
      }

      // Second pass: check for composite privilege escalation
      for (const [policyName, { block, statements }] of policyMap) {
        let hasRunInstances = false;
        let hasPassRole = false;

        for (const statement of statements) {
          if (statement.Effect === 'Allow' || statement.Effect === 'allow') {
            if (hasAction(statement, 'ec2:RunInstances')) {
              hasRunInstances = true;
            }
            if (hasAction(statement, 'iam:PassRole')) {
              hasPassRole = true;
            }
          }
        }

        // Check if same entity has both permissions (via multiple policies)
        const entityName = block.name;
        
        // Check if user has both (only process each user once)
        for (const [user, policies] of userPolicies) {
          const entityKey = `user-${user}`;
          if (processedEntities.has(entityKey)) continue;
          
          // Check if this policy is attached to the user (match by name or ARN)
          const isAttached = policies.some(p => 
            p === policyName || 
            p === `aws_iam_policy.${policyName}.arn` ||
            p.includes(policyName)
          );
          
          if (isAttached) {
            // Check other policies for this user
            for (const otherPolicyRef of policies) {
              // Try to find the policy by various name formats
              let otherPolicyName = otherPolicyRef;
              if (otherPolicyRef.includes('.')) {
                // Handle terraform references like aws_iam_policy.example.arn
                const parts = otherPolicyRef.split('.');
                if (parts.length >= 2) {
                  otherPolicyName = parts[1];
                }
              } else if (otherPolicyRef.includes('/')) {
                otherPolicyName = otherPolicyRef.split('/').pop() || otherPolicyRef;
              }
              
              if (otherPolicyName !== policyName) {
                const otherPolicy = policyMap.get(otherPolicyName);
                if (otherPolicy) {
                  for (const stmt of otherPolicy.statements) {
                    if (stmt.Effect === 'Allow' || stmt.Effect === 'allow') {
                      if (hasRunInstances && hasAction(stmt, 'iam:PassRole')) {
                        findings.push({
                          id: `${parsedFile.fileName}-${user}-composite-privesc`,
                          ruleId: this.id,
                          title: this.title,
                            description: `EXPLOIT PATH: User "${user}" can launch EC2 instances (via "${policyName}") AND pass privileged roles (via "${otherPolicyName}") → Launch instance with Admin role → curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ → Steal Admin credentials → Full account takeover.`,
                            severity: this.severity,
                            fileName: parsedFile.fileName,
                            resourcePath: `aws_iam_user.${user}`,
                            lineNumber: block.startLine,
                            remediation: 'IMMEDIATE: Remove ec2:RunInstances OR iam:PassRole. If both needed: 1) Add iam:PassedToService condition 2) Restrict EC2 to specific AMI-IDs 3) Add IP/MFA conditions 4) Use instance profiles with limited scope.',
                        });
                        processedEntities.add(entityKey);
                        break; // Stop after first finding for this user
                      } else if (hasPassRole && hasAction(stmt, 'ec2:RunInstances')) {
                        findings.push({
                          id: `${parsedFile.fileName}-${user}-composite-privesc`,
                          ruleId: this.id,
                          title: this.title,
                          description: `IAM user "${user}" has both ec2:RunInstances and iam:PassRole permissions (via policies "${policyName}" and "${otherPolicyName}"), enabling privilege escalation.`,
                          severity: this.severity,
                          fileName: parsedFile.fileName,
                          resourcePath: `aws_iam_user.${user}`,
                          lineNumber: block.startLine,
                          remediation: 'Remove one of the permissions or add restrictions. Use iam:PassedToService condition and restrict EC2 instance creation.',
                        });
                        processedEntities.add(entityKey);
                        break; // Stop after first finding for this user
                      }
                    }
                  }
                  if (processedEntities.has(entityKey)) break; // Exit outer loop if found
                }
              }
            }
          }
        }

        // Check if role has both (only process each role once)
        for (const [role, policies] of rolePolicies) {
          const entityKey = `role-${role}`;
          if (processedEntities.has(entityKey)) continue;
          
          // Check if this policy is attached to the role
          const isAttached = policies.some(p => 
            p === policyName || 
            p === `aws_iam_policy.${policyName}.arn` ||
            p.includes(policyName)
          );
          
          if (isAttached) {
            for (const otherPolicyRef of policies) {
              // Try to find the policy by various name formats
              let otherPolicyName = otherPolicyRef;
              if (otherPolicyRef.includes('.')) {
                const parts = otherPolicyRef.split('.');
                if (parts.length >= 2) {
                  otherPolicyName = parts[1];
                }
              } else if (otherPolicyRef.includes('/')) {
                otherPolicyName = otherPolicyRef.split('/').pop() || otherPolicyRef;
              }
              
              if (otherPolicyName !== policyName) {
                const otherPolicy = policyMap.get(otherPolicyName);
                if (otherPolicy) {
                  for (const stmt of otherPolicy.statements) {
                    if (stmt.Effect === 'Allow' || stmt.Effect === 'allow') {
                      if (hasRunInstances && hasAction(stmt, 'iam:PassRole')) {
                        findings.push({
                          id: `${parsedFile.fileName}-${role}-composite-privesc`,
                          ruleId: this.id,
                          title: this.title,
                          description: `EXPLOIT PATH: Role "${role}" can launch EC2 instances (via "${policyName}") AND pass privileged roles (via "${otherPolicyName}") → Nested role assumption attack → Launch privileged instances → IMDS credential theft → Account compromise.`,
                          severity: this.severity,
                          fileName: parsedFile.fileName,
                          resourcePath: `aws_iam_role.${role}`,
                          lineNumber: block.startLine,
                          remediation: 'IMMEDIATE: Remove ec2:RunInstances OR iam:PassRole. If both needed: 1) Add iam:PassedToService="ec2.amazonaws.com" condition 2) Restrict to specific AMI-IDs 3) Use least-privilege instance profiles.',
                        });
                        processedEntities.add(entityKey);
                        break; // Stop after first finding for this role
                      } else if (hasPassRole && hasAction(stmt, 'ec2:RunInstances')) {
                        findings.push({
                          id: `${parsedFile.fileName}-${role}-composite-privesc`,
                          ruleId: this.id,
                          title: this.title,
                          description: `EXPLOIT PATH: Role "${role}" can pass roles (via "${policyName}") AND launch EC2 instances (via "${otherPolicyName}") → Launch instance with Admin role → Access IMDS → Extract privileged credentials → Account takeover.`,
                          severity: this.severity,
                          fileName: parsedFile.fileName,
                          resourcePath: `aws_iam_role.${role}`,
                          lineNumber: block.startLine,
                          remediation: 'IMMEDIATE: Remove ec2:RunInstances OR iam:PassRole. If both needed: 1) Add iam:PassedToService="ec2.amazonaws.com" condition 2) Restrict to specific AMI-IDs 3) Use least-privilege instance profiles.',
                        });
                        processedEntities.add(entityKey);
                        break; // Stop after first finding for this role
                      }
                    }
                  }
                  if (processedEntities.has(entityKey)) break; // Exit outer loop if found
                }
              }
            }
          }
        }

        // Also check if single policy has both
        const singlePolicyKey = `policy-${policyName}`;
        if (hasRunInstances && hasPassRole && !processedEntities.has(singlePolicyKey)) {
          findings.push({
            id: `${parsedFile.fileName}-${policyName}-composite-privesc-single`,
            ruleId: this.id,
            title: this.title,
            description: `IAM policy "${policyName}" contains both ec2:RunInstances and iam:PassRole, enabling privilege escalation by launching EC2 instances with privileged roles.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `${block.resourceType}.${policyName}`,
            lineNumber: block.startLine,
            remediation: 'Remove one of the permissions or add restrictions. Use iam:PassedToService condition and restrict EC2 instance creation to specific AMIs/subnets.',
          });
          processedEntities.add(singlePolicyKey);
        }
      }

      return findings;
    },
  },

  // Wildcard Resources on EC2 Actions
  {
    id: 'TF_AWS_PRIV_004',
    title: 'EC2 actions with wildcard resources',
    description: 'RISK AMPLIFIER: ec2:RunInstances with Resource="*" allows launching instances with ANY AMI, subnet, security group. Combined with PassRole creates unrestricted privilege escalation vector.',
    severity: 'MEDIUM',
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
          
          const statements = parsePolicyDocument(policy);
          
          for (const statement of statements) {
            if (statement.Effect === 'Allow' || statement.Effect === 'allow') {
              if (hasAction(statement, /^ec2:/) && hasWildcardResource(statement)) {
                findings.push({
                  id: `${parsedFile.fileName}-${block.name}-ec2-wildcard`,
                  ruleId: this.id,
                  title: this.title,
                  description: `PRIVESC ENABLER: Policy "${block.name}" allows EC2 actions on ALL resources. Attacker can launch instances with malicious AMIs, use any subnet/security group, and bypass network controls.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `${block.resourceType}.${block.name}`,
                  lineNumber: block.startLine,
                  remediation: 'Replace Resource="*" with specific ARNs: Resource = ["arn:aws:ec2:region:account:instance/*", "arn:aws:ec2:region::image/ami-SPECIFIC"] + add Condition for allowed subnets/security groups.',
                });
                break;
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // Same Privileged Policies on User and Role
  {
    id: 'TF_AWS_PRIV_005',
    title: 'Duplicate privileged policies on user and role',
    description: 'IDENTITY SPRAWL RISK: Same privileged policies on user AND role creates multiple attack paths. Attacker can compromise either identity type to gain same privileges.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      const userPolicies = new Map<string, string[]>(); // user name -> policy ARNs
      const rolePolicies = new Map<string, string[]>(); // role name -> policy ARNs

      // Collect policy attachments
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iam_user_policy_attachment') {
          const user = getAttrValue(block.attributes, 'user') as string;
          const policyArn = getAttrValue(block.attributes, 'policy_arn') as string;
          if (user && policyArn) {
            if (!userPolicies.has(user)) userPolicies.set(user, []);
            userPolicies.get(user)!.push(policyArn);
          }
        }

        if (block.type === 'resource' && block.resourceType === 'aws_iam_role_policy_attachment') {
          const role = getAttrValue(block.attributes, 'role') as string;
          const policyArn = getAttrValue(block.attributes, 'policy_arn') as string;
          if (role && policyArn) {
            if (!rolePolicies.has(role)) rolePolicies.set(role, []);
            rolePolicies.get(role)!.push(policyArn);
          }
        }
      }

      // Check for duplicates
      for (const [user, userPolicyArns] of userPolicies) {
        for (const [role, rolePolicyArns] of rolePolicies) {
          const commonPolicies = userPolicyArns.filter(arn => rolePolicyArns.includes(arn));
          if (commonPolicies.length > 0) {
            // Check if these policies have sensitive permissions
            const policyNames = commonPolicies.map(arn => arn.split('/').pop() || '');
            findings.push({
              id: `${parsedFile.fileName}-${user}-${role}-duplicate-policies`,
              ruleId: this.id,
              title: this.title,
              description: `BLAST RADIUS: Policies (${policyNames.join(', ')}) attached to BOTH user "${user}" and role "${role}". Attacker can compromise either identity path. Multiple credential types (access keys + assume role) increase persistence options.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_iam_user.${user}, aws_iam_role.${role}`,
              lineNumber: 1,
              remediation: 'CHOOSE ONE: Either user-based access (with access keys) OR role-based access (with assume role). Remove duplicate policy attachments. Prefer roles over users for better security posture.',
            });
          }
        }
      }

      return findings;
    },
  },
];
