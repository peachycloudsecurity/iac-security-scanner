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

export const terraformAwsStepFunctionsRules: Rule[] = [
  // Step Functions Logging
  {
    id: 'TF_AWS_SFN_001',
    title: 'Step Functions state machine logging enabled',
    description: 'NO EXECUTION TRACE: Step Functions without logging provides zero visibility into state transitions, execution failures, or data flow. Cannot debug failed workflows or audit execution history.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sfn_state_machine') {
          const loggingConfiguration = getAttrValue(block.attributes, 'logging_configuration');

          if (isFalseOrMissing(loggingConfiguration)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-sfn-no-logging`,
              ruleId: this.id,
              title: this.title,
              description: `EXECUTION BLIND SPOT: State machine "${block.name}" has no CloudWatch logging. Cannot trace state transitions, debug failures, or audit which data was processed. Incident investigation impossible.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_sfn_state_machine.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add logging_configuration { log_destination = "\${aws_cloudwatch_log_group.sfn.arn}:*"; level = "ALL"; include_execution_data = true } for complete execution visibility.',
            });
          } else if (typeof loggingConfiguration === 'object' && loggingConfiguration !== null) {
            const level = getAttrValue(loggingConfiguration as Record<string, unknown>, 'level');
            if (level === 'OFF' || isFalseOrMissing(level)) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-sfn-logging-off`,
                ruleId: this.id,
                title: this.title,
                description: `LOGGING DISABLED: State machine "${block.name}" has logging_configuration but level = "OFF". No execution data captured to CloudWatch.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_sfn_state_machine.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Set level = "ALL" to log all events or level = "ERROR" to log only failures. Enable include_execution_data = true to capture input/output data.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // Step Functions X-Ray Tracing
  {
    id: 'TF_AWS_SFN_002',
    title: 'Step Functions X-Ray tracing enabled',
    description: 'NO DISTRIBUTED TRACING: State machine without X-Ray cannot trace requests across Lambda, DynamoDB, and other services. Cannot diagnose performance bottlenecks or service dependencies.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sfn_state_machine') {
          const tracingConfiguration = getAttrValue(block.attributes, 'tracing_configuration');

          if (isFalseOrMissing(tracingConfiguration)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-sfn-no-xray`,
              ruleId: this.id,
              title: this.title,
              description: `NO TRACING: State machine "${block.name}" missing X-Ray tracing. Cannot visualize service map, identify slow integrations, or correlate errors across Lambda/DynamoDB/API calls.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_sfn_state_machine.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add tracing_configuration { enabled = true } to enable AWS X-Ray distributed tracing for complete workflow visibility and performance analysis.',
            });
          } else if (typeof tracingConfiguration === 'object' && tracingConfiguration !== null) {
            const enabled = getAttrValue(tracingConfiguration as Record<string, unknown>, 'enabled');
            if (enabled === false) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-sfn-xray-disabled`,
                ruleId: this.id,
                title: this.title,
                description: `TRACING DISABLED: State machine "${block.name}" has tracing_configuration but enabled = false. X-Ray tracing not active.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_sfn_state_machine.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Set enabled = true in tracing_configuration to activate X-Ray distributed tracing.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // Step Functions Express State Machine Logging
  {
    id: 'TF_AWS_SFN_003',
    title: 'Step Functions Express workflows have CloudWatch logging',
    description: 'EXPRESS WORKFLOW BLIND: Express state machines process data synchronously - without logs, execution history unavailable. Cannot troubleshoot or audit high-throughput workflows.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_sfn_state_machine') {
          const type = getAttrValue(block.attributes, 'type');
          const loggingConfiguration = getAttrValue(block.attributes, 'logging_configuration');

          if (type === 'EXPRESS' && isFalseOrMissing(loggingConfiguration)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-sfn-express-no-logging`,
              ruleId: this.id,
              title: this.title,
              description: `EXPRESS NO LOGS: Express state machine "${block.name}" has NO logging. Execution history not stored - once workflow completes, all execution details lost forever. Critical for audit compliance.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_sfn_state_machine.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'REQUIRED for Express workflows: Add logging_configuration { log_destination = "\${aws_cloudwatch_log_group.sfn.arn}:*"; level = "ALL" } - execution history NOT kept without logs.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Step Functions IAM Role Least Privilege
  {
    id: 'TF_AWS_SFN_004',
    title: 'Step Functions uses least privilege IAM roles',
    description: 'OVERPRIVILEGED WORKFLOW: State machine role with wildcard permissions can access ALL AWS resources. Compromised workflow can read/modify/delete anything in account.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iam_role_policy') {
          const roleName = getAttrValue(block.attributes, 'role');
          const policy = getAttrValue(block.attributes, 'policy');

          // Check if this is a Step Functions role
          const roleStr = String(roleName || '');
          if (roleStr.toLowerCase().includes('stepfunctions') || roleStr.toLowerCase().includes('sfn') || roleStr.toLowerCase().includes('state_machine')) {
            if (typeof policy === 'object' && policy !== null) {
              const policyDoc = policy as Record<string, unknown>;
              const statements = getAttrValue(policyDoc, 'Statement') || getAttrValue(policyDoc, 'statement');

              if (Array.isArray(statements)) {
                for (const stmt of statements) {
                  if (typeof stmt !== 'object' || stmt === null) continue;
                  const statement = stmt as Record<string, unknown>;
                  const actions = getAttrValue(statement, 'Action') || getAttrValue(statement, 'action');
                  const resources = getAttrValue(statement, 'Resource') || getAttrValue(statement, 'resource');

                  const actionArray = Array.isArray(actions) ? actions : [actions];
                  const hasWildcardAction = actionArray.some((a: unknown) => a === '*' || a === '*:*');
                  const hasWildcardResource = resources === '*' || (Array.isArray(resources) && resources.includes('*'));

                  if (hasWildcardAction || hasWildcardResource) {
                    findings.push({
                      id: `${parsedFile.fileName}-${block.name}-sfn-overprivileged`,
                      ruleId: this.id,
                      title: this.title,
                      description: `EXCESSIVE PERMISSIONS: Step Functions role policy "${block.name}" uses wildcards - state machine can access ALL AWS services/resources. Violates least privilege principle.`,
                      severity: this.severity,
                      fileName: parsedFile.fileName,
                      resourcePath: `aws_iam_role_policy.${block.name}`,
                      lineNumber: block.startLine,
                      remediation: 'Replace wildcards with specific permissions: Action = ["lambda:InvokeFunction", "dynamodb:PutItem"]; Resource = ["arn:aws:lambda:REGION:ACCOUNT:function/FUNCTION-NAME"]',
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
