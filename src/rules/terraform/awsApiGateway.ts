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

export const terraformAwsApiGatewayRules: Rule[] = [
  // API Gateway Access Logging
  {
    id: 'TF_AWS_APIGW_007',
    title: 'API Gateway access logging enabled',
    description: 'NO AUDIT TRAIL: API Gateway without access logs means no visibility into API calls, failed auth attempts, or suspicious traffic patterns. Cannot detect or investigate security incidents.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_api_gateway_stage') {
          const accessLogSettings = getAttrValue(block.attributes, 'access_log_settings');
          if (isFalseOrMissing(accessLogSettings)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-apigw-no-logging`,
              ruleId: this.id,
              title: this.title,
              description: `BLIND SPOT: API Gateway stage "${block.name}" has no access logs. Cannot track who called API, when, or with what parameters. Impossible to detect brute-force attacks or data exfiltration attempts.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_api_gateway_stage.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add access_log_settings { destination_arn = aws_cloudwatch_log_group.api_gw.arn; format = "$requestId" } to enable CloudWatch logging for all API requests.',
            });
          }
        }
      }
      return findings;
    },
  },

  // API Gateway V2 (HTTP/WebSocket) Access Logging
  {
    id: 'TF_AWS_APIGW_008',
    title: 'API Gateway V2 access logging enabled',
    description: 'NO VISIBILITY: HTTP API/WebSocket without access logs provides zero visibility into real-time traffic, authentication failures, or abuse patterns.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_apigatewayv2_stage') {
          const accessLogSettings = getAttrValue(block.attributes, 'access_log_settings');
          if (isFalseOrMissing(accessLogSettings)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-apigwv2-no-logging`,
              ruleId: this.id,
              title: this.title,
              description: `NO AUDIT: API Gateway V2 stage "${block.name}" missing access logs. Cannot monitor WebSocket connections, HTTP requests, or detect API abuse. Security incidents go undetected.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_apigatewayv2_stage.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add access_log_settings { destination_arn = aws_cloudwatch_log_group.apigw_v2.arn; format = "$context.requestId" } for request tracking.',
            });
          }
        }
      }
      return findings;
    },
  },

  // API Gateway Execution Logging
  {
    id: 'TF_AWS_APIGW_009',
    title: 'API Gateway CloudWatch execution logging enabled',
    description: 'NO DEBUGGING: Without CloudWatch logs, cannot troubleshoot integration errors, Lambda timeouts, or backend failures. Blind to API execution flow.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_api_gateway_stage') {
          const xrayTracingEnabled = getAttrValue(block.attributes, 'xray_tracing_enabled');

          // Check for CloudWatch settings in the stage
          const settings = block.attributes;
          const loggingLevel = getAttrValue(settings, 'logging_level');

          if (isFalseOrMissing(loggingLevel)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-apigw-no-execution-logging`,
              ruleId: this.id,
              title: this.title,
              description: `NO DEBUG LOGS: API Gateway stage "${block.name}" has no CloudWatch execution logging. Cannot debug integration errors or trace request flow through backend services.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_api_gateway_stage.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set logging_level = "INFO" or "ERROR" in aws_api_gateway_method_settings. Also consider enabling xray_tracing_enabled = true for distributed tracing.',
            });
          }
        }
      }
      return findings;
    },
  },

  // API Gateway Authorization
  {
    id: 'TF_AWS_APIGW_010',
    title: 'API Gateway method authorization configured',
    description: 'OPEN API: API Gateway method with authorization = "NONE" allows unauthenticated access. Anyone on internet can call API without credentials.',
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

          if (authorization === 'NONE' && !apiKeyRequired) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-apigw-no-auth`,
              ruleId: this.id,
              title: this.title,
              description: `PUBLIC API: Method "${block.name}" allows anonymous access with authorization = "NONE". No authentication, no API keys - completely open to internet. DoS and abuse risk.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_api_gateway_method.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set authorization = "AWS_IAM" (IAM auth) or "COGNITO_USER_POOLS" (Cognito) or enable api_key_required = true. For public APIs, implement rate limiting with usage plans.',
            });
          }
        }
      }
      return findings;
    },
  },

  // API Gateway V2 Route Authorization
  {
    id: 'TF_AWS_APIGW_011',
    title: 'API Gateway V2 route authorization configured',
    description: 'UNAUTHENTICATED ROUTE: HTTP API route without authorization allows anyone to invoke. No identity verification or access control.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_apigatewayv2_route') {
          const authorizationType = getAttrValue(block.attributes, 'authorization_type');

          if (authorizationType === 'NONE' || isFalseOrMissing(authorizationType)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-apigwv2-no-auth`,
              ruleId: this.id,
              title: this.title,
              description: `OPEN ROUTE: API Gateway V2 route "${block.name}" has no authorization. Anyone can invoke without JWT token or IAM credentials. Complete public access.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_apigatewayv2_route.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set authorization_type = "JWT" with aws_apigatewayv2_authorizer or "AWS_IAM" for authenticated access. Add rate limiting with throttling settings.',
            });
          }
        }
      }
      return findings;
    },
  },

  // API Gateway WAF Association
  {
    id: 'TF_AWS_APIGW_012',
    title: 'API Gateway WAF protection enabled',
    description: 'NO WEB FIREWALL: API Gateway without WAF exposes API to SQL injection, XSS, rate abuse, and bot attacks. No layer 7 protection against OWASP top 10.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      const stagesWithWAF = new Set<string>();

      // First pass: collect stages that have WAF associations
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_wafv2_web_acl_association') {
          const resourceArn = getAttrValue(block.attributes, 'resource_arn');
          if (resourceArn) {
            stagesWithWAF.add(String(resourceArn));
          }
        }
      }

      // Second pass: check stages without WAF
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_api_gateway_stage') {
          const stageName = `aws_api_gateway_stage.${block.name}`;
          if (!stagesWithWAF.has(stageName)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-apigw-no-waf`,
              ruleId: this.id,
              title: this.title,
              description: `UNPROTECTED API: Stage "${block.name}" has no WAF association. Vulnerable to SQL injection, XSS, DDoS, and automated bot attacks. No rate limiting at network level.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_api_gateway_stage.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Associate WAF: resource "aws_wafv2_web_acl_association" { resource_arn = aws_api_gateway_stage.STAGE.arn; web_acl_arn = aws_wafv2_web_acl.WAF.arn }',
            });
          }
        }
      }
      return findings;
    },
  },
];
