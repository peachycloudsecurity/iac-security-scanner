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

export const terraformAwsLambdaRules: Rule[] = [
  // Lambda Function Not Public
  {
    id: 'TF_AWS_LAMBDA_001',
    title: 'Lambda function not publicly accessible',
    description: 'Lambda functions should not be publicly accessible to prevent unauthorized invocations.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_lambda_permission') {
          const principal = getAttrValue(block.attributes, 'principal');
          if (principal === '*' || principal === 'arn:aws:iam::*:*') {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-public-access`,
              ruleId: this.id,
              title: this.title,
              description: `Lambda permission "${block.name}" allows public access (Principal: *).`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_lambda_permission.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Restrict Principal to specific AWS accounts or services.',
            });
          }
        }
      }
      return findings;
    },
  },
];
