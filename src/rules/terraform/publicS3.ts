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

export const terraformPublicS3Rule: Rule = {
  id: 'TF_AWS_S3_006',
  title: 'S3 bucket blocks public access',
  description: 'S3 buckets with public access enabled can expose sensitive data to the internet.',
  severity: 'HIGH',
  applicableFileTypes: ['terraform'],
  
  evaluate(parsedFile: ParsedFile): Finding[] {
    const findings: Finding[] = [];
    const parsed = parsedFile.parsed as TerraformParsed;
    
    if (!parsed?.blocks) return findings;
    
    for (const block of parsed.blocks) {
      if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket') {
        const acl = block.attributes.acl;
        
        if (acl === 'public-read' || acl === 'public-read-write') {
          findings.push({
            id: `${parsedFile.fileName}-${block.name}-public-acl`,
            ruleId: this.id,
            title: this.title,
            description: `S3 bucket "${block.name}" has ACL set to "${acl}" which allows public access.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `aws_s3_bucket.${block.name}`,
            lineNumber: block.startLine,
            remediation: 'Set the ACL to "private" or remove the acl attribute and use aws_s3_bucket_public_access_block to block public access.',
          });
        }
      }
      
      // Also check for aws_s3_bucket_public_access_block with false values
      if (block.type === 'resource' && block.resourceType === 'aws_s3_bucket_public_access_block') {
        const attrs = block.attributes;
        if (
          attrs.block_public_acls === false ||
          attrs.block_public_policy === false ||
          attrs.ignore_public_acls === false ||
          attrs.restrict_public_buckets === false
        ) {
          findings.push({
            id: `${parsedFile.fileName}-${block.name}-public-access-block`,
            ruleId: this.id,
            title: 'S3 Public Access Block Not Fully Enabled',
            description: `S3 bucket public access block "${block.name}" has one or more settings disabled.`,
            severity: 'MEDIUM',
            fileName: parsedFile.fileName,
            resourcePath: `aws_s3_bucket_public_access_block.${block.name}`,
            lineNumber: block.startLine,
            remediation: 'Set all four public access block settings to true.',
          });
        }
      }
    }
    
    return findings;
  },
};
