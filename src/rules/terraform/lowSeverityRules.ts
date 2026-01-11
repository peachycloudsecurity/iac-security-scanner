import { Rule } from '@/types/scanner';

export const terraformLowSeverityRules: Rule[] = [
  {
    id: 'TF_AWS_TAG_001',
    title: 'Resources should have consistent tagging',
    description: 'COMPLIANCE: Resource lacks standard tags like Environment, Owner, Project. This affects cost tracking, resource management, and compliance auditing.',
    severity: 'LOW',
    applicableFileTypes: ['terraform'],
    evaluate: (parsedFile) => {
      const findings = [];
      const resources = parsedFile.resources || [];
      
      const requiredTags = ['Environment', 'Owner', 'Project', 'Name'];
      
      for (const resource of resources) {
        const resourceType = resource.type;
        const resourceName = resource.name;
        const tags = resource.attributes?.tags || {};
        
        // Skip resources that typically don't need tags
        if (resourceType?.includes('data.') || 
            resourceType?.includes('local') ||
            resourceType?.includes('variable') ||
            resourceType?.includes('output')) {
          continue;
        }
        
        const missingTags = requiredTags.filter(tag => !tags[tag]);
        
        if (missingTags.length > 0) {
          findings.push({
            ruleId: 'TF_AWS_TAG_001',
            title: 'Resources should have consistent tagging',
            description: `COMPLIANCE: Resource "${resourceName}" lacks standard tags: ${missingTags.join(', ')}. This affects cost tracking, resource management, and compliance auditing.`,
            severity: 'LOW',
            resourcePath: `${resourceType}.${resourceName}`,
            lineNumber: resource.lineNumber,
            remediation: `Add missing tags to resource: ${missingTags.map(tag => `${tag} = "appropriate-value"`).join(', ')}`
          });
        }
      }
      
      return findings;
    }
  },
  
  {
    id: 'TF_AWS_NAME_001',
    title: 'Resources should follow naming conventions',
    description: 'BEST PRACTICE: Resource names should follow consistent naming patterns for better organization and identification.',
    severity: 'LOW',
    applicableFileTypes: ['terraform'],
    evaluate: (parsedFile) => {
      const findings = [];
      const resources = parsedFile.resources || [];
      
      for (const resource of resources) {
        const resourceName = resource.name;
        const resourceType = resource.type;
        
        // Skip data sources and locals
        if (resourceType?.startsWith('data.') || 
            resourceType?.includes('local') ||
            resourceType?.includes('variable') ||
            resourceType?.includes('output')) {
          continue;
        }
        
        // Check naming convention (should contain hyphens, not underscores for AWS resources)
        if (resourceName && resourceName.includes('_') && !resourceName.includes('-')) {
          findings.push({
            ruleId: 'TF_AWS_NAME_001',
            title: 'Resources should follow naming conventions',
            description: `BEST PRACTICE: Resource "${resourceName}" uses underscores. AWS resources typically use hyphens for better readability and consistency.`,
            severity: 'LOW',
            resourcePath: `${resourceType}.${resourceName}`,
            lineNumber: resource.lineNumber,
            remediation: `Rename resource to use hyphens instead of underscores: ${resourceName.replace(/_/g, '-')}`
          });
        }
      }
      
      return findings;
    }
  },

  {
    id: 'TF_AWS_DESC_001',
    title: 'Resources should have descriptions',
    description: 'DOCUMENTATION: Resources lack description attributes, making infrastructure documentation incomplete.',
    severity: 'LOW',
    applicableFileTypes: ['terraform'],
    evaluate: (parsedFile) => {
      const findings = [];
      const resources = parsedFile.resources || [];
      
      const resourcesNeedingDescription = [
        'aws_security_group',
        'aws_iam_policy',
        'aws_iam_role',
        'aws_lambda_function',
        'aws_s3_bucket',
        'aws_vpc',
        'aws_subnet'
      ];
      
      for (const resource of resources) {
        const resourceType = resource.type;
        const resourceName = resource.name;
        
        if (resourcesNeedingDescription.includes(resourceType)) {
          const description = resource.attributes?.description;
          
          if (!description || description.trim() === '') {
            findings.push({
              ruleId: 'TF_AWS_DESC_001',
              title: 'Resources should have descriptions',
              description: `DOCUMENTATION: ${resourceType} "${resourceName}" lacks description attribute. This makes infrastructure documentation incomplete and harder to understand.`,
              severity: 'LOW',
              resourcePath: `${resourceType}.${resourceName}`,
              lineNumber: resource.lineNumber,
              remediation: `Add description attribute: description = "Brief description of this ${resourceType.replace('aws_', '')} purpose"`
            });
          }
        }
      }
      
      return findings;
    }
  },

  {
    id: 'TF_AWS_VER_001',
    title: 'Provider version should be pinned',
    description: 'VERSION CONTROL: Terraform provider version not pinned, may cause unexpected behavior with updates.',
    severity: 'LOW',
    applicableFileTypes: ['terraform'],
    evaluate: (parsedFile) => {
      const findings = [];
      const providers = parsedFile.providers || [];
      
      for (const provider of providers) {
        if (provider.name === 'aws' && !provider.version) {
          findings.push({
            ruleId: 'TF_AWS_VER_001',
            title: 'Provider version should be pinned',
            description: 'VERSION CONTROL: AWS provider version not pinned. This may cause unexpected behavior when provider updates are released.',
            severity: 'LOW',
            resourcePath: 'provider.aws',
            lineNumber: provider.lineNumber,
            remediation: 'Pin provider version: version = "~> 5.0" in terraform block or provider block'
          });
        }
      }
      
      return findings;
    }
  }
];