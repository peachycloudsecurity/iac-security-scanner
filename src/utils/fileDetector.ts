import { FileType } from '@/types/scanner';

export function detectFileType(fileName: string, content: string): FileType {
  const extension = fileName.split('.').pop()?.toLowerCase() || '';
  
  // Check by extension first
  if (extension === 'tf' || extension === 'hcl') {
    return 'terraform';
  }
  
  if (fileName.toLowerCase() === 'dockerfile' || fileName.toLowerCase().startsWith('dockerfile.')) {
    return 'dockerfile';
  }
  
  if (fileName.toLowerCase().includes('docker-compose') && (extension === 'yaml' || extension === 'yml')) {
    return 'docker-compose';
  }
  
  // Check for CloudFormation template extension
  if (extension === 'template') {
    return 'cloudformation';
  }
  
  if (extension === 'json') {
    // Check for CloudFormation indicators in JSON
    if (isCloudFormationContent(content)) {
      return 'cloudformation';
    }
    return 'json';
  }
  
  if (extension === 'yaml' || extension === 'yml') {
    // Check for Kubernetes indicators first
    if (isKubernetesContent(content)) {
      return 'kubernetes';
    }
    // Check for CloudFormation indicators
    if (isCloudFormationContent(content)) {
      return 'cloudformation';
    }
    return 'yaml';
  }
  
  // Content-based detection as fallback
  return detectByContent(content);
}

function isKubernetesContent(content: string): boolean {
  const k8sIndicators = [
    /apiVersion:\s*['"]?[\w./]+['"]?/i,
    /kind:\s*['"]?(Deployment|Service|Pod|ConfigMap|Secret|Ingress|StatefulSet|DaemonSet|Job|CronJob|Namespace|ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|PersistentVolume|PersistentVolumeClaim)['"]?/i,
  ];
  
  return k8sIndicators.every(pattern => pattern.test(content));
}

function isCloudFormationContent(content: string): boolean {
  const cfnIndicators = [
    // Template format version
    /AWSTemplateFormatVersion/i,
    /["']AWSTemplateFormatVersion["']/i,
    // Resources section
    /"Resources"\s*:/i,
    /Resources:\s*/i,
    // AWS resource types
    /"Type"\s*:\s*"AWS::/i,
    /Type:\s*AWS::/i,
    // CloudFormation intrinsic functions (common ones)
    /!Ref[\s\[]/i,
    /!GetAtt[\s\[]/i,
    /!Sub[\s\[]/i,
    /!Join[\s\[]/i,
    /!Split[\s\[]/i,
    /!Select[\s\[]/i,
    /Fn::Ref/i,
    /Fn::GetAtt/i,
    /Fn::Sub/i,
    /Fn::Join/i,
    // AWS partition/region/account pseudo parameters
    /AWS::Partition/i,
    /AWS::Region/i,
    /AWS::AccountId/i,
    /AWS::StackName/i,
  ];
  
  // At least one CloudFormation indicator should be present
  return cfnIndicators.some(pattern => pattern.test(content));
}

function detectByContent(content: string): FileType {
  const trimmed = content.trim();
  
  // Check for Terraform HCL patterns first (before YAML check)
  // Look for resource, data, provider, variable, output, module, terraform blocks
  const terraformPatterns = [
    /^\s*(resource|provider|variable|output|data|module|terraform)\s+["']?\w+/m,
    /resource\s+["'][^"']+["']\s+["'][^"']+["']\s*\{/m,
    /data\s+["'][^"']+["']\s+["'][^"']+["']\s*\{/m,
    /aws_\w+/m,
    /jsonencode\s*\(/m,
    /cidr_block\s*=/m,
    /instance_type\s*=/m,
    /availability_zone\s*=/m,
  ];
  
  // Strong Terraform indicators should take priority
  if (terraformPatterns.some(pattern => pattern.test(trimmed))) {
    return 'terraform';
  }
  
  // Check for JSON
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      JSON.parse(trimmed);
      return 'json';
    } catch {
      // Not valid JSON
    }
  }
  
  // Check for Dockerfile
  if (/^FROM\s+\S+/im.test(trimmed)) {
    return 'dockerfile';
  }
  
  // Check for Docker Compose
  if (/^(version|services):\s*/im.test(trimmed)) {
    return 'docker-compose';
  }
  
  // Check for CloudFormation
  if (isCloudFormationContent(trimmed)) {
    return 'cloudformation';
  }
  
  // Check for YAML (but be careful not to misidentify Terraform)
  if (/^[\w-]+:\s*/m.test(trimmed) || trimmed.startsWith('---')) {
    // Double-check it's not Terraform with tags/map syntax
    if (trimmed.includes('resource "') || trimmed.includes('data "') || trimmed.includes('provider "')) {
      return 'terraform';
    }
    if (isKubernetesContent(trimmed)) {
      return 'kubernetes';
    }
    return 'yaml';
  }
  
  return 'unknown';
}

export function getFileTypeLabel(fileType: FileType): string {
  const labels: Record<FileType, string> = {
    terraform: 'Terraform',
    json: 'JSON',
    yaml: 'YAML',
    kubernetes: 'Kubernetes',
    dockerfile: 'Dockerfile',
    'docker-compose': 'Docker Compose',
    cloudformation: 'CloudFormation',
    unknown: 'Unknown',
  };
  return labels[fileType];
}

export function getFileTypeIcon(fileType: FileType): string {
  const icons: Record<FileType, string> = {
    terraform: '⬡',
    json: '{ }',
    yaml: '📄',
    kubernetes: '☸',
    dockerfile: '🐳',
    'docker-compose': '🐙',
    cloudformation: '☁️',
    unknown: '?',
  };
  return icons[fileType];
}
