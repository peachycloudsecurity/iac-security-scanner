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

export const terraformAwsEKSRules: Rule[] = [
  // EKS Cluster Endpoint Public Access
  {
    id: 'TF_AWS_EKS_007',
    title: 'EKS cluster endpoint restricts public access',
    description: 'PUBLIC K8S API: Cluster endpoint with public_access_enabled = true exposes Kubernetes API to internet. Brute-force attacks on certificates, API discovery scanning, DDoS risk.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_eks_cluster') {
          const vpcConfig = getAttrValue(block.attributes, 'vpc_config');

          if (typeof vpcConfig === 'object' && vpcConfig !== null) {
            const config = vpcConfig as Record<string, unknown>;
            const endpointPublicAccess = getAttrValue(config, 'endpoint_public_access');
            const publicAccessCidrs = getAttrValue(config, 'public_access_cidrs');

            if (endpointPublicAccess === true) {
              // Check if CIDR blocks are restricted
              const hasWildcardCIDR = Array.isArray(publicAccessCidrs)
                ? publicAccessCidrs.includes('0.0.0.0/0')
                : publicAccessCidrs === '0.0.0.0/0' || isFalseOrMissing(publicAccessCidrs);

              if (hasWildcardCIDR) {
                findings.push({
                  id: `${parsedFile.fileName}-${block.name}-eks-public-endpoint`,
                  ruleId: this.id,
                  title: this.title,
                  description: `INTERNET EXPOSED: EKS cluster "${block.name}" allows public access from 0.0.0.0/0. Kubernetes API server accessible to anyone - can attempt authentication, enumerate services, exploit CVEs.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `aws_eks_cluster.${block.name}`,
                  lineNumber: block.startLine,
                  remediation: 'Set endpoint_public_access = false and endpoint_private_access = true for VPC-only access. Or restrict public_access_cidrs = ["YOUR-OFFICE-IP/32"] to specific IPs only.',
                });
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // EKS Cluster Logging
  {
    id: 'TF_AWS_EKS_008',
    title: 'EKS cluster control plane logging enabled',
    description: 'NO AUDIT LOGS: EKS without control plane logs means no visibility into API calls, authentication attempts, or scheduler decisions. Cannot detect unauthorized kubectl access or pod privilege escalation.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      const requiredLogTypes = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'];

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_eks_cluster') {
          const enabledClusterLogTypes = getAttrValue(block.attributes, 'enabled_cluster_log_types');

          if (isFalseOrMissing(enabledClusterLogTypes)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-eks-no-logging`,
              ruleId: this.id,
              title: this.title,
              description: `KUBERNETES BLIND: EKS cluster "${block.name}" has NO control plane logging. Cannot audit kubectl commands, see failed auth attempts, or investigate pod security incidents. Compliance violation.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_eks_cluster.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"] to CloudWatch log all Kubernetes control plane activities.',
            });
          } else if (Array.isArray(enabledClusterLogTypes)) {
            const missingLogTypes = requiredLogTypes.filter(logType => !enabledClusterLogTypes.includes(logType));
            if (missingLogTypes.length > 0) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-eks-incomplete-logging`,
                ruleId: this.id,
                title: this.title,
                description: `PARTIAL LOGGING: EKS cluster "${block.name}" missing critical log types: ${missingLogTypes.join(', ')}. Incomplete audit trail - cannot fully investigate security incidents.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_eks_cluster.${block.name}`,
                lineNumber: block.startLine,
                remediation: `Add missing log types to enabled_cluster_log_types: ${JSON.stringify(requiredLogTypes)}. Enable ALL for complete visibility.`,
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // EKS Secrets Encryption
  {
    id: 'TF_AWS_EKS_009',
    title: 'EKS cluster encrypts Kubernetes secrets',
    description: 'PLAINTEXT SECRETS: EKS without encryption stores Kubernetes Secrets in etcd as base64 (not encrypted). Anyone with etcd access can decode all passwords, tokens, API keys.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_eks_cluster') {
          const encryptionConfig = getAttrValue(block.attributes, 'encryption_config');

          if (isFalseOrMissing(encryptionConfig)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-eks-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `SECRETS EXPOSED: EKS cluster "${block.name}" does NOT encrypt Kubernetes Secrets at rest. All Secret objects stored in etcd as base64 - trivially decoded to plaintext. Database passwords fully exposed.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_eks_cluster.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add encryption_config { provider { key_arn = aws_kms_key.eks.arn }; resources = ["secrets"] } to encrypt all Kubernetes Secrets with KMS.',
            });
          } else if (typeof encryptionConfig === 'object' && encryptionConfig !== null) {
            const config = Array.isArray(encryptionConfig) ? encryptionConfig[0] : encryptionConfig;
            if (typeof config === 'object' && config !== null) {
              const resources = getAttrValue(config as Record<string, unknown>, 'resources');
              if (!Array.isArray(resources) || !resources.includes('secrets')) {
                findings.push({
                  id: `${parsedFile.fileName}-${block.name}-eks-secrets-not-encrypted`,
                  ruleId: this.id,
                  title: this.title,
                  description: `INCOMPLETE ENCRYPTION: EKS cluster "${block.name}" has encryption_config but does NOT include "secrets" in resources. Kubernetes Secrets still stored as base64.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `aws_eks_cluster.${block.name}`,
                  lineNumber: block.startLine,
                  remediation: 'Add "secrets" to resources array in encryption_config: resources = ["secrets"]',
                });
              }
            }
          }
        }
      }
      return findings;
    },
  },

  // EKS Node Group IMDSv2
  {
    id: 'TF_AWS_EKS_010',
    title: 'EKS node group uses IMDSv2',
    description: 'SSRF RISK: Node instances with IMDSv1 allow SSRF attacks to steal IAM credentials. Container breakout + SSRF = full node IAM role access.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_eks_node_group') {
          const launchTemplate = getAttrValue(block.attributes, 'launch_template');

          // EKS node groups should use launch template with IMDSv2
          if (isFalseOrMissing(launchTemplate)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-eks-no-imdsv2`,
              ruleId: this.id,
              title: this.title,
              description: `IMDSv1 VULNERABLE: EKS node group "${block.name}" missing launch_template - uses default IMDSv1. Container SSRF attacks can steal node IAM role credentials via http://169.254.169.254.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_eks_node_group.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Create launch_template with metadata_options { http_tokens = "required"; http_put_response_hop_limit = 1 } to enforce IMDSv2 and block SSRF credential theft.',
            });
          }
        }
      }
      return findings;
    },
  },

  // EKS Public Subnet Node Groups
  {
    id: 'TF_AWS_EKS_011',
    title: 'EKS node groups use private subnets',
    description: 'PUBLIC NODES: Worker nodes in public subnets get public IPs - directly accessible from internet. SSH brute-force, kubelet port scanning, container escape to internet.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_eks_node_group') {
          const remoteAccess = getAttrValue(block.attributes, 'remote_access');

          // Check if remote_access is configured - indicates potential public access
          if (typeof remoteAccess === 'object' && remoteAccess !== null) {
            const config = remoteAccess as Record<string, unknown>;
            const sourceSecurityGroupIds = getAttrValue(config, 'source_security_group_ids');

            if (isFalseOrMissing(sourceSecurityGroupIds)) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-eks-node-public-ssh`,
                ruleId: this.id,
                title: this.title,
                description: `OPEN SSH: EKS node group "${block.name}" has remote_access without source_security_group_ids restriction. SSH accessible from anywhere. Brute-force attack surface.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_eks_node_group.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Add source_security_group_ids to remote_access block OR remove remote_access entirely and use Systems Manager Session Manager for secure node access.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // EKS Cluster Security Group Rules
  {
    id: 'TF_AWS_EKS_012',
    title: 'EKS cluster security groups follow least privilege',
    description: 'OPEN FIREWALL: Security group with 0.0.0.0/0 ingress allows unrestricted traffic to cluster. Port scanning, exploitation of exposed services.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_security_group_rule') {
          const type = getAttrValue(block.attributes, 'type');
          const cidrBlocks = getAttrValue(block.attributes, 'cidr_blocks');
          const description = String(getAttrValue(block.attributes, 'description') || '');

          // Check if this is EKS-related security group
          if (description.toLowerCase().includes('eks') || description.toLowerCase().includes('kubernetes')) {
            if (type === 'ingress' && Array.isArray(cidrBlocks) && cidrBlocks.includes('0.0.0.0/0')) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-eks-sg-open`,
                ruleId: this.id,
                title: this.title,
                description: `UNRESTRICTED INGRESS: EKS security group rule "${block.name}" allows inbound from 0.0.0.0/0. Kubernetes services/nodes exposed to internet scanning and attacks.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_security_group_rule.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Replace 0.0.0.0/0 with specific CIDR blocks for your VPC, office, or bastion hosts. Use VPC endpoints for AWS service access instead of internet routes.',
              });
            }
          }
        }
      }
      return findings;
    },
  },
];
