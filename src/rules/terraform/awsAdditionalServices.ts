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

export const terraformAdditionalServicesRules: Rule[] = [
  // API Gateway Authorization
  {
    id: 'TF_AWS_APIGW_001',
    title: 'API Gateway method requires authorization',
    description: 'UNAUTHENTICATED API: API Gateway methods without auth allow anonymous access. Attackers can invoke endpoints, cause DoS, extract data.',
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
          const httpMethod = getAttrValue(block.attributes, 'http_method');
          
          // Skip OPTIONS (CORS preflight)
          if (httpMethod === 'OPTIONS') continue;
          
          if (authorization === 'NONE' && apiKeyRequired !== true) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-auth`,
              ruleId: this.id,
              title: this.title,
              description: `ANONYMOUS ACCESS: API method "${block.name}" has authorization="NONE" without API key. Anyone can invoke endpoint without credentials, causing DoS or data access.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_api_gateway_method.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set authorization = "AWS_IAM" or "COGNITO_USER_POOLS" or api_key_required = true. Add throttling and WAF for public APIs.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ElastiCache Encryption
  {
    id: 'TF_AWS_ELASTICACHE_001',
    title: 'ElastiCache encryption in transit enabled',
    description: 'PLAINTEXT CACHE: Redis/Memcached traffic unencrypted. Cache keys, session data, application state transmitted in plaintext.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_elasticache_replication_group') {
          const transitEncryption = getAttrValue(block.attributes, 'transit_encryption_enabled');
          const atRestEncryption = getAttrValue(block.attributes, 'at_rest_encryption_enabled');
          
          if (isFalseOrMissing(transitEncryption)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-transit-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `UNENCRYPTED CACHE: ElastiCache "${block.name}" transmits data in plaintext. Session tokens, user data, application cache readable via network sniffing.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_elasticache_replication_group.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set transit_encryption_enabled = true and auth_token for Redis authentication. Update applications to use TLS connections.',
            });
          }
          
          if (isFalseOrMissing(atRestEncryption)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-rest-encryption`,
              ruleId: 'TF_AWS_ELASTICACHE_002',
              title: 'ElastiCache encryption at rest enabled',
              description: `PLAINTEXT STORAGE: ElastiCache "${block.name}" stores data unencrypted. Cache contents, session data readable from backups and underlying storage.`,
              severity: 'HIGH',
              fileName: parsedFile.fileName,
              resourcePath: `aws_elasticache_replication_group.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set at_rest_encryption_enabled = true. Use kms_key_id for customer managed key control.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Load Balancer HTTPS
  {
    id: 'TF_AWS_ELB_001',
    title: 'ALB listener uses HTTPS protocol',
    description: 'UNENCRYPTED WEB TRAFFIC: Load balancer accepts HTTP connections. User credentials, session tokens, personal data transmitted in plaintext.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_lb_listener') {
          const protocol = getAttrValue(block.attributes, 'protocol');
          
          if (protocol === 'HTTP') {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-http-listener`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT WEB: Listener "${block.name}" accepts HTTP traffic. Login credentials, authentication cookies, user data transmitted without encryption.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_lb_listener.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Change protocol = "HTTPS" and add certificate_arn = aws_acm_certificate.example.arn. Redirect HTTP to HTTPS: action { type = "redirect", redirect { protocol = "HTTPS" } }',
            });
          }
        }
      }
      return findings;
    },
  },

  // AutoScaling Launch Template Encryption
  {
    id: 'TF_AWS_ASG_001',
    title: 'AutoScaling launch template enables EBS encryption',
    description: 'UNENCRYPTED FLEET: AutoScaling instances launch with unencrypted EBS volumes. All scaled instances store data in plaintext.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_launch_template') {
          const blockDeviceMappings = getAttrValue(block.attributes, 'block_device_mappings');
          
          if (Array.isArray(blockDeviceMappings)) {
            for (const device of blockDeviceMappings) {
              if (typeof device === 'object' && device !== null) {
                const deviceObj = device as Record<string, unknown>;
                const ebs = getAttrValue(deviceObj, 'ebs');
                
                if (typeof ebs === 'object' && ebs !== null) {
                  const ebsObj = ebs as Record<string, unknown>;
                  const encrypted = getAttrValue(ebsObj, 'encrypted');
                  
                  if (isFalseOrMissing(encrypted)) {
                    findings.push({
                      id: `${parsedFile.fileName}-${block.name}-unencrypted-ebs`,
                      ruleId: this.id,
                      title: this.title,
                      description: `UNENCRYPTED SCALING: Launch template "${block.name}" creates unencrypted EBS volumes. All AutoScaling instances store data in plaintext.`,
                      severity: this.severity,
                      fileName: parsedFile.fileName,
                      resourcePath: `aws_launch_template.${block.name}`,
                      lineNumber: block.startLine,
                      remediation: 'Set block_device_mappings: ebs { encrypted = true } to encrypt all volumes. Use kms_key_id for customer managed keys.',
                    });
                    break; // Only report once per template
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

  // EMR Cluster Encryption
  {
    id: 'TF_AWS_EMR_001',
    title: 'EMR cluster enables encryption at rest',
    description: 'UNENCRYPTED BIG DATA: EMR cluster data stored in plaintext. HDFS files, application logs, intermediate data readable from storage.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_emr_cluster') {
          // Check for security_configuration
          const securityConfiguration = getAttrValue(block.attributes, 'security_configuration');
          
          if (!securityConfiguration) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT BIG DATA: EMR cluster "${block.name}" has no security configuration. HDFS data, logs, and intermediate processing files stored unencrypted.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_emr_cluster.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add security_configuration = aws_emr_security_configuration.example.name with encryption settings for at-rest and in-transit encryption.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Kinesis Firehose Encryption
  {
    id: 'TF_AWS_FIREHOSE_001',
    title: 'Kinesis Firehose delivery stream encryption enabled',
    description: 'UNENCRYPTED STREAMING: Firehose data stored in plaintext during delivery. Stream contents, logs, analytics data readable from S3 destinations.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_kinesis_firehose_delivery_stream') {
          // Check S3 destination encryption
          const s3Configuration = getAttrValue(block.attributes, 's3_configuration');
          
          if (typeof s3Configuration === 'object' && s3Configuration !== null) {
            const s3Obj = s3Configuration as Record<string, unknown>;
            const encryption = getAttrValue(s3Obj, 'encryption_configuration');
            
            if (!encryption) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-s3-no-encryption`,
                ruleId: this.id,
                title: this.title,
                description: `PLAINTEXT DELIVERY: Firehose "${block.name}" delivers data to S3 without encryption. Stream contents stored in plaintext, readable from S3 objects.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `aws_kinesis_firehose_delivery_stream.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Add s3_configuration: encryption_configuration { kms_key_arn = aws_kms_key.firehose.arn } to encrypt delivered data.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // Config Recorder
  {
    id: 'TF_AWS_CONFIG_001',
    title: 'Config recorder includes all regions',
    description: 'CONFIGURATION BLIND SPOTS: Config recorder missing regions allows unmonitored resource changes. Attackers can operate in untracked regions.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_config_configuration_recorder') {
          const recordingGroup = getAttrValue(block.attributes, 'recording_group');
          
          let includeGlobalResourceTypes = false;
          let allSupported = false;
          
          if (typeof recordingGroup === 'object' && recordingGroup !== null) {
            const groupObj = recordingGroup as Record<string, unknown>;
            includeGlobalResourceTypes = getAttrValue(groupObj, 'include_global_resource_types') === true;
            allSupported = getAttrValue(groupObj, 'all_supported') === true;
          }
          
          if (!includeGlobalResourceTypes || !allSupported) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-incomplete-recording`,
              ruleId: this.id,
              title: this.title,
              description: `MONITORING GAPS: Config recorder "${block.name}" doesn't track all resources/regions. Attackers can modify unmonitored resources without detection.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_config_configuration_recorder.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set recording_group: { all_supported = true, include_global_resource_types = true } to monitor all resources across regions.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Neptune Cluster Encryption
  {
    id: 'TF_AWS_NEPTUNE_001',
    title: 'Neptune cluster encryption enabled',
    description: 'UNENCRYPTED GRAPH DATABASE: Neptune data stored in plaintext. Graph relationships, node properties, and queries readable from storage.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_neptune_cluster') {
          const storageEncrypted = getAttrValue(block.attributes, 'storage_encrypted');
          
          if (isFalseOrMissing(storageEncrypted)) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-no-encryption`,
              ruleId: this.id,
              title: this.title,
              description: `PLAINTEXT GRAPH DATA: Neptune cluster "${block.name}" stores graph database unencrypted. Node relationships, properties, and query patterns readable from storage.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_neptune_cluster.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set storage_encrypted = true. Use kms_key_arn = aws_kms_key.neptune.arn for customer managed encryption key.',
            });
          }
        }
      }
      return findings;
    },
  },

  // DMS Replication Instance Public
  {
    id: 'TF_AWS_DMS_001',
    title: 'DMS replication instance not publicly accessible',
    description: 'PUBLIC MIGRATION TOOL: DMS instance accessible from internet. Database migration traffic and connection strings exposed.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_dms_replication_instance') {
          const publiclyAccessible = getAttrValue(block.attributes, 'publicly_accessible');
          
          if (publiclyAccessible === true) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-public-access`,
              ruleId: this.id,
              title: this.title,
              description: `EXPOSED MIGRATION: DMS instance "${block.name}" accessible from internet. Database migration endpoints, connection strings, and replication data exposed to attacks.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_dms_replication_instance.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Set publicly_accessible = false. Access via VPC, VPN, or Direct Connect for secure database migration.',
            });
          }
        }
      }
      return findings;
    },
  },

  // ECS Task Definition Root User
  {
    id: 'TF_AWS_ECS_002',
    title: 'ECS task definition containers run as non-root',
    description: 'ROOT CONTAINER: ECS containers run as UID 0 with full privileges. Can escape container, access other tasks, compromise host.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_ecs_task_definition') {
          const containerDefinitions = getAttrValue(block.attributes, 'container_definitions');
          
          if (typeof containerDefinitions === 'string') {
            try {
              const containers = JSON.parse(containerDefinitions);
              if (Array.isArray(containers)) {
                for (const container of containers) {
                  if (typeof container === 'object' && container !== null) {
                    const containerObj = container as Record<string, unknown>;
                    const user = containerObj.user;
                    
                    // Check if user is root or not specified (defaults to root)
                    if (!user || user === 'root' || user === '0') {
                      findings.push({
                        id: `${parsedFile.fileName}-${block.name}-root-container`,
                        ruleId: this.id,
                        title: this.title,
                        description: `ROOT EXECUTION: Task "${block.name}" container "${containerObj.name}" runs as root. Has full system privileges, can escape container boundaries.`,
                        severity: this.severity,
                        fileName: parsedFile.fileName,
                        resourcePath: `aws_ecs_task_definition.${block.name}`,
                        lineNumber: block.startLine,
                        remediation: 'Set "user": "1001" in container definition. Ensure Dockerfile creates non-root user: RUN adduser -u 1001 appuser',
                      });
                      break; // Only report once per task definition
                    }
                  }
                }
              }
            } catch {
              // Invalid JSON, skip
            }
          }
        }
      }
      return findings;
    },
  },

  // IoT Policy Wildcard
  {
    id: 'TF_AWS_IOT_001',
    title: 'IoT policy avoids wildcard resources',
    description: 'IOT DEVICE TAKEOVER: IoT policy with Resource="*" allows device to access all IoT resources. Can control other devices, read all telemetry.',
    severity: 'HIGH',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_iot_policy') {
          const policy = getAttrValue(block.attributes, 'policy');
          
          if (typeof policy === 'string') {
            try {
              const policyDoc = JSON.parse(policy);
              if (policyDoc.Statement && Array.isArray(policyDoc.Statement)) {
                for (const statement of policyDoc.Statement) {
                  if (typeof statement === 'object' && statement !== null) {
                    const stmtObj = statement as Record<string, unknown>;
                    const resources = stmtObj.Resource;
                    const effect = stmtObj.Effect;
                    
                    if (effect === 'Allow' && 
                        (resources === '*' || 
                         (Array.isArray(resources) && resources.includes('*')))) {
                      findings.push({
                        id: `${parsedFile.fileName}-${block.name}-wildcard-resource`,
                        ruleId: this.id,
                        title: this.title,
                        description: `IOT DEVICE CONTROL: Policy "${block.name}" allows Resource="*" giving device access to ALL IoT resources. Can control other devices, read all telemetry data.`,
                        severity: this.severity,
                        fileName: parsedFile.fileName,
                        resourcePath: `aws_iot_policy.${block.name}`,
                        lineNumber: block.startLine,
                        remediation: 'Replace Resource="*" with specific thing ARNs: "arn:aws:iot:region:account:thing/device-*" to limit device access scope.',
                      });
                      break;
                    }
                  }
                }
              }
            } catch {
              // Invalid JSON policy
            }
          }
        }
      }
      return findings;
    },
  },

  // Directory Service Password
  {
    id: 'TF_AWS_DS_001',
    title: 'Directory Service uses secure password',
    description: 'WEAK DIRECTORY CREDENTIALS: Directory Service with weak passwords vulnerable to brute-force. Controls domain authentication.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && 
            (block.resourceType === 'aws_directory_service_directory' ||
             block.resourceType === 'aws_directory_service_simple_ad')) {
          const password = getAttrValue(block.attributes, 'password');
          
          if (typeof password === 'string') {
            // Check for hardcoded password patterns
            if (password.length < 12 || 
                !(/[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password))) {
              findings.push({
                id: `${parsedFile.fileName}-${block.name}-weak-password`,
                ruleId: this.id,
                title: this.title,
                description: `WEAK DOMAIN PASSWORD: Directory "${block.name}" has weak hardcoded password. Controls domain authentication - vulnerable to brute-force attacks.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `${block.resourceType}.${block.name}`,
                lineNumber: block.startLine,
                remediation: 'Use random_password resource: password = random_password.ds_password.result with length >= 12, special characters. Store in Secrets Manager.',
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // CloudWatch Log Group Encryption
  {
    id: 'TF_AWS_CW_001',
    title: 'CloudWatch log group uses customer managed KMS key',
    description: 'DEFAULT LOG ENCRYPTION: CloudWatch logs encrypted with AWS managed key. AWS can decrypt application logs, sensitive data.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_cloudwatch_log_group') {
          const kmsKeyId = getAttrValue(block.attributes, 'kms_key_id');
          
          if (!kmsKeyId) {
            findings.push({
              id: `${parsedFile.fileName}-${block.name}-default-kms`,
              ruleId: this.id,
              title: this.title,
              description: `AWS MANAGED ENCRYPTION: Log group "${block.name}" uses default AWS key. AWS can decrypt application logs, error messages, sensitive data.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `aws_cloudwatch_log_group.${block.name}`,
              lineNumber: block.startLine,
              remediation: 'Add kms_key_id = aws_kms_key.cloudwatch.arn to use customer managed key for log encryption.',
            });
          }
        }
      }
      return findings;
    },
  },

  // VPC Flow Logs
  {
    id: 'TF_AWS_VPC_002',
    title: 'VPC enables flow logs for network monitoring',
    description: 'NO NETWORK AUDIT: VPC without flow logs provides no visibility into network traffic. Cannot detect lateral movement, data exfiltration.',
    severity: 'MEDIUM',
    applicableFileTypes: ['terraform'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as TerraformParsed;
      if (!parsed?.blocks) return findings;

      const vpcs = new Set<string>();
      const vpcFlowLogs = new Set<string>();

      // Collect VPCs and flow logs
      for (const block of parsed.blocks) {
        if (block.type === 'resource' && block.resourceType === 'aws_vpc') {
          vpcs.add(block.name);
        }
        if (block.type === 'resource' && block.resourceType === 'aws_flow_log') {
          const vpcId = getAttrValue(block.attributes, 'vpc_id');
          if (typeof vpcId === 'string') {
            // Extract VPC name from reference
            const vpcName = vpcId.includes('.') ? vpcId.split('.')[1] : vpcId;
            vpcFlowLogs.add(vpcName);
          }
        }
      }

      // Check for VPCs without flow logs
      for (const vpcName of vpcs) {
        if (!vpcFlowLogs.has(vpcName)) {
          findings.push({
            id: `${parsedFile.fileName}-${vpcName}-no-flow-logs`,
            ruleId: this.id,
            title: this.title,
            description: `NETWORK BLIND SPOT: VPC "${vpcName}" has no flow logs. Cannot detect network attacks, lateral movement, or data exfiltration attempts.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `aws_vpc.${vpcName}`,
            lineNumber: 1,
            remediation: 'Add aws_flow_log with vpc_id = aws_vpc.${vpcName}.id, log_destination_type = "cloud-watch-logs" for network monitoring.',
          });
        }
      }
      return findings;
    },
  },
];