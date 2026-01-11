import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sContainer {
  name?: string;
  securityContext?: {
    capabilities?: {
      add?: string[];
      drop?: string[];
    };
  };
}

interface K8sPodSpec {
  containers?: K8sContainer[];
  initContainers?: K8sContainer[];
  securityContext?: {
    capabilities?: {
      add?: string[];
      drop?: string[];
    };
  };
}

interface K8sDocument {
  apiVersion?: string;
  kind?: string;
  metadata?: {
    name?: string;
    namespace?: string;
  };
  spec?: {
    template?: {
      spec?: K8sPodSpec;
    };
    containers?: K8sContainer[];
  };
}

export const kubernetesCapabilitiesRules: Rule[] = [
  // Dangerous Capabilities
  {
    id: 'K8S_CAP_001',
    title: 'Containers avoid dangerous capabilities',
    description: 'CAPABILITY ESCALATION: Container has dangerous capabilities like SYS_ADMIN, NET_ADMIN, or ALL. Can modify host network, mount filesystems, or bypass security controls.',
    severity: 'HIGH',
    applicableFileTypes: ['kubernetes'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const documents = parsedFile.parsed as K8sDocument[];
      
      if (!Array.isArray(documents)) return findings;
      
      const dangerousCaps = ['SYS_ADMIN', 'NET_ADMIN', 'NET_RAW', 'ALL', 'SYS_MODULE', 'SYS_TIME', 'SYS_PTRACE'];
      
      for (const doc of documents) {
        if (!doc || !doc.kind) continue;
        
        const workloadKinds = ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet'];
        if (!workloadKinds.includes(doc.kind)) continue;
        
        const resourceName = doc.metadata?.name || 'unnamed';
        
        let podSpec: K8sPodSpec | undefined;
        if (doc.kind === 'Pod') {
          podSpec = doc.spec as unknown as K8sPodSpec;
        } else if (doc.spec?.template?.spec) {
          podSpec = doc.spec.template.spec;
        }
        
        if (!podSpec) continue;
        
        const allContainers = [
          ...(podSpec.containers || []),
          ...(podSpec.initContainers || []),
        ];
        
        const podCaps = podSpec.securityContext?.capabilities?.add || [];
        
        for (const container of allContainers) {
          const containerName = container.name || 'unnamed';
          const containerCaps = container.securityContext?.capabilities?.add || [];
          const allCaps = [...new Set([...podCaps, ...containerCaps])];
          
          const foundDangerous = allCaps.filter(cap => 
            dangerousCaps.includes(cap.toUpperCase())
          );
          
          if (foundDangerous.length > 0) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-dangerous-caps`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" has dangerous capabilities: ${foundDangerous.join(', ')}.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: `Remove dangerous capabilities from securityContext.capabilities.add. Use only specific, necessary capabilities. Drop ALL: securityContext.capabilities.drop: ["ALL"].`,
            });
          }
        }
      }
      return findings;
    },
  },

  // Drop ALL Capabilities
  {
    id: 'K8S_CAP_002',
    title: 'Containers drop ALL capabilities',
    description: 'EXCESSIVE CAPABILITIES: Container does not drop ALL capabilities. Default capabilities grant unnecessary privileges that can be exploited.',
    severity: 'MEDIUM',
    applicableFileTypes: ['kubernetes'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const documents = parsedFile.parsed as K8sDocument[];
      
      if (!Array.isArray(documents)) return findings;
      
      for (const doc of documents) {
        if (!doc || !doc.kind) continue;
        
        const workloadKinds = ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet'];
        if (!workloadKinds.includes(doc.kind)) continue;
        
        const resourceName = doc.metadata?.name || 'unnamed';
        
        let podSpec: K8sPodSpec | undefined;
        if (doc.kind === 'Pod') {
          podSpec = doc.spec as unknown as K8sPodSpec;
        } else if (doc.spec?.template?.spec) {
          podSpec = doc.spec.template.spec;
        }
        
        if (!podSpec) continue;
        
        const allContainers = [
          ...(podSpec.containers || []),
          ...(podSpec.initContainers || []),
        ];
        
        const podDropCaps = podSpec.securityContext?.capabilities?.drop || [];
        
        for (const container of allContainers) {
          const containerName = container.name || 'unnamed';
          const containerDropCaps = container.securityContext?.capabilities?.drop || [];
          const allDropCaps = [...new Set([...podDropCaps, ...containerDropCaps])];
          
          if (!allDropCaps.includes('ALL')) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-no-drop-all`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" does not drop ALL capabilities.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: 'Add securityContext.capabilities.drop: ["ALL"] to drop all default capabilities, then add only specific ones needed.',
            });
          }
        }
      }
      return findings;
    },
  },
];
