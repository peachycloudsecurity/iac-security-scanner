import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sContainer {
  name?: string;
  resources?: {
    limits?: {
      cpu?: string;
      memory?: string;
    };
    requests?: {
      cpu?: string;
      memory?: string;
    };
  };
}

interface K8sPodSpec {
  containers?: K8sContainer[];
  initContainers?: K8sContainer[];
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

export const kubernetesResourceLimitsRules: Rule[] = [
  // CPU Limits
  {
    id: 'K8S_RES_001',
    title: 'Containers define CPU limits',
    description: 'RESOURCE EXHAUSTION: Container without CPU limits can consume all node CPU, causing DoS, affecting other pods, or enabling resource-based attacks.',
    severity: 'HIGH',
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
        
        for (const container of allContainers) {
          const containerName = container.name || 'unnamed';
          const cpuLimit = container.resources?.limits?.cpu;
          
          if (!cpuLimit) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-no-cpu-limit`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" does not define CPU limits.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: 'Add resources.limits.cpu (e.g., "500m" or "1") to prevent resource exhaustion.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Memory Limits
  {
    id: 'K8S_RES_002',
    title: 'Containers define memory limits',
    description: 'MEMORY EXHAUSTION: Container without memory limits can consume all node memory, causing OOM kills, pod evictions, or host instability.',
    severity: 'HIGH',
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
        
        for (const container of allContainers) {
          const containerName = container.name || 'unnamed';
          const memoryLimit = container.resources?.limits?.memory;
          
          if (!memoryLimit) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-no-memory-limit`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" does not define memory limits.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: 'Add resources.limits.memory (e.g., "512Mi" or "1Gi") to prevent memory exhaustion.',
            });
          }
        }
      }
      return findings;
    },
  },
];
