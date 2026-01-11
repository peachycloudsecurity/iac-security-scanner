import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sPodSpec {
  hostNetwork?: boolean;
  hostPID?: boolean;
  hostIPC?: boolean;
  containers?: Array<{
    name?: string;
  }>;
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
    hostNetwork?: boolean;
    hostPID?: boolean;
    hostIPC?: boolean;
    containers?: Array<{
      name?: string;
    }>;
  };
}

export const kubernetesNetworkSecurityRules: Rule[] = [
  // Host Network
  {
    id: 'K8S_NET_001',
    title: 'Pods avoid host network mode',
    description: 'NETWORK BYPASS: Pod uses hostNetwork, bypassing Kubernetes network isolation. Can access host network interfaces, services, and potentially other pods.',
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
        
        if (podSpec.hostNetwork === true) {
          findings.push({
            id: `${parsedFile.fileName}-${resourceName}-host-network`,
            ruleId: this.id,
            title: this.title,
            description: `${doc.kind} "${resourceName}" uses hostNetwork mode.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `${doc.kind}/${resourceName}`,
            remediation: 'Remove hostNetwork: true. Use Kubernetes Service networking for inter-pod communication.',
          });
        }
      }
      return findings;
    },
  },

  // Host PID
  {
    id: 'K8S_NET_002',
    title: 'Pods avoid host PID mode',
    description: 'PROCESS EXPOSURE: Pod uses hostPID, allowing access to host process namespace. Can inspect, kill, or manipulate host processes, leading to privilege escalation.',
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
        
        if (podSpec.hostPID === true) {
          findings.push({
            id: `${parsedFile.fileName}-${resourceName}-host-pid`,
            ruleId: this.id,
            title: this.title,
            description: `${doc.kind} "${resourceName}" uses hostPID mode.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `${doc.kind}/${resourceName}`,
            remediation: 'Remove hostPID: true. Use default PID namespace for process isolation.',
          });
        }
      }
      return findings;
    },
  },

  // Host IPC
  {
    id: 'K8S_NET_003',
    title: 'Pods avoid host IPC mode',
    description: 'SHARED MEMORY EXPOSURE: Pod uses hostIPC, sharing inter-process communication with host. Can access host shared memory segments and potentially other processes.',
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
        
        if (podSpec.hostIPC === true) {
          findings.push({
            id: `${parsedFile.fileName}-${resourceName}-host-ipc`,
            ruleId: this.id,
            title: this.title,
            description: `${doc.kind} "${resourceName}" uses hostIPC mode.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `${doc.kind}/${resourceName}`,
            remediation: 'Remove hostIPC: true. Use default IPC namespace for isolation.',
          });
        }
      }
      return findings;
    },
  },

  // Default Namespace
  {
    id: 'K8S_NET_004',
    title: 'Resources avoid default namespace',
    description: 'NAMESPACE POLLUTION: Resource uses "default" namespace. Mixes workloads, complicates RBAC, and increases risk of accidental exposure.',
    severity: 'MEDIUM',
    applicableFileTypes: ['kubernetes'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const documents = parsedFile.parsed as K8sDocument[];
      
      if (!Array.isArray(documents)) return findings;
      
      for (const doc of documents) {
        if (!doc || !doc.kind) continue;
        
        const namespace = doc.metadata?.namespace || 'default';
        
        if (namespace === 'default') {
          const resourceName = doc.metadata?.name || 'unnamed';
          findings.push({
            id: `${parsedFile.fileName}-${resourceName}-default-namespace`,
            ruleId: this.id,
            title: this.title,
            description: `${doc.kind} "${resourceName}" uses the default namespace.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `${doc.kind}/${resourceName}`,
            remediation: 'Create and use a dedicated namespace (e.g., metadata.namespace: "production" or "staging").',
          });
        }
      }
      return findings;
    },
  },
];
