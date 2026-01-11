import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sContainer {
  name?: string;
  securityContext?: {
    runAsNonRoot?: boolean;
    runAsUser?: number;
    privileged?: boolean;
    allowPrivilegeEscalation?: boolean;
    readOnlyRootFilesystem?: boolean;
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
    runAsNonRoot?: boolean;
    runAsUser?: number;
    privileged?: boolean;
    allowPrivilegeEscalation?: boolean;
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
    securityContext?: K8sPodSpec['securityContext'];
  };
}

export const kubernetesSecurityContextRules: Rule[] = [
  // Privileged Containers
  {
    id: 'K8S_SEC_001',
    title: 'Containers without privileged mode',
    description: 'Privileged containers have full access to the host system, significantly increasing security risk.',
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
        
        const podPrivileged = podSpec.securityContext?.privileged;
        
        for (const container of allContainers) {
          const containerName = container.name || 'unnamed';
          const containerSC = container.securityContext;
          const privileged = containerSC?.privileged ?? podPrivileged;
          
          if (privileged === true) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-privileged`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" has privileged mode enabled.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: 'Set securityContext.privileged to false or remove it.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Allow Privilege Escalation
  {
    id: 'K8S_SEC_002',
    title: 'Containers block privilege escalation',
    description: 'Containers should not allow privilege escalation to prevent security risks.',
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
        
        const podAllowEscalation = podSpec.securityContext?.allowPrivilegeEscalation;
        
        for (const container of allContainers) {
          const containerName = container.name || 'unnamed';
          const containerSC = container.securityContext;
          const allowEscalation = containerSC?.allowPrivilegeEscalation ?? podAllowEscalation;
          
          // Default is true if not set, so we check for true or undefined
          if (allowEscalation !== false) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-privilege-escalation`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" allows privilege escalation.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: 'Set securityContext.allowPrivilegeEscalation to false.',
            });
          }
        }
      }
      return findings;
    },
  },

  // Read-Only Root Filesystem
  {
    id: 'K8S_SEC_003',
    title: 'Containers use read-only root filesystem',
    description: 'Containers should use read-only root filesystem to prevent unauthorized writes.',
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
        
        for (const container of allContainers) {
          const containerName = container.name || 'unnamed';
          const containerSC = container.securityContext;
          const readOnlyRootFS = containerSC?.readOnlyRootFilesystem;
          
          if (readOnlyRootFS !== true) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-readonly-fs`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" does not use read-only root filesystem.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: 'Set securityContext.readOnlyRootFilesystem to true and use emptyDir volumes for writable directories.',
            });
          }
        }
      }
      return findings;
    },
  },
];
