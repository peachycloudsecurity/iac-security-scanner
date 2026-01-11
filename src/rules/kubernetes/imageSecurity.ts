import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sContainer {
  name?: string;
  image?: string;
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

export const kubernetesImageSecurityRules: Rule[] = [
  // Image Tag
  {
    id: 'K8S_IMG_001',
    title: 'Container images use specific tags',
    description: 'Using the latest tag makes it difficult to track which version is running and can lead to unexpected updates.',
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
          const image = container.image || '';
          
          // Check if image uses latest tag or no tag
          if (image && (image.endsWith(':latest') || (!image.includes(':') && !image.includes('@sha256:')))) {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-latest-tag`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" uses latest tag or no tag.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: 'Use a specific image tag or digest (e.g., image:tag or image@sha256:hash).',
            });
          }
        }
      }
      return findings;
    },
  },

  // Image Pull Policy
  {
    id: 'K8S_IMG_002',
    title: 'Container images use Always pull policy',
    description: 'Using Always for imagePullPolicy ensures the latest image is always pulled, improving security.',
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
          const imagePullPolicy = (container as Record<string, unknown>).imagePullPolicy;
          
          if (imagePullPolicy !== 'Always') {
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${containerName}-pull-policy`,
              ruleId: this.id,
              title: this.title,
              description: `Container "${containerName}" in ${doc.kind} "${resourceName}" does not use imagePullPolicy Always.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
              remediation: 'Set imagePullPolicy to Always.',
            });
          }
        }
      }
      return findings;
    },
  },
];
