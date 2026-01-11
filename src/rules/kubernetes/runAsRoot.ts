import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sContainer {
  name?: string;
  securityContext?: {
    runAsNonRoot?: boolean;
    runAsUser?: number;
  };
}

interface K8sPodSpec {
  containers?: K8sContainer[];
  initContainers?: K8sContainer[];
  securityContext?: {
    runAsNonRoot?: boolean;
    runAsUser?: number;
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

export const kubernetesRunAsRootRule: Rule = {
  id: 'K8S_SEC_004',
  title: 'Containers run as non-root user',
  description: 'Running containers as root increases the attack surface and risk of privilege escalation.',
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
      
      // Get pod spec based on kind
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
      
      const podSecurityContext = podSpec.securityContext;
      const podRunAsNonRoot = podSecurityContext?.runAsNonRoot;
      const podRunAsUser = podSecurityContext?.runAsUser;
      
      for (const container of allContainers) {
        const containerName = container.name || 'unnamed';
        const containerSC = container.securityContext;
        
        // Check if runAsNonRoot is explicitly set to true at container or pod level
        const runAsNonRoot = containerSC?.runAsNonRoot ?? podRunAsNonRoot;
        const runAsUser = containerSC?.runAsUser ?? podRunAsUser;
        
        // Container may run as root if:
        // 1. runAsNonRoot is not set or is false
        // 2. AND runAsUser is not set or is 0
        const mayRunAsRoot = !runAsNonRoot && (runAsUser === undefined || runAsUser === 0);
        
        if (mayRunAsRoot) {
          findings.push({
            id: `${parsedFile.fileName}-${resourceName}-${containerName}-root`,
            ruleId: this.id,
            title: this.title,
            description: `Container "${containerName}" in ${doc.kind} "${resourceName}" may run as root user.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
            remediation: 'Set securityContext.runAsNonRoot: true or securityContext.runAsUser to a non-zero value.',
          });
        }
      }
    }
    
    return findings;
  },
};
