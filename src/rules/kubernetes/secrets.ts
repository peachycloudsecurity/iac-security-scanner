import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sContainer {
  name?: string;
  env?: Array<{
    valueFrom?: {
      secretKeyRef?: unknown;
    };
  }>;
  envFrom?: Array<{
    secretRef?: unknown;
  }>;
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

export const kubernetesSecretsRule: Rule = {
  id: 'K8S_SEC_005',
  title: 'Secrets mounted as files not env vars',
  description: 'Secrets should be mounted as files rather than environment variables to reduce exposure risk.',
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
        
        // Check env with secretKeyRef
        if (Array.isArray(container.env)) {
          for (const envVar of container.env) {
            if (envVar.valueFrom?.secretKeyRef) {
              findings.push({
                id: `${parsedFile.fileName}-${resourceName}-${containerName}-secret-env`,
                ruleId: this.id,
                title: this.title,
                description: `Container "${containerName}" in ${doc.kind} "${resourceName}" uses secrets as environment variables via secretKeyRef.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
                remediation: 'Mount secrets as files using volumeMounts and volumes instead of environment variables.',
              });
              break;
            }
          }
        }
        
        // Check envFrom with secretRef
        if (Array.isArray(container.envFrom)) {
          for (const envFrom of container.envFrom) {
            if (envFrom.secretRef) {
              findings.push({
                id: `${parsedFile.fileName}-${resourceName}-${containerName}-secret-envfrom`,
                ruleId: this.id,
                title: this.title,
                description: `Container "${containerName}" in ${doc.kind} "${resourceName}" uses secrets as environment variables via envFrom.secretRef.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                resourcePath: `${doc.kind}/${resourceName}/container/${containerName}`,
                remediation: 'Mount secrets as files using volumeMounts and volumes instead of envFrom.',
              });
              break;
            }
          }
        }
      }
    }
    
    return findings;
  },
};
