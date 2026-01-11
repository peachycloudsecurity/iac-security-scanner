import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sContainer {
  name?: string;
  env?: Array<{
    name?: string;
    value?: string;
    valueFrom?: {
      secretKeyRef?: unknown;
    };
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

function checkForSecrets(value: string): boolean {
  const secretPatterns = [
    /AKIA[0-9A-Z]{16}/, // AWS Access Key ID
    /ASIA[0-9A-Z]{16}/, // AWS Session Token
    /[Pp]assword[=:]\s*["']?[^"'\s]{8,}/,
    /[Ss]ecret[=:]\s*["']?[^"'\s]{10,}/,
    /[Aa][Pp][Ii][_-]?[Kk]ey[=:]\s*["']?[^"'\s]{10,}/,
    /[Tt]oken[=:]\s*["']?[^"'\s]{10,}/,
    /[Pp]rivate[_-]?[Kk]ey[=:]\s*["']?-----BEGIN/,
    /BEGIN\s+(RSA\s+)?PRIVATE\s+KEY/,
  ];
  return secretPatterns.some(pattern => pattern.test(value));
}

export const kubernetesSecretScanningRules: Rule[] = [
  // Hardcoded Secrets in Environment Variables
  {
    id: 'K8S_SECRET_001',
    title: 'Kubernetes manifests contain no hardcoded secrets',
    description: 'CREDENTIAL EXPOSURE: Hardcoded secrets in env vars are visible in kubectl describe, logs, and git history. Never expire or rotate.',
    severity: 'HIGH',
    applicableFileTypes: ['kubernetes'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const documents = parsedFile.parsed as K8sDocument[];
      
      if (!Array.isArray(documents)) return findings;
      
      for (const doc of documents) {
        if (!doc || !doc.kind) continue;
        
        const workloadKinds = ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'ReplicaSet', 'ConfigMap', 'Secret'];
        if (!workloadKinds.includes(doc.kind)) continue;
        
        const resourceName = doc.metadata?.name || 'unnamed';
        
        // Check ConfigMap data
        if (doc.kind === 'ConfigMap') {
          const data = (doc.spec as Record<string, unknown>)?.data || (doc as Record<string, unknown>).data;
          if (typeof data === 'object' && data !== null) {
            for (const [key, value] of Object.entries(data)) {
              if (typeof value === 'string' && checkForSecrets(value)) {
                findings.push({
                  id: `${parsedFile.fileName}-${resourceName}-configmap-${key}-secret`,
                  ruleId: this.id,
                  title: this.title,
                  description: `CREDENTIAL LEAK: ConfigMap "${resourceName}" contains hardcoded secret in key "${key}". ConfigMaps are not encrypted and visible in plaintext.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `${doc.kind}/${resourceName}/data/${key}`,
                  remediation: 'Move secret to Kubernetes Secret resource. Use: kubectl create secret generic my-secret --from-literal=key=value. Reference via secretKeyRef.',
                });
              }
            }
          }
        }
        
        // Check Secret data (base64 encoded, but still shouldn't be hardcoded)
        if (doc.kind === 'Secret') {
          const data = (doc.spec as Record<string, unknown>)?.data || (doc as Record<string, unknown>).data;
          if (typeof data === 'object' && data !== null) {
            for (const [key, value] of Object.entries(data)) {
              if (typeof value === 'string' && value.length > 0) {
                // Check if it looks like a hardcoded value (not a reference)
                const sensitiveKeys = ['password', 'secret', 'key', 'token', 'credential', 'api'];
                if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
                  findings.push({
                    id: `${parsedFile.fileName}-${resourceName}-secret-${key}-hardcoded`,
                    ruleId: this.id,
                    title: 'Kubernetes Secret contains hardcoded values',
                    description: `CREDENTIAL LEAK: Secret "${resourceName}" has hardcoded value in "${key}". Secrets in manifests are committed to git and visible in base64.`,
                    severity: this.severity,
                    fileName: parsedFile.fileName,
                    resourcePath: `${doc.kind}/${resourceName}/data/${key}`,
                    remediation: 'Use external secret management: 1) Sealed Secrets 2) External Secrets Operator 3) HashiCorp Vault 4) AWS Secrets Manager CSI driver. Never commit secrets to git.',
                  });
                }
              }
            }
          }
        }
        
        // Check Pod/Deployment env vars
        let podSpec: K8sPodSpec | undefined;
        if (doc.kind === 'Pod') {
          podSpec = doc.spec as unknown as K8sPodSpec;
        } else if (doc.spec?.template?.spec) {
          podSpec = doc.spec.template.spec;
        }
        
        if (podSpec) {
          const allContainers = [
            ...(podSpec.containers || []),
            ...(podSpec.initContainers || []),
          ];
          
          for (const container of allContainers) {
            const containerName = container.name || 'unnamed';
            
            if (Array.isArray(container.env)) {
              for (const envVar of container.env) {
                // Check for hardcoded values (not from secretKeyRef)
                if (envVar.value && typeof envVar.value === 'string' && !envVar.valueFrom) {
                  if (checkForSecrets(envVar.value)) {
                    findings.push({
                      id: `${parsedFile.fileName}-${resourceName}-${containerName}-${envVar.name}-hardcoded-secret`,
                      ruleId: this.id,
                      title: this.title,
                      description: `CREDENTIAL EXPOSURE: Container "${containerName}" in ${doc.kind} "${resourceName}" has hardcoded secret in env var "${envVar.name}". Visible in kubectl describe and logs.`,
                      severity: this.severity,
                      fileName: parsedFile.fileName,
                      resourcePath: `${doc.kind}/${resourceName}/container/${containerName}/env/${envVar.name}`,
                      remediation: `Replace env.value with env.valueFrom.secretKeyRef: { name: "my-secret", key: "${envVar.name}" }. Use Kubernetes Secrets or external secret management.`,
                    });
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
];
