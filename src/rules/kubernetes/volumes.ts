import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface K8sVolume {
  name?: string;
  hostPath?: {
    path?: string;
  };
}

interface K8sPodSpec {
  volumes?: K8sVolume[];
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
    volumes?: K8sVolume[];
  };
}

export const kubernetesVolumesRules: Rule[] = [
  // Host Path Volumes
  {
    id: 'K8S_VOL_001',
    title: 'Pods avoid host path volumes',
    description: 'HOST FILESYSTEM EXPOSURE: Pod mounts host path volumes. Can access host filesystem, sensitive directories, or escape container boundaries.',
    severity: 'HIGH',
    applicableFileTypes: ['kubernetes'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const documents = parsedFile.parsed as K8sDocument[];
      
      if (!Array.isArray(documents)) return findings;
      
      const sensitivePaths = ['/etc', '/var/run/docker.sock', '/proc', '/sys', '/dev', '/root', '/home'];
      
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
        
        if (!podSpec || !podSpec.volumes) continue;
        
        for (const volume of podSpec.volumes) {
          if (volume.hostPath) {
            const hostPath = volume.hostPath.path || '';
            const isSensitive = sensitivePaths.some(path => hostPath.startsWith(path));
            
            findings.push({
              id: `${parsedFile.fileName}-${resourceName}-${volume.name}-host-path`,
              ruleId: this.id,
              title: this.title,
              description: `${doc.kind} "${resourceName}" mounts host path "${hostPath}"${isSensitive ? ' (sensitive directory)' : ''}.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `${doc.kind}/${resourceName}/volume/${volume.name}`,
              remediation: 'Replace hostPath volumes with PersistentVolumeClaims, emptyDir, or configMap/secret volumes. Avoid direct host filesystem access.',
            });
          }
        }
      }
      return findings;
    },
  },
];
