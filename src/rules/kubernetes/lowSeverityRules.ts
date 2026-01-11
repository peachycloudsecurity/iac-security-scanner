import { Rule } from '@/types/scanner';

export const kubernetesLowSeverityRules: Rule[] = [
  {
    id: 'K8S_IMG_001',
    title: 'Container should not use latest tag',
    description: 'VERSION CONTROL: Container uses "latest" tag which can lead to unpredictable deployments and security issues.',
    severity: 'LOW',
    applicableFileTypes: ['kubernetes'],
    evaluate: (parsedFile) => {
      const findings = [];
      const resources = Array.isArray(parsedFile) ? parsedFile : [parsedFile];
      
      for (const resource of resources) {
        if (!resource || typeof resource !== 'object') continue;
        
        const kind = resource.kind;
        if (!['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'Pod'].includes(kind)) continue;
        
        let containers = [];
        if (kind === 'Pod') {
          containers = resource.spec?.containers || [];
        } else if (kind === 'CronJob') {
          containers = resource.spec?.jobTemplate?.spec?.template?.spec?.containers || [];
        } else {
          containers = resource.spec?.template?.spec?.containers || [];
        }
        
        for (const container of containers) {
          const image = container.image || '';
          if (image.endsWith(':latest') || (!image.includes(':') && image !== '')) {
            findings.push({
              ruleId: 'K8S_IMG_001',
              title: 'Container should not use latest tag',
              description: `VERSION CONTROL: Container "${container.name}" uses "latest" tag or no tag (defaults to latest). This can lead to unpredictable deployments and potential security vulnerabilities.`,
              severity: 'LOW',
              resourcePath: `${kind}/${resource.metadata?.name}/containers/${container.name}`,
              remediation: 'Use specific image tags: image: "nginx:1.21.6" instead of "nginx:latest" or "nginx"'
            });
          }
        }
      }
      
      return findings;
    }
  },

  {
    id: 'K8S_PROBE_001',
    title: 'Container should have liveness probe',
    description: 'RELIABILITY: Container lacks liveness probe, Kubernetes cannot detect if container is healthy.',
    severity: 'LOW',
    applicableFileTypes: ['kubernetes'],
    evaluate: (parsedFile) => {
      const findings = [];
      const resources = Array.isArray(parsedFile) ? parsedFile : [parsedFile];
      
      for (const resource of resources) {
        if (!resource || typeof resource !== 'object') continue;
        
        const kind = resource.kind;
        if (!['Deployment', 'StatefulSet', 'DaemonSet'].includes(kind)) continue;
        
        const containers = resource.spec?.template?.spec?.containers || [];
        
        for (const container of containers) {
          if (!container.livenessProbe) {
            findings.push({
              ruleId: 'K8S_PROBE_001',
              title: 'Container should have liveness probe',
              description: `RELIABILITY: Container "${container.name}" lacks liveness probe. Kubernetes cannot automatically restart unhealthy containers.`,
              severity: 'LOW',
              resourcePath: `${kind}/${resource.metadata?.name}/containers/${container.name}`,
              remediation: 'Add liveness probe: livenessProbe: { httpGet: { path: "/health", port: 8080 }, initialDelaySeconds: 30, periodSeconds: 10 }'
            });
          }
        }
      }
      
      return findings;
    }
  },

  {
    id: 'K8S_PROBE_002',
    title: 'Container should have readiness probe',
    description: 'RELIABILITY: Container lacks readiness probe, may receive traffic before being ready.',
    severity: 'LOW',
    applicableFileTypes: ['kubernetes'],
    evaluate: (parsedFile) => {
      const findings = [];
      const resources = Array.isArray(parsedFile) ? parsedFile : [parsedFile];
      
      for (const resource of resources) {
        if (!resource || typeof resource !== 'object') continue;
        
        const kind = resource.kind;
        if (!['Deployment', 'StatefulSet', 'DaemonSet'].includes(kind)) continue;
        
        const containers = resource.spec?.template?.spec?.containers || [];
        
        for (const container of containers) {
          if (!container.readinessProbe) {
            findings.push({
              ruleId: 'K8S_PROBE_002',
              title: 'Container should have readiness probe',
              description: `RELIABILITY: Container "${container.name}" lacks readiness probe. May receive traffic before application is ready to serve requests.`,
              severity: 'LOW',
              resourcePath: `${kind}/${resource.metadata?.name}/containers/${container.name}`,
              remediation: 'Add readiness probe: readinessProbe: { httpGet: { path: "/ready", port: 8080 }, initialDelaySeconds: 5, periodSeconds: 5 }'
            });
          }
        }
      }
      
      return findings;
    }
  },

  {
    id: 'K8S_LABEL_001',
    title: 'Resources should have standard labels',
    description: 'ORGANIZATION: Resource lacks standard Kubernetes labels for better organization and selection.',
    severity: 'LOW',
    applicableFileTypes: ['kubernetes'],
    evaluate: (parsedFile) => {
      const findings = [];
      const resources = Array.isArray(parsedFile) ? parsedFile : [parsedFile];
      
      const recommendedLabels = ['app.kubernetes.io/name', 'app.kubernetes.io/version', 'app.kubernetes.io/component'];
      
      for (const resource of resources) {
        if (!resource || typeof resource !== 'object') continue;
        
        const kind = resource.kind;
        const name = resource.metadata?.name;
        const labels = resource.metadata?.labels || {};
        
        if (['Deployment', 'StatefulSet', 'DaemonSet', 'Service', 'ConfigMap', 'Secret'].includes(kind)) {
          const missingLabels = recommendedLabels.filter(label => !labels[label]);
          
          if (missingLabels.length > 0) {
            findings.push({
              ruleId: 'K8S_LABEL_001',
              title: 'Resources should have standard labels',
              description: `ORGANIZATION: ${kind} "${name}" lacks recommended labels: ${missingLabels.join(', ')}. This affects resource organization and selection.`,
              severity: 'LOW',
              resourcePath: `${kind}/${name}`,
              remediation: `Add standard labels: ${missingLabels.map(label => `${label}: "appropriate-value"`).join(', ')}`
            });
          }
        }
      }
      
      return findings;
    }
  }
];