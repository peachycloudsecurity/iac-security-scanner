import { Rule } from '@/types/scanner';

export const dockerComposeLowSeverityRules: Rule[] = [
  {
    id: 'COMPOSE_VER_001',
    title: 'Docker Compose version should be specified',
    description: 'VERSION CONTROL: Docker Compose version not specified, may cause compatibility issues.',
    severity: 'LOW',
    applicableFileTypes: ['docker-compose'],
    evaluate: (parsedFile) => {
      const findings = [];
      
      if (!(parsedFile as any).version) {
        findings.push({
          ruleId: 'COMPOSE_VER_001',
          title: 'Docker Compose version should be specified',
          description: 'VERSION CONTROL: Docker Compose file lacks version specification. This may cause compatibility issues with different Docker Compose versions.',
          severity: 'LOW',
          resourcePath: 'docker-compose.yml',
          lineNumber: 1,
          remediation: 'Add version at the top: version: "3.8" (or appropriate version)'
        });
      }
      
      return findings;
    }
  },

  {
    id: 'COMPOSE_NAME_001',
    title: 'Services should have descriptive names',
    description: 'ORGANIZATION: Service names should be descriptive for better understanding and maintenance.',
    severity: 'LOW',
    applicableFileTypes: ['docker-compose'],
    evaluate: (parsedFile) => {
      const findings = [];
      const services = (parsedFile as any).services || {};
      
      const genericNames = ['app', 'web', 'api', 'service', 'container', 'main'];
      
      for (const [serviceName, serviceConfig] of Object.entries(services)) {
        if (genericNames.includes(serviceName.toLowerCase())) {
          findings.push({
            ruleId: 'COMPOSE_NAME_001',
            title: 'Services should have descriptive names',
            description: `ORGANIZATION: Service "${serviceName}" uses generic name. Descriptive names improve understanding and maintenance.`,
            severity: 'LOW',
            resourcePath: `services.${serviceName}`,
            remediation: `Use descriptive name like: frontend-web, user-api, payment-service instead of "${serviceName}"`
          });
        }
      }
      
      return findings;
    }
  },

  {
    id: 'COMPOSE_HEALTH_001',
    title: 'Services should have health checks',
    description: 'RELIABILITY: Service lacks health check configuration for better monitoring and recovery.',
    severity: 'LOW',
    applicableFileTypes: ['docker-compose'],
    evaluate: (parsedFile) => {
      const findings = [];
      const services = (parsedFile as any).services || {};
      
      for (const [serviceName, serviceConfig] of Object.entries(services)) {
        const config = serviceConfig as any;
        
        if (!config.healthcheck && !config.depends_on) {
          findings.push({
            ruleId: 'COMPOSE_HEALTH_001',
            title: 'Services should have health checks',
            description: `RELIABILITY: Service "${serviceName}" lacks health check configuration. This affects monitoring and automatic recovery capabilities.`,
            severity: 'LOW',
            resourcePath: `services.${serviceName}`,
            remediation: 'Add healthcheck: { test: ["CMD", "curl", "-f", "http://localhost:8080/health"], interval: "30s", timeout: "10s", retries: 3 }'
          });
        }
      }
      
      return findings;
    }
  }
];