import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface DockerComposeService {
  privileged?: boolean;
  cap_add?: string[];
  security_opt?: string[];
  volumes?: string[];
  ports?: string[];
  network_mode?: string;
  pid?: string;
  user?: string;
  environment?: Record<string, string> | string[];
  read_only?: boolean;
  tmpfs?: string[];
  image?: string;
  restart?: string;
  logging?: {
    driver?: string;
    options?: Record<string, string>;
  };
  ulimits?: Record<string, any>;
  devices?: string[];
}

interface DockerComposeParsed {
  version?: string;
  services?: Record<string, DockerComposeService>;
}

function checkForSecrets(text: string): boolean {
  const secretPatterns = [
    /AKIA[0-9A-Z]{16}/g, // AWS Access Key
    /password\s*[:=]\s*["\']?([^"'\s]+)/gi,
    /secret\s*[:=]\s*["\']?([^"'\s]+)/gi,
    /token\s*[:=]\s*["\']?([^"'\s]+)/gi,
    /api_key\s*[:=]\s*["\']?([^"'\s]+)/gi,
    /private_key/gi,
  ];
  
  return secretPatterns.some(pattern => pattern.test(text));
}

export const dockerComposeSecurityRules: Rule[] = [
  // Privileged Mode and Dangerous Capabilities
  {
  id: 'COMPOSE_SEC_001',
  title: 'Docker Compose containers without privileged mode',
    description: 'PRIVILEGED CONTAINER: Full host access, can escape container, access other services, compromise entire system.',
  severity: 'HIGH',
  applicableFileTypes: ['docker-compose'],
  
  evaluate(parsedFile: ParsedFile): Finding[] {
    const findings: Finding[] = [];
    const parsed = parsedFile.parsed as DockerComposeParsed;
    
    if (!parsed?.services) return findings;
    
    for (const [serviceName, service] of Object.entries(parsed.services)) {
      if (!service || typeof service !== 'object') continue;
      
      // Check for privileged mode
      if (service.privileged === true) {
        findings.push({
          id: `${parsedFile.fileName}-${serviceName}-privileged`,
          ruleId: this.id,
          title: this.title,
            description: `CONTAINER ESCAPE: Service "${serviceName}" runs privileged=true with full host access. Can break container isolation, access other services, compromise host system.`,
          severity: this.severity,
          fileName: parsedFile.fileName,
          resourcePath: `services/${serviceName}`,
            remediation: 'Remove privileged: true. Use cap_add with specific capabilities only: cap_add: ["NET_BIND_SERVICE"] for port 80/443 binding.',
        });
      }
      
      // Check for dangerous capabilities
        const dangerousCaps = ['SYS_ADMIN', 'NET_ADMIN', 'ALL', 'SYS_PTRACE', 'SYS_MODULE'];
      if (Array.isArray(service.cap_add)) {
        const foundDangerous = service.cap_add.filter(cap => 
          dangerousCaps.includes(cap.toUpperCase())
        );
        
        if (foundDangerous.length > 0) {
          findings.push({
            id: `${parsedFile.fileName}-${serviceName}-dangerous-caps`,
            ruleId: 'COMPOSE_SEC_002',
              title: 'Container avoids dangerous capabilities',
              description: `DANGEROUS CAPABILITIES: Service "${serviceName}" has capabilities ${foundDangerous.join(', ')} allowing system-level access, container escape, and host compromise.`,
              severity: 'HIGH',
              fileName: parsedFile.fileName,
              resourcePath: `services/${serviceName}`,
              remediation: 'Remove dangerous capabilities. Use minimal caps: NET_BIND_SERVICE for ports, CHOWN for file ownership. Avoid SYS_ADMIN, NET_ADMIN, ALL.',
            });
          }
        }
      }
      
      return findings;
    },
  },

  // Host Volume Mounts
  {
    id: 'COMPOSE_SEC_003',
    title: 'Container avoids sensitive host volume mounts',
    description: 'HOST FILESYSTEM ACCESS: Mounting host directories gives container access to host files. Can read sensitive data, modify system files, escape container.',
    severity: 'HIGH',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      const sensitivePaths = ['/etc', '/var/run/docker.sock', '/proc', '/sys', '/dev', '/', '/root', '/home'];
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        if (Array.isArray(service.volumes)) {
          for (const volume of service.volumes) {
            if (typeof volume === 'string') {
              const [hostPath] = volume.split(':');
              
              if (sensitivePaths.some(path => hostPath.startsWith(path))) {
                findings.push({
                  id: `${parsedFile.fileName}-${serviceName}-sensitive-volume`,
                  ruleId: this.id,
                  title: this.title,
                  description: `HOST ACCESS: Service "${serviceName}" mounts sensitive host path "${hostPath}". Can read host secrets, modify system files, access Docker socket for container escape.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `services/${serviceName}`,
                  remediation: `Remove volume mount "${volume}". Use named volumes or bind specific non-sensitive directories only. Never mount /var/run/docker.sock unless required for container orchestration.`,
                });
              }
            }
          }
        }
      }
      
      return findings;
    },
  },

  // Host Network Mode
  {
    id: 'COMPOSE_SEC_004',
    title: 'Container avoids host network mode',
    description: 'HOST NETWORK: Container shares host network stack. Can access all host ports, bypass firewall rules, interfere with host services.',
    severity: 'HIGH',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        if (service.network_mode === 'host') {
          findings.push({
            id: `${parsedFile.fileName}-${serviceName}-host-network`,
            ruleId: this.id,
            title: this.title,
            description: `HOST NETWORK BYPASS: Service "${serviceName}" uses network_mode: host, sharing host network. Can access all host ports, bypass container network isolation, conflict with host services.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `services/${serviceName}`,
            remediation: 'Remove network_mode: host. Use custom networks: networks: [app-network] and expose only required ports: ports: ["8080:8080"].',
          });
        }
      }
      
      return findings;
    },
  },

  // Host PID Mode
  {
    id: 'COMPOSE_SEC_005',
    title: 'Container avoids host PID mode',
    description: 'HOST PROCESS ACCESS: Container can see and control host processes. Enables process injection, signal attacks, information disclosure.',
    severity: 'HIGH',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        if (service.pid === 'host') {
          findings.push({
            id: `${parsedFile.fileName}-${serviceName}-host-pid`,
            ruleId: this.id,
            title: this.title,
            description: `HOST PROCESS VISIBILITY: Service "${serviceName}" uses pid: host, sharing host process namespace. Can view all host processes, send signals, access process memory.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `services/${serviceName}`,
            remediation: 'Remove pid: host unless absolutely required for system monitoring tools. Use isolated PID namespace for security.',
          });
        }
      }
      
      return findings;
    },
  },

  // Environment Variable Secrets
  {
    id: 'COMPOSE_SEC_006',
    title: 'Container environment has no hardcoded secrets',
    description: 'CREDENTIAL EXPOSURE: Hardcoded secrets in environment variables visible in process lists, docker inspect, and logs.',
    severity: 'HIGH',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        if (service.environment) {
          let hasSecrets = false;
          let secretVar = '';
          
          if (Array.isArray(service.environment)) {
            // Format: ["KEY=value", "SECRET=password"]
            for (const envVar of service.environment) {
              if (typeof envVar === 'string' && checkForSecrets(envVar)) {
                hasSecrets = true;
                secretVar = envVar.split('=')[0];
                break;
              }
            }
          } else if (typeof service.environment === 'object') {
            // Format: {KEY: value, SECRET: password}
            for (const [key, value] of Object.entries(service.environment)) {
              if (typeof value === 'string' && checkForSecrets(value)) {
                hasSecrets = true;
                secretVar = key;
                break;
              }
            }
          }
          
          if (hasSecrets) {
            findings.push({
              id: `${parsedFile.fileName}-${serviceName}-env-secrets`,
              ruleId: this.id,
              title: this.title,
              description: `EXPOSED CREDENTIALS: Service "${serviceName}" has hardcoded secrets in environment variable "${secretVar}". Visible in docker inspect, process lists, and container logs.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `services/${serviceName}`,
              remediation: `Remove hardcoded secret from "${secretVar}". Use: 1) Docker secrets: secrets: [db_password] 2) External env file: env_file: [.env] 3) Runtime injection from secure store.`,
            });
          }
        }
      }
      
      return findings;
    },
  },

  // Unrestricted Port Exposure
  {
    id: 'COMPOSE_SEC_007',
    title: 'Container ports not exposed to all interfaces',
    description: 'ALL INTERFACE BINDING: Ports bound to 0.0.0.0 accessible from any network interface. Exposes services beyond intended scope.',
    severity: 'MEDIUM',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        if (Array.isArray(service.ports)) {
          for (const port of service.ports) {
            if (typeof port === 'string') {
              // Check for wide binding: "80:8080" or "0.0.0.0:80:8080"
              if (port.match(/^(\d+:\d+|0\.0\.0\.0:\d+:\d+)$/)) {
                findings.push({
                  id: `${parsedFile.fileName}-${serviceName}-wide-port-binding`,
                  ruleId: this.id,
                  title: this.title,
                  description: `UNRESTRICTED BINDING: Service "${serviceName}" binds port "${port}" to all interfaces (0.0.0.0). Accessible from any network connection to host.`,
                  severity: this.severity,
                  fileName: parsedFile.fileName,
                  resourcePath: `services/${serviceName}`,
                  remediation: `Bind to localhost only: "127.0.0.1:${port}" or specific interface: "10.0.1.100:${port}". Use reverse proxy (nginx) for external access.`,
                });
              }
            }
          }
        }
      }
      
      return findings;
    },
  },

  // Non-Root User Check
  {
    id: 'COMPOSE_SEC_008',
    title: 'Container runs as non-root user',
    description: 'ROOT CONTAINER: Container runs as UID 0 with full system privileges. Can escape container, access host filesystem, compromise other containers.',
            severity: 'MEDIUM',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        // Check if user is not specified (defaults to root) or explicitly set to root
        if (!service.user || service.user === 'root' || service.user === '0') {
          findings.push({
            id: `${parsedFile.fileName}-${serviceName}-root-user`,
            ruleId: this.id,
            title: this.title,
            description: `ROOT EXECUTION: Service "${serviceName}" ${!service.user ? 'has no user specified (defaults to root)' : 'explicitly runs as root'}. Container has full system privileges.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `services/${serviceName}`,
            remediation: 'Add user: "1001:1001" or user: "appuser". Ensure Dockerfile creates non-root user: RUN adduser -D appuser.',
          });
        }
      }
      
      return findings;
    },
  },

  // Latest Tag Usage
  {
    id: 'COMPOSE_SEC_013',
    title: 'Container images use specific tags not latest',
    description: 'LATEST TAG RISK: Using :latest tag pulls unpredictable image versions. No control over security patches, breaking changes, or malicious updates.',
    severity: 'MEDIUM',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        if (typeof service.image === 'string') {
          const image = service.image;
          if (image.endsWith(':latest') || !image.includes(':')) {
            findings.push({
              id: `${parsedFile.fileName}-${serviceName}-latest-tag`,
              ruleId: this.id,
              title: this.title,
              description: `UNPREDICTABLE IMAGE: Service "${serviceName}" uses image "${image}" with :latest or no tag. Deployments may pull different versions with unknown vulnerabilities.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              resourcePath: `services/${serviceName}`,
              remediation: `Use specific version tag: image: "${image.split(':')[0]}:1.2.3" or digest: image: "${image.split(':')[0]}@sha256:abc123". Pin to known secure versions.`,
          });
        }
      }
    }
    
    return findings;
  },
  },

  // Device Access
  {
    id: 'COMPOSE_SEC_014',
    title: 'Container avoids host device access',
    description: 'HOST DEVICE ACCESS: Mounting host devices gives container hardware access. Can access storage, network interfaces, USB devices.',
    severity: 'HIGH',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        if (Array.isArray(service.devices)) {
          findings.push({
            id: `${parsedFile.fileName}-${serviceName}-device-access`,
            ruleId: this.id,
            title: this.title,
            description: `HARDWARE ACCESS: Service "${serviceName}" mounts host devices: ${service.devices.join(', ')}. Can access storage devices, network interfaces, bypass container isolation.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `services/${serviceName}`,
            remediation: 'Remove devices: [...] unless absolutely required for hardware interaction. Use specific device paths, not /dev/* wildcards.',
          });
        }
      }
      
      return findings;
    },
  },

  // Unlimited Resource Usage
  {
    id: 'COMPOSE_SEC_015',
    title: 'Container has resource limits configured',
    description: 'RESOURCE EXHAUSTION: No CPU/memory limits allows container to consume all host resources. Enables DoS attacks against host and other containers.',
    severity: 'MEDIUM',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        const deploy = (service as any).deploy;
        const hasResourceLimits = deploy && deploy.resources && deploy.resources.limits && 
          (deploy.resources.limits.memory || deploy.resources.limits.cpus);
        
        if (!hasResourceLimits) {
          findings.push({
            id: `${parsedFile.fileName}-${serviceName}-no-resource-limits`,
            ruleId: this.id,
            title: this.title,
            description: `UNBOUNDED RESOURCES: Service "${serviceName}" has no CPU/memory limits. Can consume all host resources, causing DoS to other containers and host system.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `services/${serviceName}`,
            remediation: 'Add deploy: resources: limits: {memory: "512M", cpus: "0.5"} to prevent resource exhaustion. Set appropriate limits based on application needs.',
          });
        }
      }
      
      return findings;
    },
  },

  // Always Restart Policy
  {
    id: 'COMPOSE_SEC_016',
    title: 'Container restart policy not set to always',
    description: 'AUTO-RESTART RISK: restart: always automatically restarts failed containers. Malware or compromised containers persist through crashes.',
    severity: 'MEDIUM',
    applicableFileTypes: ['docker-compose'],
    
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerComposeParsed;
      
      if (!parsed?.services) return findings;
      
      for (const [serviceName, service] of Object.entries(parsed.services)) {
        if (!service || typeof service !== 'object') continue;
        
        if (service.restart === 'always') {
          findings.push({
            id: `${parsedFile.fileName}-${serviceName}-always-restart`,
            ruleId: this.id,
            title: this.title,
            description: `PERSISTENCE RISK: Service "${serviceName}" uses restart: always. Compromised or malicious containers automatically restart after crashes, maintaining persistence.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            resourcePath: `services/${serviceName}`,
            remediation: 'Change to restart: "on-failure:3" to limit restart attempts or restart: "unless-stopped" for manual control. Avoid restart: always in production.',
          });
        }
      }
      
      return findings;
    },
  },
];

// Export the main rule for backward compatibility
export const dockerComposePrivilegedRule = dockerComposeSecurityRules[0];
