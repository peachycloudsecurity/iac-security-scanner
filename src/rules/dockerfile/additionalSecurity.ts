import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface DockerfileInstruction {
  instruction: string;
  arguments: string;
  lineNumber: number;
}

interface DockerfileParsed {
  instructions: DockerfileInstruction[];
}

export const dockerfileAdditionalSecurityRules: Rule[] = [
  // HEALTHCHECK Instruction
  {
    id: 'DOCKER_HEALTH_001',
    title: 'Dockerfile includes HEALTHCHECK instruction',
    description: 'MISSING HEALTH MONITORING: No HEALTHCHECK instruction. Cannot detect container failures, leading to serving traffic to unhealthy containers.',
    severity: 'MEDIUM',
    applicableFileTypes: ['dockerfile'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerfileParsed;
      
      if (!parsed?.instructions) return findings;
      
      const hasHealthcheck = parsed.instructions.some(inst => inst.instruction === 'HEALTHCHECK');
      
      if (!hasHealthcheck) {
        findings.push({
          id: `${parsedFile.fileName}-no-healthcheck`,
          ruleId: this.id,
          title: this.title,
          description: 'Dockerfile does not include a HEALTHCHECK instruction.',
          severity: this.severity,
          fileName: parsedFile.fileName,
          lineNumber: parsed.instructions[parsed.instructions.length - 1]?.lineNumber || 1,
          remediation: 'Add HEALTHCHECK instruction: HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost/health || exit 1',
        });
      }
      
      return findings;
    },
  },

  // Exposed Ports
  {
    id: 'DOCKER_NET_001',
    title: 'Dockerfile documents exposed ports',
    description: 'MISSING PORT DOCUMENTATION: No EXPOSE instruction. Makes it unclear which ports the container listens on, complicating security reviews and network policies.',
    severity: 'MEDIUM',
    applicableFileTypes: ['dockerfile'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerfileParsed;
      
      if (!parsed?.instructions) return findings;
      
      const hasExpose = parsed.instructions.some(inst => inst.instruction === 'EXPOSE');
      const hasRun = parsed.instructions.some(inst => 
        inst.instruction === 'RUN' && 
        (inst.arguments.includes('listen') || inst.arguments.includes('port') || inst.arguments.includes('server'))
      );
      
      // If there's a RUN command that suggests a server, but no EXPOSE, flag it
      if (hasRun && !hasExpose) {
        findings.push({
          id: `${parsedFile.fileName}-no-expose`,
          ruleId: this.id,
          title: this.title,
          description: 'Dockerfile appears to run a server but does not include EXPOSE instruction.',
          severity: this.severity,
          fileName: parsedFile.fileName,
          lineNumber: parsed.instructions[parsed.instructions.length - 1]?.lineNumber || 1,
          remediation: 'Add EXPOSE instruction for all ports the container listens on (e.g., EXPOSE 8080 8443).',
        });
      }
      
      return findings;
    },
  },

  // Dangerous RUN commands
  {
    id: 'DOCKER_RUN_001',
    title: 'Dockerfile avoids dangerous RUN commands',
    description: 'UNSAFE INSTALLATION: RUN command uses curl|sh, wget|sh, or pip install --upgrade. Can execute arbitrary code, introduce vulnerabilities, or break builds.',
    severity: 'HIGH',
    applicableFileTypes: ['dockerfile'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerfileParsed;
      
      if (!parsed?.instructions) return findings;
      
      const dangerousPatterns = [
        { pattern: /\bcurl\s+.*\s*\|\s*sh\b/i, desc: 'curl | sh' },
        { pattern: /\bwget\s+.*\s*\|\s*sh\b/i, desc: 'wget | sh' },
        { pattern: /\bpip\s+install\s+.*--upgrade\b/i, desc: 'pip install --upgrade' },
        { pattern: /\bnpm\s+install\s+-g\b/i, desc: 'npm install -g' },
        { pattern: /\bapt-get\s+upgrade\b/i, desc: 'apt-get upgrade' },
      ];
      
      for (const instruction of parsed.instructions) {
        if (instruction.instruction === 'RUN') {
          for (const { pattern, desc } of dangerousPatterns) {
            if (pattern.test(instruction.arguments)) {
              findings.push({
                id: `${parsedFile.fileName}-line${instruction.lineNumber}-dangerous-run-${desc.replace(/\s+/g, '-')}`,
                ruleId: this.id,
                title: this.title,
                description: `Dockerfile uses dangerous RUN command (${desc}) on line ${instruction.lineNumber}.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                lineNumber: instruction.lineNumber,
                remediation: `Avoid ${desc}. Download scripts first, verify checksums, then execute. Use specific package versions instead of --upgrade.`,
              });
              break;
            }
          }
        }
      }
      
      return findings;
    },
  },

  // Multi-stage builds
  {
    id: 'DOCKER_BUILD_001',
    title: 'Dockerfile uses multi-stage builds',
    description: 'LARGE IMAGE SIZE: Single-stage build includes build tools and dependencies in final image. Increases attack surface, image size, and deployment time.',
    severity: 'MEDIUM',
    applicableFileTypes: ['dockerfile'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerfileParsed;
      
      if (!parsed?.instructions) return findings;
      
      const fromInstructions = parsed.instructions.filter(inst => inst.instruction === 'FROM');
      const hasMultiStage = fromInstructions.length > 1;
      const hasBuildTools = parsed.instructions.some(inst => 
        inst.instruction === 'RUN' && 
        (inst.arguments.includes('gcc') || inst.arguments.includes('make') || inst.arguments.includes('npm install') || inst.arguments.includes('pip install'))
      );
      
      if (hasBuildTools && !hasMultiStage) {
        findings.push({
          id: `${parsedFile.fileName}-no-multistage`,
          ruleId: this.id,
          title: this.title,
          description: 'Dockerfile includes build tools but does not use multi-stage builds.',
          severity: this.severity,
          fileName: parsedFile.fileName,
          lineNumber: fromInstructions[0]?.lineNumber || 1,
          remediation: 'Use multi-stage builds: FROM node:18 AS builder ... FROM node:18-alpine COPY --from=builder /app /app. This excludes build tools from final image.',
        });
      }
      
      return findings;
    },
  },
];
