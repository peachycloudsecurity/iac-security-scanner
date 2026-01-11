import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface DockerfileInstruction {
  instruction: string;
  arguments: string;
  lineNumber: number;
}

interface DockerfileParsed {
  instructions: DockerfileInstruction[];
}

export const dockerfileSecurityRules: Rule[] = [
  // Use COPY instead of ADD
  {
    id: 'DOCKER_SEC_002',
    title: 'Dockerfile uses COPY instead of ADD',
    description: 'COPY is more transparent and predictable than ADD, which can download files from URLs.',
    severity: 'MEDIUM',
    applicableFileTypes: ['dockerfile'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerfileParsed;
      
      if (!parsed?.instructions) return findings;
      
      for (const instruction of parsed.instructions) {
        if (instruction.instruction === 'ADD') {
          findings.push({
            id: `${parsedFile.fileName}-line${instruction.lineNumber}-add-instead-of-copy`,
            ruleId: this.id,
            title: this.title,
            description: `Dockerfile uses ADD instead of COPY on line ${instruction.lineNumber}.`,
            severity: this.severity,
            fileName: parsedFile.fileName,
            lineNumber: instruction.lineNumber,
            remediation: 'Replace ADD with COPY unless you specifically need ADD\'s URL download or tar extraction features.',
          });
        }
      }
      
      return findings;
    },
  },

  // No hardcoded secrets
  {
    id: 'DOCKER_SEC_003',
    title: 'Dockerfile has no hardcoded secrets',
    description: 'Hardcoded secrets in Dockerfiles are a security risk and should be avoided.',
    severity: 'HIGH',
    applicableFileTypes: ['dockerfile'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerfileParsed;
      
      if (!parsed?.instructions) return findings;
      
      const secretPatterns = [
        /password\s*=\s*['"][^'"]+['"]/i,
        /secret\s*=\s*['"][^'"]+['"]/i,
        /api[_-]?key\s*=\s*['"][^'"]+['"]/i,
        /access[_-]?token\s*=\s*['"][^'"]+['"]/i,
        /aws[_-]?secret[_-]?access[_-]?key\s*=\s*['"][^'"]+['"]/i,
        /private[_-]?key\s*=\s*['"][^'"]+['"]/i,
      ];
      
      for (const instruction of parsed.instructions) {
        if (instruction.instruction === 'ENV' || instruction.instruction === 'ARG' || instruction.instruction === 'RUN') {
          const args = instruction.arguments;
          
          for (const pattern of secretPatterns) {
            if (pattern.test(args)) {
              findings.push({
                id: `${parsedFile.fileName}-line${instruction.lineNumber}-hardcoded-secret`,
                ruleId: this.id,
                title: this.title,
                description: `Dockerfile may contain hardcoded secrets on line ${instruction.lineNumber}.`,
                severity: this.severity,
                fileName: parsedFile.fileName,
                lineNumber: instruction.lineNumber,
                remediation: 'Use Docker secrets, environment variables, or build arguments instead of hardcoding secrets.',
              });
              break;
            }
          }
        }
      }
      
      return findings;
    },
  },

  // No sudo usage
  {
    id: 'DOCKER_SEC_004',
    title: 'Dockerfile does not use sudo',
    description: 'Using sudo in Dockerfiles is unnecessary and can lead to security issues.',
    severity: 'MEDIUM',
    applicableFileTypes: ['dockerfile'],
    evaluate(parsedFile: ParsedFile): Finding[] {
      const findings: Finding[] = [];
      const parsed = parsedFile.parsed as DockerfileParsed;
      
      if (!parsed?.instructions) return findings;
      
      for (const instruction of parsed.instructions) {
        if (instruction.instruction === 'RUN') {
          const args = instruction.arguments;
          if (/\bsudo\b/.test(args)) {
            findings.push({
              id: `${parsedFile.fileName}-line${instruction.lineNumber}-sudo-usage`,
              ruleId: this.id,
              title: this.title,
              description: `Dockerfile uses sudo on line ${instruction.lineNumber}.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              lineNumber: instruction.lineNumber,
              remediation: 'Remove sudo usage. If root privileges are needed, use USER root or run as root user.',
            });
          }
        }
      }
      
      return findings;
    },
  },
];
