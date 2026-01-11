import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface DockerfileInstruction {
  instruction: string;
  arguments: string;
  lineNumber: number;
}

interface DockerfileParsed {
  instructions: DockerfileInstruction[];
}

export const dockerfileExposePort22Rule: Rule = {
  id: 'DOCKER_NET_001',
  title: 'Dockerfile does not expose port 22',
  description: 'Exposing port 22 (SSH) in containers is a security risk and should be avoided.',
  severity: 'MEDIUM',
  applicableFileTypes: ['dockerfile'],
  
  evaluate(parsedFile: ParsedFile): Finding[] {
    const findings: Finding[] = [];
    const parsed = parsedFile.parsed as DockerfileParsed;
    
    if (!parsed?.instructions) return findings;
    
    for (const instruction of parsed.instructions) {
      if (instruction.instruction === 'EXPOSE') {
        const ports = instruction.arguments.trim().split(/\s+/);
        for (const port of ports) {
          if (port === '22' || port === '22/tcp' || port === '22/udp') {
            findings.push({
              id: `${parsedFile.fileName}-line${instruction.lineNumber}-expose-22`,
              ruleId: this.id,
              title: this.title,
              description: `Dockerfile exposes port 22 (SSH) on line ${instruction.lineNumber}.`,
              severity: this.severity,
              fileName: parsedFile.fileName,
              lineNumber: instruction.lineNumber,
              remediation: 'Remove the EXPOSE 22 instruction. SSH should not be exposed in containers.',
            });
            break;
          }
        }
      }
    }
    
    return findings;
  },
};
