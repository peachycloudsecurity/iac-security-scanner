import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface DockerfileInstruction {
  instruction: string;
  arguments: string;
  lineNumber: number;
}

interface DockerfileParsed {
  instructions: DockerfileInstruction[];
}

export const dockerfileRootUserRule: Rule = {
  id: 'DOCKER_SEC_001',
  title: 'Dockerfile uses non-root user',
  description: 'Running containers as root increases security risk. The last USER instruction should not be root.',
  severity: 'HIGH',
  applicableFileTypes: ['dockerfile'],
  
  evaluate(parsedFile: ParsedFile): Finding[] {
    const findings: Finding[] = [];
    const parsed = parsedFile.parsed as DockerfileParsed;
    
    if (!parsed?.instructions) return findings;
    
    // Find the last USER instruction
    let lastUserInstruction: DockerfileInstruction | null = null;
    for (let i = parsed.instructions.length - 1; i >= 0; i--) {
      if (parsed.instructions[i].instruction === 'USER') {
        lastUserInstruction = parsed.instructions[i];
        break;
      }
    }
    
    // If no USER instruction, container runs as root by default
    if (!lastUserInstruction) {
      findings.push({
        id: `${parsedFile.fileName}-no-user`,
        ruleId: this.id,
        title: 'No USER Instruction Found',
        description: 'Dockerfile does not specify a USER instruction, so the container will run as root by default.',
        severity: this.severity,
        fileName: parsedFile.fileName,
        lineNumber: parsed.instructions[0]?.lineNumber || 1,
        remediation: 'Add a USER instruction with a non-root user before the end of the Dockerfile.',
      });
      return findings;
    }
    
    // Check if the last USER is root
    const userValue = lastUserInstruction.arguments.trim();
    if (userValue === 'root' || userValue === '0') {
      findings.push({
        id: `${parsedFile.fileName}-line${lastUserInstruction.lineNumber}-root-user`,
        ruleId: this.id,
        title: this.title,
        description: `The last USER instruction (line ${lastUserInstruction.lineNumber}) is set to root.`,
        severity: this.severity,
        fileName: parsedFile.fileName,
        lineNumber: lastUserInstruction.lineNumber,
        remediation: 'Change the USER instruction to a non-root user (e.g., "USER appuser" or "USER 1000").',
      });
    }
    
    return findings;
  },
};
