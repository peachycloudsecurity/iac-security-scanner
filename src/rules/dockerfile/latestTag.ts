import { Rule, Finding, ParsedFile } from '@/types/scanner';

interface DockerfileInstruction {
  instruction: string;
  arguments: string;
  lineNumber: number;
}

interface DockerfileParsed {
  instructions: DockerfileInstruction[];
}

export const dockerfileLatestTagRule: Rule = {
  id: 'DOCKER_IMG_001',
  title: 'Dockerfile uses specific image tags',
  description: 'Using the "latest" tag or no tag makes builds non-reproducible and can introduce unexpected changes.',
  severity: 'MEDIUM',
  applicableFileTypes: ['dockerfile'],
  
  evaluate(parsedFile: ParsedFile): Finding[] {
    const findings: Finding[] = [];
    const parsed = parsedFile.parsed as DockerfileParsed;
    
    if (!parsed?.instructions) return findings;
    
    for (const instruction of parsed.instructions) {
      if (instruction.instruction !== 'FROM') continue;
      
      const args = instruction.arguments.trim();
      
      // Parse the image reference
      // Format: [registry/]image[:tag|@digest][ AS stage]
      const imageMatch = args.match(/^(\S+?)(?:\s+AS\s+\S+)?$/i);
      if (!imageMatch) continue;
      
      const imageRef = imageMatch[1];
      
      // Skip scratch (special base image)
      if (imageRef === 'scratch') continue;
      
      // Check if it has a tag or digest
      const hasTag = imageRef.includes(':');
      const hasDigest = imageRef.includes('@sha256:');
      
      if (!hasTag && !hasDigest) {
        // No tag specified - implicitly using :latest
        findings.push({
          id: `${parsedFile.fileName}-line${instruction.lineNumber}-no-tag`,
          ruleId: this.id,
          title: 'No Image Tag Specified',
          description: `Image "${imageRef}" has no tag specified, implicitly using ":latest".`,
          severity: this.severity,
          fileName: parsedFile.fileName,
          lineNumber: instruction.lineNumber,
          remediation: 'Specify an explicit version tag (e.g., "node:18-alpine") or use a digest for maximum reproducibility.',
        });
      } else if (hasTag && imageRef.endsWith(':latest')) {
        // Explicitly using :latest
        findings.push({
          id: `${parsedFile.fileName}-line${instruction.lineNumber}-latest`,
          ruleId: this.id,
          title: this.title,
          description: `Image "${imageRef}" explicitly uses the ":latest" tag.`,
          severity: this.severity,
          fileName: parsedFile.fileName,
          lineNumber: instruction.lineNumber,
          remediation: 'Use a specific version tag (e.g., "node:18-alpine") instead of ":latest".',
        });
      }
    }
    
    return findings;
  },
};
