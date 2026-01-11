interface DockerfileInstruction {
  instruction: string;
  arguments: string;
  lineNumber: number;
  raw: string;
}

interface DockerfileParsed {
  instructions: DockerfileInstruction[];
  stages: DockerfileStage[];
  raw: string;
}

interface DockerfileStage {
  name: string | null;
  baseImage: string;
  startLine: number;
  instructions: DockerfileInstruction[];
}

export function parseDockerfile(content: string): DockerfileParsed {
  const lines = content.split('\n');
  const instructions: DockerfileInstruction[] = [];
  const stages: DockerfileStage[] = [];
  let currentStage: DockerfileStage | null = null;
  
  let lineBuffer = '';
  let bufferStartLine = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Skip empty lines and comments
    if (trimmed === '' || trimmed.startsWith('#')) {
      continue;
    }
    
    // Handle line continuation
    if (trimmed.endsWith('\\')) {
      if (lineBuffer === '') {
        bufferStartLine = i;
      }
      lineBuffer += trimmed.slice(0, -1).trim() + ' ';
      continue;
    }
    
    // Complete the line
    const fullLine = lineBuffer + trimmed;
    const actualLineNumber = lineBuffer ? bufferStartLine : i;
    lineBuffer = '';
    
    // Parse instruction
    const match = fullLine.match(/^(\w+)\s*(.*)?$/);
    if (match) {
      const [, instruction, args = ''] = match;
      const instructionObj: DockerfileInstruction = {
        instruction: instruction.toUpperCase(),
        arguments: args.trim(),
        lineNumber: actualLineNumber + 1, // 1-indexed
        raw: fullLine,
      };
      
      instructions.push(instructionObj);
      
      // Track stages (FROM instructions)
      if (instruction.toUpperCase() === 'FROM') {
        const fromMatch = args.match(/^(\S+)(?:\s+AS\s+(\S+))?/i);
        if (fromMatch) {
          const [, baseImage, stageName = null] = fromMatch;
          currentStage = {
            name: stageName,
            baseImage,
            startLine: actualLineNumber + 1,
            instructions: [instructionObj],
          };
          stages.push(currentStage);
        }
      } else if (currentStage) {
        currentStage.instructions.push(instructionObj);
      }
    }
  }
  
  return { instructions, stages, raw: content };
}
