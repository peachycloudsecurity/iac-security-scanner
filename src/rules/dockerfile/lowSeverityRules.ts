import { Rule } from '@/types/scanner';

export const dockerfileLowSeverityRules: Rule[] = [
  {
    id: 'DOCKER_CACHE_001',
    title: 'Dockerfile should use build cache efficiently',
    description: 'PERFORMANCE: Dockerfile structure may not utilize Docker build cache efficiently, leading to slower builds.',
    severity: 'LOW',
    applicableFileTypes: ['dockerfile'],
    evaluate: (parsedFile) => {
      const findings = [];
      const instructions = parsedFile.instructions || [];
      
      let copyBeforeRun = false;
      let runAfterCopy = false;
      
      for (let i = 0; i < instructions.length; i++) {
        const instruction = instructions[i];
        
        if (instruction.command === 'COPY' && instruction.args?.includes('package.json')) {
          copyBeforeRun = true;
        }
        
        if (copyBeforeRun && instruction.command === 'RUN' && 
            (instruction.args?.includes('npm install') || instruction.args?.includes('yarn install'))) {
          runAfterCopy = true;
        }
        
        if (instruction.command === 'COPY' && instruction.args?.includes('.') && !runAfterCopy) {
          findings.push({
            ruleId: 'DOCKER_CACHE_001',
            title: 'Dockerfile should use build cache efficiently',
            description: 'PERFORMANCE: Copying all files before installing dependencies invalidates cache on any file change. Copy package files first, install dependencies, then copy source code.',
            severity: 'LOW',
            resourcePath: 'Dockerfile',
            lineNumber: instruction.lineNumber,
            remediation: 'Restructure: 1) COPY package*.json ./ 2) RUN npm install 3) COPY . ./'
          });
          break;
        }
      }
      
      return findings;
    }
  },

  {
    id: 'DOCKER_LABEL_001',
    title: 'Dockerfile should include metadata labels',
    description: 'DOCUMENTATION: Dockerfile lacks metadata labels for better image identification and management.',
    severity: 'LOW',
    applicableFileTypes: ['dockerfile'],
    evaluate: (parsedFile) => {
      const findings = [];
      const instructions = parsedFile.instructions || [];
      
      const recommendedLabels = ['maintainer', 'version', 'description'];
      const foundLabels = [];
      
      for (const instruction of instructions) {
        if (instruction.command === 'LABEL') {
          const labelArgs = instruction.args || '';
          for (const label of recommendedLabels) {
            if (labelArgs.toLowerCase().includes(label)) {
              foundLabels.push(label);
            }
          }
        }
      }
      
      const missingLabels = recommendedLabels.filter(label => !foundLabels.includes(label));
      
      if (missingLabels.length > 0) {
        findings.push({
          ruleId: 'DOCKER_LABEL_001',
          title: 'Dockerfile should include metadata labels',
          description: `DOCUMENTATION: Dockerfile lacks recommended metadata labels: ${missingLabels.join(', ')}. This affects image identification and management.`,
          severity: 'LOW',
          resourcePath: 'Dockerfile',
          lineNumber: 1,
          remediation: `Add metadata labels: ${missingLabels.map(label => `LABEL ${label}="appropriate-value"`).join(', ')}`
        });
      }
      
      return findings;
    }
  },

  {
    id: 'DOCKER_WORK_001',
    title: 'Dockerfile should set explicit WORKDIR',
    description: 'BEST PRACTICE: No explicit WORKDIR set, commands may run in unpredictable directories.',
    severity: 'LOW',
    applicableFileTypes: ['dockerfile'],
    evaluate: (parsedFile) => {
      const findings = [];
      const instructions = parsedFile.instructions || [];
      
      const hasWorkdir = instructions.some(inst => inst.command === 'WORKDIR');
      
      if (!hasWorkdir) {
        findings.push({
          ruleId: 'DOCKER_WORK_001',
          title: 'Dockerfile should set explicit WORKDIR',
          description: 'BEST PRACTICE: No explicit WORKDIR instruction found. Commands may run in unpredictable directories, affecting build reproducibility.',
          severity: 'LOW',
          resourcePath: 'Dockerfile',
          lineNumber: 1,
          remediation: 'Add WORKDIR instruction: WORKDIR /app (or appropriate working directory)'
        });
      }
      
      return findings;
    }
  },

  {
    id: 'DOCKER_ARG_001',
    title: 'Dockerfile should minimize build arguments',
    description: 'SECURITY: Excessive build arguments may expose sensitive information in image history.',
    severity: 'LOW',
    applicableFileTypes: ['dockerfile'],
    evaluate: (parsedFile) => {
      const findings = [];
      const instructions = parsedFile.instructions || [];
      
      const argInstructions = instructions.filter(inst => inst.command === 'ARG');
      
      if (argInstructions.length > 5) {
        findings.push({
          ruleId: 'DOCKER_ARG_001',
          title: 'Dockerfile should minimize build arguments',
          description: `SECURITY: Dockerfile has ${argInstructions.length} ARG instructions. Excessive build arguments may expose sensitive information in image history.`,
          severity: 'LOW',
          resourcePath: 'Dockerfile',
          lineNumber: argInstructions[0]?.lineNumber || 1,
          remediation: 'Minimize ARG usage, use environment variables at runtime, or use multi-stage builds to reduce exposure'
        });
      }
      
      return findings;
    }
  }
];