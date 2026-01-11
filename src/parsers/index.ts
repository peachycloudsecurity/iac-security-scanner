import { FileType, ParsedFile } from '@/types/scanner';
import { parseYaml, parseMultiDocYaml } from './yamlParser';
import { parseJson } from './jsonParser';
import { parseTerraform } from './terraformParser';
import { parseDockerfile } from './dockerfileParser';

export function parseFile(fileName: string, content: string, fileType: FileType): ParsedFile {
  const lines = content.split('\n');
  let parsed: unknown;
  
  try {
    switch (fileType) {
      case 'terraform':
        parsed = parseTerraform(content);
        break;
      case 'json':
        parsed = parseJson(content);
        break;
      case 'yaml':
      case 'docker-compose':
        parsed = parseYaml(content);
        break;
      case 'kubernetes':
        parsed = parseMultiDocYaml(content);
        break;
      case 'cloudformation':
        // CloudFormation can be JSON or YAML format
        const trimmed = content.trim();
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
          parsed = parseJson(content);
        } else {
          // Suppress YAML warnings for CloudFormation intrinsic functions
          parsed = parseYaml(content, true);
        }
        break;
      case 'dockerfile':
        parsed = parseDockerfile(content);
        break;
      default:
        parsed = { raw: content };
    }
  } catch (error) {
    throw new Error(`Failed to parse ${fileType} file: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
  
  return {
    fileName,
    fileType,
    content,
    parsed,
    lines,
  };
}
