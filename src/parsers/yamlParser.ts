import * as yaml from 'yaml';

export function parseYaml(content: string, suppressWarnings = false): unknown {
  try {
    if (suppressWarnings) {
      // For CloudFormation, suppress YAML warnings for intrinsic functions (!Ref, !GetAtt, etc.)
      const originalWarn = console.warn;
      console.warn = () => {}; // Suppress warnings temporarily
      try {
        const doc = yaml.parseDocument(content);
        return doc.toJS();
      } finally {
        console.warn = originalWarn; // Restore original
      }
    }
    return yaml.parse(content);
  } catch (error) {
    throw new Error(`YAML parsing error: ${error instanceof Error ? error.message : 'Invalid YAML'}`);
  }
}

export function parseMultiDocYaml(content: string): unknown[] {
  try {
    const documents = yaml.parseAllDocuments(content);
    return documents.map(doc => {
      if (doc.errors.length > 0) {
        throw new Error(doc.errors.map(e => e.message).join(', '));
      }
      return doc.toJSON();
    }).filter(Boolean);
  } catch (error) {
    throw new Error(`YAML parsing error: ${error instanceof Error ? error.message : 'Invalid YAML'}`);
  }
}
