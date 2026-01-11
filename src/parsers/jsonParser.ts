export function parseJson(content: string): unknown {
  try {
    return JSON.parse(content);
  } catch (error) {
    throw new Error(`JSON parsing error: ${error instanceof Error ? error.message : 'Invalid JSON'}`);
  }
}
