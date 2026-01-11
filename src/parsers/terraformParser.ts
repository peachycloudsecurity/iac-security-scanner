// Simple HCL-like parser for Terraform files
// This is a lightweight parser that extracts resource blocks

interface TerraformBlock {
  type: string;
  resourceType?: string;
  name: string;
  attributes: Record<string, unknown>;
  startLine: number;
  endLine: number;
}

interface TerraformParsed {
  blocks: TerraformBlock[];
  raw: string;
}

export function parseTerraform(content: string): TerraformParsed {
  const blocks: TerraformBlock[] = [];
  const lines = content.split('\n');
  
  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();
    
    // Skip empty lines and comments
    if (line === '' || line.startsWith('#')) {
      i++;
      continue;
    }
    
    // Match block starts: resource "type" "name" {, provider "name" {, etc.
    // More flexible matching to handle various formats
    const resourceMatch = line.match(/^(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{?\s*$/);
    const simpleBlockMatch = line.match(/^(provider|variable|output|module|terraform|locals)\s+"?([^"\s{]+)"?\s*\{?\s*$/);
    
    if (resourceMatch) {
      const [, blockType, resourceType, name] = resourceMatch;
      const block = extractBlock(lines, i, blockType, name, resourceType);
      blocks.push(block);
      i = block.endLine + 1;
    } else if (simpleBlockMatch) {
      const [, blockType, name] = simpleBlockMatch;
      const block = extractBlock(lines, i, blockType, name);
      blocks.push(block);
      i = block.endLine + 1;
    } else {
      i++;
    }
  }
  
  return { blocks, raw: content };
}

// Parse IAM policy content from jsonencode block using regex (best-effort, non-JSON)
function parseJsonencodeBlock(raw: string): Record<string, unknown> | null {
  return parseIamPolicyFromJsonencode(raw);
}

// Helper function to extract Statement array content with proper bracket matching
function extractStatementArray(raw: string): string | null {
  const stmtIdx = raw.indexOf('Statement');
  if (stmtIdx === -1) return null;

  const arrayStart = raw.indexOf('[', stmtIdx);
  if (arrayStart === -1) return null;

  let depth = 0;
  let collected = '';

  for (let i = arrayStart; i < raw.length; i++) {
    const ch = raw[i];

    if (ch === '[') depth++;
    if (ch === ']') depth--;

    if (depth > 0) collected += ch;

    if (depth === 0 && collected) {
      return collected;
    }
  }

  return null;
}

// Extract IAM policy semantics (Effect, Action, Resource) from jsonencode(...) content
function parseIamPolicyFromJsonencode(raw: string): { Statement: any[] } {
  const statements: any[] = [];

  const statementBody = extractStatementArray(raw);
  
  if (!statementBody) {
    return { Statement: [] };
  }

  const blocks = statementBody.match(/\{[\s\S]*?\}/g);
  
  if (!blocks) {
    return { Statement: [] };
  }

  for (const block of blocks) {
    const stmt: any = {};

    const effect = block.match(/Effect\s*=\s*"([^"]+)"/);
    if (effect) {
      stmt.Effect = effect[1];
    }

    const actionMatch = block.match(/Action\s*=\s*(\[[\s\S]*?\]|"[^"]+")/);
    if (actionMatch) {
      stmt.Action = actionMatch[1]
        .replace(/[\[\]"]/g, '')
        .split(/\s*,\s*|\n/)
        .map(a => a.trim())
        .filter(Boolean);
    }

    const resourceMatch = block.match(/Resource\s*=\s*(\[[\s\S]*?\]|"[^"]+")/);
    if (resourceMatch) {
      stmt.Resource = resourceMatch[1]
        .replace(/[\[\]"]/g, '')
        .split(/\s*,\s*|\n/)
        .map(r => r.trim())
        .filter(Boolean);
    }

    const passRoleCond = block.match(/iam:PassedToService\s*=\s*"([^"]+)"/);
    if (passRoleCond) {
      stmt.Condition = {
        StringEquals: { 'iam:PassedToService': passRoleCond[1] }
      };
    }

    if (stmt.Effect && stmt.Action) {
      statements.push(stmt);
    }
  }
  return { Statement: statements };
}

function extractBlock(
  lines: string[],
  startLine: number,
  type: string,
  name: string,
  resourceType?: string
): TerraformBlock {
  let braceCount = 0;
  let endLine = startLine;
  const contentLines: string[] = [];
  
  for (let i = startLine; i < lines.length; i++) {
    const line = lines[i];
    contentLines.push(line);
    
    // Count braces
    for (const char of line) {
      if (char === '{') braceCount++;
      if (char === '}') braceCount--;
    }
    
    endLine = i;
    
    if (braceCount === 0 && i > startLine) {
      break;
    }
  }
  
  // Extract simple key-value attributes
  const attributes = extractAttributes(contentLines.slice(1, -1));
  
  return {
    type,
    resourceType,
    name,
    attributes,
    startLine: startLine + 1, // 1-indexed
    endLine: endLine + 1,
  };
}

function extractAttributes(lines: string[]): Record<string, unknown> {
  const attrs: Record<string, unknown> = {};
  
  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();
    
    // Skip empty lines and comments
    if (line === '' || line.startsWith('#')) {
      i++;
      continue;
    }
    
    // Simple key = value
    const simpleMatch = line.match(/^(\w+)\s*=\s*(.+)$/);
    if (simpleMatch) {
      const [, key, value] = simpleMatch;
      const trimmedValue = value.trim();
      
      // Check for jsonencode() function
      if (trimmedValue.includes('jsonencode(')) {
        // Extract content inside jsonencode - collect all content until closing paren
        let fullContent = '';
        let foundJsonEncode = false;
        let completed = false;
        let maxLines = 200;
        
        for (let j = i; j < lines.length && maxLines > 0; j++, maxLines--) {
          const lineRaw = lines[j];
          
          if (!foundJsonEncode && lineRaw.includes('jsonencode(')) {
            foundJsonEncode = true;
            // Get everything after jsonencode(
            const startIdx = lineRaw.indexOf('jsonencode(') + 'jsonencode('.length;
            fullContent = lineRaw.substring(startIdx);
          } else if (foundJsonEncode) {
            fullContent += '\n' + lineRaw;
          }
          
          // Check if we have a complete jsonencode block by counting parens
          if (foundJsonEncode) {
            let parenCount = 1; // Start with 1 for the opening paren
            let lastParenIndex = -1;
            
            for (let k = 0; k < fullContent.length; k++) {
              const ch = fullContent[k];
              if (ch === '(') parenCount++;
              if (ch === ')') {
                parenCount--;
                lastParenIndex = k;
                if (parenCount === 0) break;
              }
            }
            
            if (parenCount === 0 && lastParenIndex !== -1) {
              // Extract content before the closing paren
              const inner = fullContent.substring(0, lastParenIndex).trim();
              
              const parsed = parseJsonencodeBlock(inner);
              
              if (parsed !== null) {
                attrs[key] = parsed;
              } else {
                attrs[key] = extractPolicyFromRaw(inner);
              }
              i = j + 1;
              completed = true;
              break;
            }
          }
        }
        if (!completed) {
          attrs[key] = parseValue(value);
          i++;
        }
      } else {
        attrs[key] = parseValue(value);
        i++;
      }
    } else {
      // Nested block detection
      const nestedMatch = line.match(/^(\w+)\s*\{/);
      if (nestedMatch) {
        const [, key] = nestedMatch;
        if (!attrs[key]) {
          attrs[key] = { _isBlock: true };
        }
      }
      i++;
    }
  }
  
  return attrs;
}

// Convert HCL-like syntax to JSON object (simplified version)
function convertHclToJson(hclContent: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = hclContent.split('\n');
  
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    // Check for multi-line arrays first: key = [
    const arrayStartMatch = trimmed.match(/^(\w+)\s*=\s*\[(.*)$/);
    if (arrayStartMatch) {
      const [, key, restOfLine] = arrayStartMatch;
      
      // Check if array closes on same line
      if (restOfLine.trim().endsWith(']')) {
        const arrayContent = restOfLine.substring(0, restOfLine.lastIndexOf(']'));
        const items = arrayContent.split(',').map(item => parseHclValue(item.trim())).filter(Boolean);
        result[key] = items;
        continue;
      }
      
      // Multi-line array - need to parse objects
      const items: unknown[] = [];
      let bracketCount = 1;
      let inObject = false;
      let objectContent = '';
      let objectBraceCount = 0;
      
      // Check rest of first line
      if (restOfLine.trim()) {
        const firstLineTrimmed = restOfLine.trim();
        if (firstLineTrimmed.startsWith('{')) {
          inObject = true;
          objectContent = firstLineTrimmed + '\n';
          objectBraceCount = (firstLineTrimmed.match(/\{/g) || []).length - (firstLineTrimmed.match(/\}/g) || []).length;
        }
      }
      
      for (let j = idx + 1; j < lines.length && bracketCount > 0; j++) {
        const arrayLine = lines[j];
        const arrayLineTrimmed = arrayLine.trim();
        
        if (arrayLineTrimmed === ']' || (arrayLineTrimmed.endsWith(']') && !arrayLineTrimmed.startsWith('}'))) {
          if (inObject && objectContent) {
            // Save pending object - parse line by line
            const contentToParse = objectContent.replace(/^\s*\{\s*\n?/, '').replace(/\}\s*,?\s*\n?$/, '').trim();
            try {
              const obj = parseObjectLines(contentToParse);
              if (Object.keys(obj).length > 0) {
                items.push(obj);
              }
            } catch (err) {
              console.error('Failed to parse object:', contentToParse, err);
            }
            inObject = false;
            objectContent = '';
          }
          bracketCount--;
          if (bracketCount === 0) {
            idx = j;
            break;
          }
          continue;
        }
        
        if (arrayLineTrimmed.startsWith('{')) {
          if (inObject && objectContent) {
            // Save previous object
            const contentToParse = objectContent.replace(/^\s*\{\s*\n?/, '').replace(/\}\s*,?\s*\n?$/, '').trim();
            try {
              const obj = parseObjectLines(contentToParse);
              if (Object.keys(obj).length > 0) {
                items.push(obj);
              }
            } catch (err) {
              console.error('Failed to parse previous object:', contentToParse, err);
            }
          }
          inObject = true;
          objectContent = arrayLine + '\n';
          objectBraceCount = (arrayLine.match(/\{/g) || []).length - (arrayLine.match(/\}/g) || []).length;
        } else if (arrayLineTrimmed.endsWith('}') && inObject) {
          objectContent += arrayLine + '\n';
          objectBraceCount += (arrayLine.match(/\{/g) || []).length - (arrayLine.match(/\}/g) || []).length;
          
          if (objectBraceCount === 0) {
            // Object complete - parse line by line
            const contentToParse = objectContent.replace(/^\s*\{\s*\n?/, '').replace(/\}\s*,?\s*\n?$/, '').trim();
            try {
              const obj = parseObjectLines(contentToParse);
              if (Object.keys(obj).length > 0) {
                items.push(obj);
              }
            } catch (err) {
              console.error('Failed to parse complete object:', contentToParse, err);
            }
            inObject = false;
            objectContent = '';
          }
        } else if (inObject) {
          objectContent += arrayLine + '\n';
          objectBraceCount += (arrayLine.match(/\{/g) || []).length - (arrayLine.match(/\}/g) || []).length;
          
          // Check if object closed mid-line
          if (objectBraceCount === 0) {
            const contentToParse = objectContent.replace(/^\s*\{\s*\n?/, '').replace(/\}\s*,?\s*\n?$/, '').trim();
            try {
              const obj = parseObjectLines(contentToParse);
              if (Object.keys(obj).length > 0) {
                items.push(obj);
              }
            } catch (err) {
              console.error('Failed to parse mid-line object:', contentToParse, err);
            }
            inObject = false;
            objectContent = '';
          }
        } else if (arrayLineTrimmed && !arrayLineTrimmed.startsWith('#') && arrayLineTrimmed !== ',') {
          // Simple value
          const cleanLine = arrayLineTrimmed.replace(/,$/,'');
          const val = parseHclValue(cleanLine);
          if (val !== null && val !== undefined && val !== '') {
            items.push(val);
          }
        }
      }
      result[key] = items;
      continue;
    }
    
    // Match key = value patterns (simple values)
    const keyValueMatch = trimmed.match(/^(\w+)\s*=\s*(.+)$/);
    if (keyValueMatch) {
      const [, key, value] = keyValueMatch;
      // Make sure it's not an array start
      if (!value.trim().startsWith('[')) {
        const parsedValue = parseHclValue(value.trim());
        result[key] = parsedValue;
      }
      continue;
    }
    
    // Match nested objects: key = { ... }
    const objectMatch = trimmed.match(/^(\w+)\s*=\s*\{/);
    if (objectMatch) {
      const [, key] = objectMatch;
      // Extract nested object content
      let nestedContent = '';
      let braceCount = 1;
      let found = false;
      
      for (let j = idx + 1; j < lines.length && braceCount > 0; j++) {
        const nestedLine = lines[j];
        nestedContent += nestedLine + '\n';
        for (const char of nestedLine) {
          if (char === '{') braceCount++;
          if (char === '}') braceCount--;
        }
        if (braceCount === 0) {
          nestedContent = nestedContent.slice(0, -1); // Remove last newline
          found = true;
          idx = j; // Skip processed lines
          break;
        }
      }
      
      if (found) {
        result[key] = convertHclToJson(nestedContent);
      }
    }
  }
  
  return result;
}

function parseHclValue(value: string): unknown {
  // Remove quotes
  if ((value.startsWith('"') && value.endsWith('"')) || 
      (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  
  // Boolean
  if (value === 'true') return true;
  if (value === 'false') return false;
  
  // Number
  if (/^\d+$/.test(value)) return parseInt(value, 10);
  if (/^\d+\.\d+$/.test(value)) return parseFloat(value);
  
  // Variable reference (keep as string)
  if (value.startsWith('var.') || value.startsWith('aws_')) {
    return value;
  }
  
  return value;
}

// Parse object content line by line without recursion to avoid issues
function parseObjectLines(content: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = content.split('\n');
  
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      i++;
      continue;
    }
    
    // Handle arrays: key = [...]
    const arrayMatch = trimmed.match(/^(\w+)\s*=\s*\[(.*)$/);
    if (arrayMatch) {
      const [, key, restOfLine] = arrayMatch;
      
      // Check if array closes on same line
      if (restOfLine.includes(']')) {
        const closeBracketIndex = restOfLine.indexOf(']');
        const arrayContent = restOfLine.substring(0, closeBracketIndex);
        const items = arrayContent.split(',').map(item => parseHclValue(item.trim())).filter(Boolean);
        result[key] = items;
        i++;
        continue;
      }
      
      // Multi-line array
      const items: unknown[] = [];
      for (let j = i + 1; j < lines.length; j++) {
        const arrayLine = lines[j].trim();
        if (arrayLine === ']' || arrayLine.endsWith(']')) {
          i = j + 1;
          break;
        }
        if (arrayLine && !arrayLine.startsWith('#') && arrayLine !== ',') {
          const cleanLine = arrayLine.replace(/,$/,'');
          const val = parseHclValue(cleanLine);
          if (val) items.push(val);
        }
      }
      result[key] = items;
      continue;
    }
    
    // Handle simple key = value
    const keyValueMatch = trimmed.match(/^(\w+)\s*=\s*(.+)$/);
    if (keyValueMatch) {
      const [, key, value] = keyValueMatch;
      if (!value.startsWith('[') && !value.startsWith('{')) {
        result[key] = parseHclValue(value.trim());
      }
    }
    
    i++;
  }
  
  return result;
}

// Extract policy from raw HCL content when JSON parsing fails
function extractPolicyFromRaw(raw: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  
  // Extract Version
  const versionMatch = raw.match(/Version\s*=\s*"([^"]+)"/);
  if (versionMatch) {
    result.Version = versionMatch[1];
  }
  
  // Extract Statement array - handle multi-line
  const statementStart = raw.indexOf('Statement');
  if (statementStart !== -1) {
    const statements: unknown[] = [];
    const afterStatement = raw.substring(statementStart);
    
    // Find all statement blocks { ... }
    let braceDepth = 0;
    let inStatement = false;
    let currentStatement = '';
    
    for (let i = 0; i < afterStatement.length; i++) {
      const char = afterStatement[i];
      
      if (char === '{') {
        if (braceDepth === 0) {
          inStatement = true;
          currentStatement = '';
        }
        braceDepth++;
        if (inStatement) currentStatement += char;
      } else if (char === '}') {
        if (inStatement) currentStatement += char;
        braceDepth--;
        if (braceDepth === 0 && inStatement) {
          // Complete statement found
          const stmt = parseStatementBlock(currentStatement);
          if (stmt && Object.keys(stmt).length > 0) {
            statements.push(stmt);
          }
          inStatement = false;
          currentStatement = '';
        }
      } else if (inStatement) {
        currentStatement += char;
      }
    }
    
    if (statements.length > 0) {
      result.Statement = statements;
    }
  }
  
  return result;
}

// Parse a single statement block from HCL
function parseStatementBlock(block: string): Record<string, unknown> | null {
  const stmt: Record<string, unknown> = {};
  
  // Extract Action
  const actionMatch = block.match(/Action\s*=\s*\[([^\]]+)\]/s);
  if (actionMatch) {
    const actionsStr = actionMatch[1];
    const actions = actionsStr
      .split(',')
      .map(a => a.trim().replace(/^"|"$/g, ''))
      .filter(a => a);
    stmt.Action = actions.length === 1 ? actions[0] : actions;
  }
  
  // Extract Effect
  const effectMatch = block.match(/Effect\s*=\s*"([^"]+)"/);
  if (effectMatch) {
    stmt.Effect = effectMatch[1];
  }
  
  // Extract Resource
  const resourceMatch = block.match(/Resource\s*=\s*"([^"]+)"/);
  if (resourceMatch) {
    stmt.Resource = resourceMatch[1];
  }
  
  // Extract Condition
  const conditionMatch = block.match(/Condition\s*=\s*\{/);
  if (conditionMatch) {
    // Simple condition extraction
    const condition: Record<string, unknown> = {};
    const stringEqualsMatch = block.match(/StringEquals\s*=\s*\{[^}]*\}/);
    if (stringEqualsMatch) {
      condition.StringEquals = {};
    }
    if (Object.keys(condition).length > 0) {
      stmt.Condition = condition;
    }
  }
  
  return Object.keys(stmt).length > 0 ? stmt : null;
}

function parseValue(value: string): unknown {
  const trimmed = value.trim();
  
  // Boolean
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  
  // Number
  if (/^\d+$/.test(trimmed)) return parseInt(trimmed, 10);
  if (/^\d+\.\d+$/.test(trimmed)) return parseFloat(trimmed);
  
  // String (remove quotes)
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  
  // List
  if (trimmed.startsWith('[')) {
    // Simple list parsing
    const listContent = trimmed.slice(1, -1);
    if (listContent.trim() === '') return [];
    return listContent.split(',').map(item => parseValue(item.trim()));
  }
  
  return trimmed;
}
