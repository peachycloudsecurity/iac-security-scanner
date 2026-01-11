/**
 * GitHub Client - Fetches files from GitHub repositories
 * Only allows public repositories from github.com
 * Includes rate limiting to prevent API abuse
 */

const GITHUB_API_BASE = 'https://api.github.com';
const ALLOWED_DOMAINS = ['github.com', 'www.github.com'];

// Rate limiting configuration
// Unauthenticated: 60 requests/hour
// Authenticated: 5000 requests/hour
// We'll be conservative and use 1 request per 1.5 seconds (40 requests/minute = 2400/hour)
// This gives us good balance between speed and staying under limits
const MIN_REQUEST_INTERVAL = 1500; // 1.5 seconds between requests
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY = 1000; // 1 second

// Rate limit state - reset on each page load
let lastRequestTime = 0;
let rateLimitResetTime = 0;
let rateLimitRemaining = 60; // Conservative default for unauthenticated

/**
 * Reset rate limit state (useful for testing or manual reset)
 */
export function resetRateLimitState() {
  rateLimitResetTime = 0;
  rateLimitRemaining = 60;
  lastRequestTime = 0;
}

/**
 * Get current rate limit status
 */
export function getRateLimitStatus(): { remaining: number; resetTime: Date | null } {
  return {
    remaining: rateLimitRemaining,
    resetTime: rateLimitResetTime > 0 ? new Date(rateLimitResetTime) : null,
  };
}

export interface GitHubFile {
  path: string;
  content: string;
  sha: string;
  size: number;
}

export interface RepoInfo {
  owner: string;
  repo: string;
  defaultBranch: string;
}

/**
 * Validate GitHub URL - only allow public repos from github.com
 */
export function validateGitHubUrl(url: string): { valid: boolean; error?: string; info?: RepoInfo } {
  try {
    const urlObj = new URL(url);
    
    // Only allow https
    if (urlObj.protocol !== 'https:') {
      return { valid: false, error: 'Only HTTPS URLs are allowed' };
    }
    
    // Only allow github.com or www.github.com
    const hostname = urlObj.hostname.toLowerCase();
    if (!ALLOWED_DOMAINS.includes(hostname)) {
      return { valid: false, error: 'Only GitHub.com repositories are allowed' };
    }
    
    // Extract owner and repo from path
    // Format: /owner/repo or /owner/repo/tree/branch
    const pathParts = urlObj.pathname.split('/').filter(p => p);
    
    if (pathParts.length < 2) {
      return { valid: false, error: 'Invalid GitHub URL format. Expected: https://github.com/owner/repo' };
    }
    
    const owner = pathParts[0];
    const repo = pathParts[1];
    
    // Basic validation
    if (!owner || !repo || owner.includes('.') || repo.includes('.')) {
      return { valid: false, error: 'Invalid owner or repository name' };
    }
    
    return {
      valid: true,
      info: {
        owner,
        repo,
        defaultBranch: pathParts[2] === 'tree' && pathParts[3] ? pathParts[3] : 'main', // Default to main
      },
    };
  } catch (error) {
    return { valid: false, error: 'Invalid URL format' };
  }
}

/**
 * Callback type for rate limit confirmation
 */
export type RateLimitHandler = (resetTime: Date, waitMinutes: number) => Promise<boolean>;

// Global rate limit handler
let rateLimitHandler: RateLimitHandler | null = null;

/**
 * Set rate limit handler callback
 */
export function setRateLimitHandler(handler: RateLimitHandler | null) {
  rateLimitHandler = handler;
}

/**
 * Make a rate-limited request to GitHub API
 */
async function makeRateLimitedRequest(
  url: string,
  retryCount: number = 0,
  onProgress?: (message: string) => void
): Promise<Response> {
  const now = Date.now();
  
  // Clear old rate limit reset time if it's in the past (stale data)
  if (rateLimitResetTime > 0 && rateLimitResetTime <= now) {
    rateLimitResetTime = 0;
    rateLimitRemaining = 60; // Reset to default
  }

  // Enforce minimum interval between requests (only for GitHub API calls, not file downloads)
  if (url.includes('api.github.com')) {
    const timeSinceLastRequest = now - lastRequestTime;
    if (timeSinceLastRequest < MIN_REQUEST_INTERVAL && lastRequestTime > 0) {
      const waitTime = MIN_REQUEST_INTERVAL - timeSinceLastRequest;
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }

  // Make the request
  const response = await fetch(url);
  lastRequestTime = Date.now();

  // Update rate limit state from headers (always update from actual response)
  const remaining = response.headers.get('x-ratelimit-remaining');
  const reset = response.headers.get('x-ratelimit-reset');
  
  if (remaining !== null) {
    const remainingInt = parseInt(remaining, 10);
    if (!isNaN(remainingInt)) {
      rateLimitRemaining = remainingInt;
    }
  }
  
  if (reset !== null) {
    const resetTimestamp = parseInt(reset, 10) * 1000; // Convert to milliseconds
    // Always update with latest reset time from GitHub
    if (!isNaN(resetTimestamp) && resetTimestamp > 0) {
      rateLimitResetTime = resetTimestamp;
    }
  }

  // Handle rate limit errors - check response status and headers (like sbomplay)
  if (response.status === 403) {
    // Check if it's actually a rate limit issue by examining headers
    const remaining = response.headers.get('x-ratelimit-remaining');
    const reset = response.headers.get('x-ratelimit-reset');
    const retryAfter = response.headers.get('retry-after');
    
    // It's a rate limit if: remaining is exactly '0' AND we have a reset time
    // This matches sbomplay's logic: if (remaining === '0' && reset)
    const isRateLimit = remaining === '0' && reset !== null;
    
    if (isRateLimit && retryCount < MAX_RETRIES) {
      let waitTime = INITIAL_RETRY_DELAY * Math.pow(2, retryCount); // Exponential backoff
      
      if (retryAfter) {
        waitTime = parseInt(retryAfter, 10) * 1000; // Convert to milliseconds
      } else if (reset && remaining === '0') {
        const resetTimestamp = parseInt(reset, 10) * 1000;
        waitTime = Math.max(resetTimestamp - Date.now(), 60000); // At least 1 minute
      } else {
        waitTime = 60000; // Default to 1 minute
      }
      
      const waitSeconds = Math.ceil(waitTime / 1000);
      const waitMinutes = Math.ceil(waitSeconds / 60);
      const resetDate = reset ? new Date(parseInt(reset, 10) * 1000) : new Date(Date.now() + waitTime);
      
      // Ask user if they want to wait or stop
      let shouldWait = false;
      
      if (rateLimitHandler) {
        try {
          shouldWait = await rateLimitHandler(resetDate, waitMinutes);
        } catch (error) {
          // User cancelled or error - stop the scan
          shouldWait = false;
        }
      } else {
        // No handler - if wait time is more than 5 minutes, throw error
        if (waitSeconds > 300) {
          throw new Error(`GitHub API rate limit exceeded. Rate limit resets at ${resetDate.toLocaleTimeString()}. Please try again later.`);
        }
        // Otherwise auto-wait for short durations
        shouldWait = true;
      }
      
      if (!shouldWait) {
        // User chose to stop
        throw new Error(`Scan stopped. GitHub API rate limit exceeded. Rate limit resets at ${resetDate.toLocaleTimeString()}. Please try again later.`);
      }
      
      // User chose to wait
      const message = `⏳ Rate limit exceeded. Waiting ${waitMinutes} minute${waitMinutes !== 1 ? 's' : ''} (${waitSeconds}s) for reset... (attempt ${retryCount + 1}/${MAX_RETRIES})`;
      console.log(message);
      onProgress?.(message);
      
      // Show progress updates every 10 seconds
      const updateInterval = 10000; // 10 seconds
      const totalUpdates = Math.ceil(waitSeconds / 10);
      
      for (let i = 0; i < totalUpdates; i++) {
        const remaining = Math.max(0, waitSeconds - (i * 10));
        if (remaining > 0) {
          const remainingMinutes = Math.ceil(remaining / 60);
          onProgress?.(`⏳ Waiting for rate limit reset... ${remainingMinutes} minute${remainingMinutes !== 1 ? 's' : ''} remaining`);
          await new Promise(resolve => setTimeout(resolve, Math.min(updateInterval, remaining * 1000)));
        }
      }
      
      onProgress?.('✅ Rate limit reset. Continuing scan...');
      return makeRateLimitedRequest(url, retryCount + 1, onProgress);
    } else if (isRateLimit) {
      // Rate limit but max retries reached
      const resetDate = reset ? new Date(parseInt(reset, 10) * 1000) : new Date();
      throw new Error(`Rate limit exceeded. Please try again later. Reset time: ${resetDate.toLocaleTimeString()}`);
    } else {
      // 403 but not rate limit - access denied
      throw new Error('Access denied (403). Repository might be private or require authentication.');
    }
  }
  
  // Handle 429 Too Many Requests
  if (response.status === 429) {
    const retryAfter = response.headers.get('retry-after');
    const reset = response.headers.get('x-ratelimit-reset');
    
    if (retryCount < MAX_RETRIES) {
      let waitTime = INITIAL_RETRY_DELAY * Math.pow(2, retryCount);
      
      if (retryAfter) {
        waitTime = parseInt(retryAfter, 10) * 1000;
      } else if (reset) {
        const resetTimestamp = parseInt(reset, 10) * 1000;
        waitTime = Math.max(resetTimestamp - Date.now(), 60000);
      } else {
        waitTime = 60000;
      }
      
      const waitSeconds = Math.ceil(waitTime / 1000);
      
      if (waitSeconds > 300) {
        const resetDate = reset ? new Date(parseInt(reset, 10) * 1000) : new Date(Date.now() + waitTime);
        throw new Error(`GitHub API rate limit exceeded. Rate limit resets at ${resetDate.toLocaleTimeString()}. Please try again later.`);
      }
      
      onProgress?.(`⏳ Rate limit exceeded (429). Waiting ${Math.ceil(waitSeconds / 60)} minutes...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      
      return makeRateLimitedRequest(url, retryCount + 1, onProgress);
    } else {
      throw new Error('Rate limit exceeded. Maximum retries reached. Please try again later.');
    }
  }

  // Check if we're running low on rate limit
  if (rateLimitRemaining <= 5 && rateLimitRemaining > 0) {
    console.warn(`⚠️ Rate limit running low: ${rateLimitRemaining} requests remaining`);
  }

  return response;
}

/**
 * Get repository default branch
 */
async function getDefaultBranch(owner: string, repo: string, onProgress?: (message: string) => void): Promise<string> {
  try {
    const url = `${GITHUB_API_BASE}/repos/${owner}/${repo}`;
    const response = await makeRateLimitedRequest(url, 0, onProgress);
    
    if (!response.ok) {
      // Check response body for more details
      let errorDetails = '';
      try {
        const errorData = await response.json();
        if (errorData.message) {
          errorDetails = errorData.message;
        }
      } catch {
        // Ignore JSON parse errors
      }
      
      if (response.status === 404) {
        throw new Error('Repository not found or is private');
      }
      if (response.status === 403) {
        // makeRateLimitedRequest already handles rate limits, so this is likely access denied
        if (errorDetails.includes('rate limit') || errorDetails.includes('API rate limit')) {
          throw new Error('GitHub API rate limit exceeded. Please wait a few minutes and try again.');
        }
        throw new Error(`Access denied (403). ${errorDetails || 'Repository might be private or require authentication.'}`);
      }
      throw new Error(`Failed to fetch repository: ${response.status} ${errorDetails || ''}`);
    }
    
    const data = await response.json();
    
    // Check if repository is public
    if (data.private) {
      throw new Error('Private repositories are not supported');
    }
    
    return data.default_branch || 'main';
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }
    throw new Error('Failed to fetch repository information');
  }
}

// Global flag to stop scanning on rate limit
let rateLimitHit = false;

/**
 * Get file tree recursively from GitHub repository
 */
async function getFileTree(
  owner: string,
  repo: string,
  branch: string,
  path: string = '',
  onProgress?: (current: number, total: number, currentFile?: string) => void,
  progressState?: { directoriesScanned: number; filesFound: number; filesFetched: number },
  onStatusUpdate?: (message: string) => void
): Promise<GitHubFile[]> {
  const files: GitHubFile[] = [];
  const state = progressState || { directoriesScanned: 0, filesFound: 0, filesFetched: 0 };
  
  // Stop if rate limit was hit
  if (rateLimitHit) {
    return files;
  }
  
  try {
    const url = `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}?ref=${branch}`;
    onProgress?.(state.directoriesScanned, state.directoriesScanned + 1, `Scanning: ${path || 'root'}`);
    const response = await makeRateLimitedRequest(url, 0, onStatusUpdate);
    state.directoriesScanned++;
    
    if (!response.ok) {
      if (response.status === 404) {
        return files; // Path doesn't exist, return empty
      }
      if (response.status === 403 || response.status === 429) {
        // Check if it's rate limit
        const remaining = response.headers.get('x-ratelimit-remaining');
        const reset = response.headers.get('x-ratelimit-reset');
        if (remaining === '0' && reset) {
          rateLimitHit = true; // Set flag to stop further requests
          const resetDate = new Date(parseInt(reset, 10) * 1000);
          throw new Error(`GitHub API rate limit exceeded. Rate limit resets at ${resetDate.toLocaleTimeString()}. Please try again later.`);
        }
        throw new Error('Access denied. Repository might be private or rate limited.');
      }
      throw new Error(`Failed to fetch contents: ${response.status}`);
    }
    
    const items = await response.json();
    
    // Handle single file response
    if (!Array.isArray(items)) {
      if (items.type === 'file') {
        // Check if it's a text file we can process
        if (items.size > 0 && items.size < 10 * 1024 * 1024) { // Max 10MB
          if (isIaCFile(items.path)) {
            state.filesFound++;
            onProgress?.(state.filesFetched, state.filesFound, `Fetching: ${items.path}`);
            try {
              const content = await fetchFileContent(items.download_url);
              if (content) {
                files.push({
                  path: items.path,
                  content,
                  sha: items.sha,
                  size: items.size,
                });
                state.filesFetched++;
                onProgress?.(state.filesFetched, state.filesFound, `✓ ${items.path}`);
              }
            } catch (error) {
              console.warn(`Failed to fetch content for ${items.path}:`, error);
            }
          }
        }
      }
      return files;
    }
    
    // Process directory items with rate limiting
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      
      if (item.type === 'file') {
        // Check if it's an IaC file type
        if (isIaCFile(item.path)) {
          state.filesFound++;
          // Check file size (max 1MB per file for performance)
          if (item.size > 0 && item.size < 1024 * 1024) {
            onProgress?.(state.filesFetched, state.filesFound, `Downloading: ${item.path} (${i + 1}/${items.length})`);
            try {
              const content = await fetchFileContent(item.download_url);
              if (content) {
                files.push({
                  path: item.path,
                  content,
                  sha: item.sha,
                  size: item.size,
                });
                state.filesFetched++;
                onProgress?.(state.filesFetched, state.filesFound, `✓ ${item.path}`);
              }
            } catch (error) {
              console.warn(`Failed to fetch content for ${item.path}:`, error);
            }
          } else {
            onProgress?.(state.filesFetched, state.filesFound, `Skipping large file: ${item.path}`);
          }
        }
      } else if (item.type === 'dir') {
        // Recursively fetch directory contents
        // Skip common non-IaC directories for performance
        if (!shouldSkipDirectory(item.path)) {
          // Stop if rate limit was hit
          if (rateLimitHit) {
            break;
          }
          
          onProgress?.(state.directoriesScanned, state.directoriesScanned + 1, `Exploring: ${item.path}`);
          // Add delay before recursive call to avoid rate limits
          await new Promise(resolve => setTimeout(resolve, 200)); // Increased to 200ms
          try {
            const subFiles = await getFileTree(owner, repo, branch, item.path, onProgress, state, onStatusUpdate);
            files.push(...subFiles);
          } catch (error) {
            // If rate limit hit, stop processing
            if (error instanceof Error && error.message.includes('rate limit')) {
              rateLimitHit = true;
              throw error; // Re-throw to stop entire scan
            }
            console.warn(`Error fetching subdirectory ${item.path}:`, error);
            // Continue with other directories
          }
        }
      }
    }
  } catch (error) {
    // Re-throw rate limit errors to stop the scan
    if (error instanceof Error && error.message.includes('rate limit')) {
      throw error;
    }
    console.error(`Error fetching tree for ${path}:`, error);
  }
  
  return files;
}

/**
 * Fetch file content from download URL
 * Note: download_url points to raw.githubusercontent.com which has different rate limits
 * We'll still add a small delay to be safe
 */
async function fetchFileContent(downloadUrl: string): Promise<string | null> {
  try {
    // Small delay to avoid hammering raw.githubusercontent.com
    const timeSinceLastRequest = Date.now() - lastRequestTime;
    if (timeSinceLastRequest < 500) { // 500ms minimum between file content requests
      await new Promise(resolve => setTimeout(resolve, 500 - timeSinceLastRequest));
    }
    
    const response = await fetch(downloadUrl);
    lastRequestTime = Date.now();
    
    if (!response.ok) {
      if (response.status === 403 || response.status === 429) {
        // Rate limited - wait a bit and retry once
        await new Promise(resolve => setTimeout(resolve, 2000));
        const retryResponse = await fetch(downloadUrl);
        if (!retryResponse.ok) {
          return null;
        }
        return await retryResponse.text();
      }
      return null;
    }
    return await response.text();
  } catch (error) {
    console.error('Failed to fetch file content:', error);
    return null;
  }
}

/**
 * Check if file is an IaC file type
 */
function isIaCFile(path: string): boolean {
  const lowerPath = path.toLowerCase();
  const extension = lowerPath.split('.').pop() || '';
  
  // Terraform files
  if (extension === 'tf' || extension === 'hcl' || lowerPath.endsWith('.tf.json')) {
    return true;
  }
  
  // Docker files
  if (lowerPath === 'dockerfile' || lowerPath.startsWith('dockerfile.') || 
      lowerPath.includes('docker-compose') && (extension === 'yaml' || extension === 'yml')) {
    return true;
  }
  
  // Kubernetes files
  if (extension === 'yaml' || extension === 'yml') {
    return true; // Will be filtered by content later
  }
  
  // CloudFormation files
  if (extension === 'template' || (extension === 'json' && lowerPath.includes('cloudformation'))) {
    return true;
  }
  
  // JSON files (might be CloudFormation)
  if (extension === 'json') {
    return true;
  }
  
  return false;
}

/**
 * Check if directory should be skipped
 */
function shouldSkipDirectory(path: string): boolean {
  const lowerPath = path.toLowerCase();
  const skipPatterns = [
    'node_modules',
    '.git',
    'vendor',
    'dist',
    'build',
    '.next',
    '.cache',
    'coverage',
    '.idea',
    '.vscode',
    'target',
    'bin',
    'obj',
    '.terraform',
    '.terraform.lock.hcl',
  ];
  
  return skipPatterns.some(pattern => lowerPath.includes(pattern));
}

/**
 * Fetch all IaC files from a GitHub repository
 */
export async function fetchGitHubRepoFiles(
  owner: string,
  repo: string,
  branch?: string,
  onProgress?: (current: number, total: number, currentFile?: string) => void,
  onStatusUpdate?: (message: string) => void
): Promise<{ files: GitHubFile[]; branch: string }> {
  // Reset rate limit flag
  rateLimitHit = false;
  
  // Get default branch if not provided
  onProgress?.(0, 100, 'Connecting to GitHub...');
  const defaultBranch = branch || await getDefaultBranch(owner, repo, onStatusUpdate);
  
  onProgress?.(1, 100, 'Scanning repository structure...');
  
  // Fetch all files with progress tracking
  const files = await getFileTree(owner, repo, defaultBranch, '', onProgress, undefined, onStatusUpdate);
  
  onProgress?.(files.length, files.length, `✓ Found ${files.length} IaC files`);
  
  return { files, branch: defaultBranch };
}
