import { describe, it, expect, vi, beforeEach } from 'vitest';
import { registerPackRemoteRepositoryPrompt } from '../../../src/mcp/prompts/packRemoteRepositoryPrompts.js';

describe('packRemoteRepositoryPrompts', () => {
  const mockMcpServer = {
    prompt: vi.fn(),
  };
  
  let promptHandler: Function;
  
  beforeEach(() => {
    vi.resetAllMocks();
    
    registerPackRemoteRepositoryPrompt(mockMcpServer as any);
    
    promptHandler = mockMcpServer.prompt.mock.calls[0][3];
  });
  
  it('should register the prompt with correct parameters', () => {
    expect(mockMcpServer.prompt).toHaveBeenCalledWith(
      'pack_remote_repository',
      expect.any(String),
      expect.objectContaining({
        repository: expect.any(Object),
        includePatterns: expect.any(Object),
        ignorePatterns: expect.any(Object),
      }),
      expect.any(Function),
    );
  });
  
  it('should generate a prompt with repository only', async () => {
    const result = await promptHandler({ repository: 'user/repo' });
    
    expect(result).toHaveProperty('messages');
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0].role).toBe('user');
    expect(result.messages[0].content.type).toBe('text');
    expect(result.messages[0].content.text).toContain('Please analyze the GitHub repository at user/repo');
    expect(result.messages[0].content.text).toContain('- repository: "user/repo"');
    expect(result.messages[0].content.text).not.toContain('- includePatterns:');
    expect(result.messages[0].content.text).not.toContain('- ignorePatterns:');
  });
  
  it('should include includePatterns when provided', async () => {
    const result = await promptHandler({ 
      repository: 'user/repo',
      includePatterns: 'src/**,lib/**'
    });
    
    expect(result.messages[0].content.text).toContain('- includePatterns: "src/**,lib/**"');
    expect(result.messages[0].content.text).not.toContain('- ignorePatterns:');
  });
  
  it('should include ignorePatterns when provided', async () => {
    const result = await promptHandler({ 
      repository: 'user/repo',
      ignorePatterns: '**/*.test.js,**/*.spec.js'
    });
    
    expect(result.messages[0].content.text).toContain('- ignorePatterns: "**/*.test.js,**/*.spec.js"');
    expect(result.messages[0].content.text).not.toContain('- includePatterns:');
  });
  
  it('should include both patterns when provided', async () => {
    const result = await promptHandler({ 
      repository: 'user/repo',
      includePatterns: 'src/**,lib/**',
      ignorePatterns: '**/*.test.js,**/*.spec.js'
    });
    
    expect(result.messages[0].content.text).toContain('- includePatterns: "src/**,lib/**"');
    expect(result.messages[0].content.text).toContain('- ignorePatterns: "**/*.test.js,**/*.spec.js"');
  });
});
