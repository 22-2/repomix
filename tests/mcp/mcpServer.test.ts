import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { getVersion } from '../../src/core/file/packageJsonParse.js';
import { createMcpServer, runMcpServer } from '../../src/mcp/mcpServer.js';
import { logger } from '../../src/shared/logger.js';

// Mock dependencies
vi.mock('@modelcontextprotocol/sdk/server/mcp.js');
vi.mock('@modelcontextprotocol/sdk/server/stdio.js');
vi.mock('../../src/core/file/packageJsonParse.js');
vi.mock('../../src/shared/logger.js');

describe('MCP Server', () => {
  let mockExit: ReturnType<typeof vi.fn<(code?: number) => never>>;
  const mockVersion = '1.0.0';

  const mockLogger = {
    trace: vi.fn(),
    error: vi.fn(),
  };

  beforeEach(async () => {
    vi.resetAllMocks();
    mockExit = vi.fn();
    vi.mocked(getVersion).mockResolvedValue(mockVersion);

    // ロガーのモックを設定
    vi.mocked(logger.trace).mockImplementation(mockLogger.trace);
    vi.mocked(logger.error).mockImplementation(mockLogger.error);
  });

  describe('createMcpServer', () => {
    test('should create server with correct configuration', async () => {
      const server = await createMcpServer();

      expect(McpServer).toHaveBeenCalledWith({
        name: 'repomix-mcp-server',
        version: mockVersion,
      });
      expect(server).toBeDefined();
    });
  });

  describe('runMcpServer', () => {
    test('should connect server with stdio transport', async () => {
      await expect(runMcpServer({ processExit: mockExit })).resolves.toBeUndefined();

      expect(StdioServerTransport).toHaveBeenCalled();
      expect(vi.mocked(McpServer).mock.results[0].value.connect).toHaveBeenCalledWith(
        vi.mocked(StdioServerTransport).mock.results[0].value,
      );
      expect(logger.trace).toHaveBeenCalledWith('Repomix MCP Server running on stdio');
    });

    test('should handle connection error', async () => {
      const error = new Error('Connection failed');
      const mockMcpServer = {
        tool: vi.fn().mockReturnThis(),
        prompt: vi.fn().mockReturnThis(),
        connect: vi.fn().mockRejectedValue(error),
        close: vi.fn().mockResolvedValue(undefined),
        ...createMockServerProps(),
      } as unknown as McpServer;

      vi.mocked(McpServer).mockImplementation(() => mockMcpServer);
      try {
        await runMcpServer({ processExit: mockExit });
      } catch (e) {
        expect(e).toEqual(error);
      }

      expect(logger.error).toHaveBeenCalledWith('Failed to start MCP server:', error);
      expect(mockExit).toHaveBeenCalledWith(1);
    });

    test('should handle SIGINT signal', async () => {
      const mockServer = {
        tool: vi.fn().mockReturnThis(),
        prompt: vi.fn().mockReturnThis(),
        connect: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
        ...createMockServerProps(),
      } as unknown as McpServer;

      vi.mocked(McpServer).mockImplementation(() => mockServer);
      await expect(runMcpServer({ processExit: mockExit })).resolves.toBeUndefined();
      mockLogger.trace.mockClear();
      process.emit('SIGINT');

      // 非同期処理の完了を待つ
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(mockServer.close).toHaveBeenCalled();
      expect(logger.trace).toHaveBeenCalledWith('Repomix MCP Server shutdown complete');
      expect(mockExit).toHaveBeenCalledWith(0);
    });

    test('should handle SIGTERM signal', async () => {
      const mockServer = {
        tool: vi.fn().mockReturnThis(),
        prompt: vi.fn().mockReturnThis(),
        connect: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
        ...createMockServerProps(),
      } as unknown as McpServer;

      vi.mocked(McpServer).mockImplementation(() => mockServer);
      await expect(runMcpServer({ processExit: mockExit })).resolves.toBeUndefined();
      mockLogger.trace.mockClear();
      process.emit('SIGTERM');

      // 非同期処理の完了を待つ
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(mockServer.close).toHaveBeenCalled();
      expect(logger.trace).toHaveBeenCalledWith('Repomix MCP Server shutdown complete');
      expect(mockExit).toHaveBeenCalledWith(0);
    });

    test('should handle shutdown error', async () => {
      const error = new Error('Shutdown failed');
      const mockServer = {
        tool: vi.fn().mockReturnThis(),
        prompt: vi.fn().mockReturnThis(),
        connect: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockRejectedValue(error),
        ...createMockServerProps(),
      } as unknown as McpServer;

      vi.mocked(McpServer).mockImplementation(() => mockServer);
      await expect(runMcpServer({ processExit: mockExit })).resolves.toBeUndefined();
      mockLogger.error.mockClear();
      process.emit('SIGINT');

      // 非同期処理の完了を待つ
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(logger.error).toHaveBeenCalledWith('Error during MCP server shutdown:', error);
      expect(mockExit).toHaveBeenCalledWith(1);
    });
  });
});

function createMockServerProps() {
  return {
    server: {},
    _registeredResources: new Map(),
    _registeredResourceTemplates: new Map(),
    _registeredTools: new Map(),
    _registeredPrompts: new Map(),
    _registeredAgents: new Map(),
    _registeredInstructions: new Map(),
    _registeredRoutes: new Map(),
    _registeredSessions: new Map(),
    _registeredSockets: new Map(),
    _registeredStreams: new Map(),
    _registeredWebSockets: new Map(),
    _registeredWorkers: new Map(),
    _toolHandlersInitialized: false,
    _completionHandlerInitialized: false,
    setToolRequestHandlers: vi.fn(),
    setCompletionRequestHandler: vi.fn(),
    _messageHandler: vi.fn(),
    _transport: {},
    _connected: false,
    _completionHandler: vi.fn(),
    _toolHandlers: new Map(),
    _validateHandlersInitialized: vi.fn(),
    handlePromptCompletion: vi.fn(),
    handleResourceCompletion: vi.fn(),
    _resourceHandlersInitialized: false,
    setResourceRequestHandlers: vi.fn(),
    _resourceHandlers: new Map(),
    _validateSession: vi.fn(),
    _validateResource: vi.fn(),
    _resourceTemplateHandlers: new Map(),
  };
}
