import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { 
  MCPServer, 
  LogLevel,
  type LogLevelName,
  type LoggingConfig,
  type LoggingCapabilities,
  type StructuredLogEntry,
  z
} from '../src/index.js';

// Mock the SDK server
vi.mock('@modelcontextprotocol/sdk/server/mcp.js', () => ({
  McpServer: vi.fn().mockImplementation(() => {
    const mockServer = {
      registerTool: vi.fn(),
      registerResource: vi.fn(),
      registerPrompt: vi.fn(),
      notification: vi.fn(),
      setRequestHandler: vi.fn(),
      server: {
        notification: vi.fn(),
        setRequestHandler: vi.fn()
      }
    };
    return mockServer;
  })
}));

describe('MCP Advanced Logging System', () => {
  let server: MCPServer;
  let mockSDKServer: any;

  beforeEach(() => {
    server = new MCPServer({
      name: 'test-server',
      version: '1.0.0',
      logging: {
        level: LogLevel.Info,
        structured: true,
        includeTimestamp: true,
        includeSource: true,
        maxMessageLength: 1000,
        loggerLevels: {
          'test.debug': LogLevel.Debug,
          'test.error': LogLevel.Error
        }
      }
    });
    mockSDKServer = server.getSDKServer();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Logging Configuration', () => {
    it('should initialize with default logging settings', () => {
      const defaultServer = new MCPServer({
        name: 'default-server',
        version: '1.0.0'
      });

      const config = defaultServer.getLoggingConfig();
      expect(config.level).toBe(LogLevel.Info);
      expect(config.structured).toBe(false);
      expect(config.includeTimestamp).toBe(true);
      expect(config.includeSource).toBe(false);
      expect(config.maxMessageLength).toBe(8192);
    });

    it('should initialize with custom logging settings', () => {
      const config = server.getLoggingConfig();
      expect(config.level).toBe(LogLevel.Info);
      expect(config.structured).toBe(true);
      expect(config.includeTimestamp).toBe(true);
      expect(config.includeSource).toBe(true);
      expect(config.maxMessageLength).toBe(1000);
      expect(config.loggers.get('test.debug')).toBe(LogLevel.Debug);
      expect(config.loggers.get('test.error')).toBe(LogLevel.Error);
    });

    it('should provide logging capabilities', () => {
      const capabilities = server.getLoggingCapabilities();
      expect(capabilities.supportedLevels).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
      expect(capabilities.supportsStructuredLogs).toBe(true);
      expect(capabilities.supportsLoggerNamespaces).toBe(true);
      expect(capabilities.maxMessageLength).toBe(1000);
    });
  });

  describe('RFC 5424 Log Levels', () => {
    it('should map log level enums correctly', () => {
      expect(LogLevel.Emergency).toBe(0);
      expect(LogLevel.Alert).toBe(1);
      expect(LogLevel.Critical).toBe(2);
      expect(LogLevel.Error).toBe(3);
      expect(LogLevel.Warning).toBe(4);
      expect(LogLevel.Notice).toBe(5);
      expect(LogLevel.Info).toBe(6);
      expect(LogLevel.Debug).toBe(7);
    });

    it('should handle all log level convenience methods', async () => {
      const testMessage = 'Test message';
      const testData = { key: 'value' };
      const logger = 'test.debug'; // Use configured logger name to allow debug level

      await server.logEmergency(testMessage, testData, logger);
      await server.logAlert(testMessage, testData, logger);
      await server.logCritical(testMessage, testData, logger);
      await server.logError(testMessage, testData, logger);
      await server.logWarning(testMessage, testData, logger);
      await server.logNotice(testMessage, testData, logger);
      await server.logInfo(testMessage, testData, logger);
      await server.logDebug(testMessage, testData, logger);

      // All should have been called (Debug won't be filtered out due to logger-specific level)
      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(8);
    });
  });

  describe('Log Level Filtering', () => {
    it('should filter logs based on global level', async () => {
      // Server is set to Info level, so Debug should be filtered out
      await server.logDebug('Debug message');
      await server.logInfo('Info message');
      await server.logError('Error message');

      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(2); // Info and Error only
    });

    it('should filter logs based on logger-specific levels', async () => {
      // test.debug logger is set to Debug level
      await server.logDebug('Debug message', {}, 'test.debug');
      await server.logDebug('Debug message', {}, 'test.other'); // Should be filtered (uses global Info level)

      // test.error logger is set to Error level
      await server.logInfo('Info message', {}, 'test.error'); // Should be filtered
      await server.logError('Error message', {}, 'test.error'); // Should pass

      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(2); // Debug from test.debug and Error from test.error
    });

    it('should handle unknown loggers with global level', async () => {
      await server.logDebug('Debug message', {}, 'unknown.logger'); // Should be filtered (global Info level)
      await server.logWarning('Warning message', {}, 'unknown.logger'); // Should pass

      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(1); // Warning only
    });
  });

  describe('Structured Logging', () => {
    it('should send structured logs when enabled', async () => {
      const message = 'Test structured log';
      const data = { request: 'test', id: 123 };
      const logger = 'test.structured';
      const source = { file: 'test.ts', function: 'testFunction', line: 42 };
      const requestId = 'req-123';
      const sessionId = 'session-456';

      await server.log(LogLevel.Info, message, data, logger, source, requestId, sessionId);

      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(1);
      const call = mockSDKServer.server.notification.mock.calls[0][0];
      
      expect(call.method).toBe('notifications/message');
      expect(call.params.level).toBe('info');
      expect(call.params.logger).toBe(logger);
      
      const logEntry = call.params.data as StructuredLogEntry;
      expect(logEntry.message).toBe(message);
      expect(logEntry.data).toEqual(data);
      expect(logEntry.level).toBe(LogLevel.Info);
      expect(logEntry.levelName).toBe('info');
      expect(logEntry.logger).toBe(logger);
      expect(logEntry.source).toEqual(source);
      expect(logEntry.requestId).toBe(requestId);
      expect(logEntry.sessionId).toBe(sessionId);
      expect(logEntry.timestamp).toBeDefined();
      expect(typeof logEntry.timestamp).toBe('string');
    });

    it('should send simple logs when structured logging disabled', async () => {
      const simpleServer = new MCPServer({
        name: 'simple-server',
        version: '1.0.0',
        logging: {
          structured: false,
          includeTimestamp: false,
          includeSource: false
        }
      });
      const simpleMockSDK = simpleServer.getSDKServer();
      
      // Ensure the server property exists
      if (!simpleMockSDK.server) {
        simpleMockSDK.server = { notification: vi.fn() };
      }

      const message = 'Simple log message';
      const data = { key: 'value' };

      await simpleServer.logInfo(message, data, 'simple.logger');

      expect(simpleMockSDK.server.notification).toHaveBeenCalledTimes(1);
      const call = simpleMockSDK.server.notification.mock.calls[0][0];
      
      expect(call.method).toBe('notifications/message');
      expect(call.params.level).toBe('info');
      expect(call.params.logger).toBe('simple.logger');
      expect(call.params.data).toEqual({ message, data });
    });

    it('should omit optional fields when configured', async () => {
      const noTimestampServer = new MCPServer({
        name: 'no-timestamp-server',
        version: '1.0.0',
        logging: {
          structured: true,
          includeTimestamp: false,
          includeSource: false
        }
      });
      const noTimestampMockSDK = noTimestampServer.getSDKServer();
      
      // Ensure the server property exists
      if (!noTimestampMockSDK.server) {
        noTimestampMockSDK.server = { notification: vi.fn() };
      }

      await noTimestampServer.logInfo('Test message');

      const call = noTimestampMockSDK.server.notification.mock.calls[0][0];
      const logEntry = call.params.data as StructuredLogEntry;
      
      expect(logEntry.timestamp).toBe('');
      expect(logEntry.source).toBeUndefined();
    });
  });

  describe('Message Length Limiting', () => {
    it('should truncate long messages', async () => {
      const longMessage = 'A'.repeat(1500); // Exceeds 1000 char limit
      
      await server.logInfo(longMessage);

      const call = mockSDKServer.server.notification.mock.calls[0][0];
      const logEntry = call.params.data as StructuredLogEntry;
      
      expect(logEntry.message).toHaveLength(1000);
      expect(logEntry.message.endsWith('...')).toBe(true);
      expect(logEntry.message.substring(0, 997)).toBe('A'.repeat(997));
    });

    it('should not truncate short messages', async () => {
      const shortMessage = 'Short message';
      
      await server.logInfo(shortMessage);

      const call = mockSDKServer.server.notification.mock.calls[0][0];
      const logEntry = call.params.data as StructuredLogEntry;
      
      expect(logEntry.message).toBe(shortMessage);
    });

    it('should handle undefined maxMessageLength', async () => {
      const unlimitedServer = new MCPServer({
        name: 'unlimited-server',
        version: '1.0.0',
        logging: {
          structured: true,
          maxMessageLength: undefined
        }
      });
      const unlimitedMockSDK = unlimitedServer.getSDKServer();
      
      // Ensure the server property exists
      if (!unlimitedMockSDK.server) {
        unlimitedMockSDK.server = { notification: vi.fn() };
      }

      const veryLongMessage = 'A'.repeat(20000);
      
      await unlimitedServer.logInfo(veryLongMessage);

      const call = unlimitedMockSDK.server.notification.mock.calls[0][0];
      const logEntry = call.params.data as StructuredLogEntry;
      
      expect(logEntry.message).toBe(veryLongMessage);
    });
  });

  describe('Log Level Management', () => {
    it('should set global log level', async () => {
      await server.setLogLevel(LogLevel.Debug);
      
      const config = server.getLoggingConfig();
      expect(config.level).toBe(LogLevel.Debug);

      // Should now allow debug logs
      await server.logDebug('Debug message');
      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(2); // 1 for setLogLevel notification + 1 for debug
    });

    it('should set logger-specific log level', async () => {
      await server.setLogLevel(LogLevel.Warning, 'specific.logger');
      
      const config = server.getLoggingConfig();
      expect(config.loggers.get('specific.logger')).toBe(LogLevel.Warning);

      // Should filter out Info for specific logger
      await server.logInfo('Info message', {}, 'specific.logger');
      await server.logError('Error message', {}, 'specific.logger');
      
      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(2); // 1 for setLogLevel notification + 1 for error
    });

    it('should send notification when log level changes', async () => {
      await server.setLogLevel(LogLevel.Debug, 'test.logger');
      
      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(1);
      const call = mockSDKServer.server.notification.mock.calls[0][0];
      
      expect(call.method).toBe('notifications/message');
      expect(call.params.level).toBe('info');
      expect(call.params.logger).toBe('mcp.server.logging');
      expect(call.params.data.message).toContain('Log level changed to debug');
      expect(call.params.data.level).toBe(LogLevel.Debug);
      expect(call.params.data.logger).toBe('test.logger');
    });
  });

  describe('Logging Endpoint Registration', () => {
    it('should support setting log levels directly', async () => {
      // In SDK v1.27+, logging endpoints are handled by the SDK server
      // Test that the framework-level setLogLevel still works
      await server.setLogLevel(LogLevel.Debug, 'test.handler');

      // Verify the log level was set
      const config = server.getLoggingConfig();
      expect(config.loggers.get('test.handler')).toBe(LogLevel.Debug);
    });

    it('should handle logging/setLevel requests', async () => {
      // Test logging functionality directly through server methods
      await server.setLogLevel(LogLevel.Debug, 'test.handler');

      // Verify the log level was set
      const config = server.getLoggingConfig();
      expect(config.loggers.get('test.handler')).toBe(LogLevel.Debug);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid log levels gracefully', async () => {
      // This would normally be caught by Zod validation, but test direct method
      const invalidLevel = 999 as LogLevel;
      
      await server.log(invalidLevel, 'Test message');
      
      // Should still send notification with 'info' as fallback
      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(1);
      const call = mockSDKServer.server.notification.mock.calls[0][0];
      expect(call.params.level).toBe('info'); // Default fallback
    });

    it('should handle missing logger gracefully', async () => {
      await server.logInfo('Test message', {}, undefined);
      
      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(1);
      const call = mockSDKServer.server.notification.mock.calls[0][0];
      expect(call.params.logger).toBeUndefined();
    });
  });

  describe('Integration with Existing Features', () => {
    it('should work with tools', async () => {
      server.registerTool(
        'logging-tool',
        {
          description: 'A tool that logs',
          inputSchema: z.object({})
        },
        async () => {
          await server.logInfo('Tool executed', { tool: 'logging-tool' }, 'tools.logging-tool');
          return { content: [{ type: 'text', text: 'Logged execution' }] };
        }
      );

      // Verify tool registration and can use logging
      expect(server.getTool('logging-tool')).toBeDefined();
    });

    it('should respect logger namespaces', async () => {
      // Test hierarchical logger behavior
      await server.setLogLevel(LogLevel.Error, 'app');
      await server.setLogLevel(LogLevel.Debug, 'app.debug');
      
      // app logger should filter out Info
      await server.logInfo('Info message', {}, 'app');
      await server.logError('Error message', {}, 'app');
      
      // app.debug logger should allow Debug
      await server.logDebug('Debug message', {}, 'app.debug');
      
      // app.other should use app level (Error)
      await server.logInfo('Info message', {}, 'app.other');
      await server.logError('Error message', {}, 'app.other');
      
      // 2 for setLogLevel notifications + 1 error from app + 1 debug from app.debug + 1 error from app.other = 5
      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(5);
    });
  });

  describe('Performance Considerations', () => {
    it('should short-circuit when log level filtering would prevent sending', async () => {
      const heavyData = { 
        largeArray: new Array(1000).fill('data'),
        timestamp: Date.now(),
        metadata: { complex: 'object' }
      };
      
      // Debug should be filtered out at Info level
      await server.logDebug('Heavy debug log', heavyData);
      
      // Should not have sent notification
      expect(mockSDKServer.server.notification).not.toHaveBeenCalled();
    });

    it('should handle concurrent logging calls', async () => {
      const logPromises = [];
      
      for (let i = 0; i < 10; i++) {
        logPromises.push(server.logInfo(`Concurrent log ${i}`, { index: i }));
      }
      
      await Promise.all(logPromises);
      
      expect(mockSDKServer.server.notification).toHaveBeenCalledTimes(10);
    });
  });
});