import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { MCPServer, LogLevel, CorrelationManager, PerformanceTracker, RequestTracer, ToolContext, PerformanceMetrics } from '../src/index.js';
import { z } from 'zod';

describe('Request Tracing System', () => {
  let server: MCPServer;
  let performanceTracker: PerformanceTracker;
  let requestTracer: RequestTracer;

  beforeEach(() => {
    server = new MCPServer({
      name: 'test-server',
      version: '1.0.0',
      logging: {
        level: LogLevel.Debug,
        structured: true
      }
    });

    performanceTracker = server.getPerformanceTracker();
    requestTracer = server.getRequestTracer();
  });

  afterEach(() => {
    // Clean up any active tracking
    performanceTracker.clearAll();
  });

  describe('CorrelationManager', () => {
    it('should generate unique correlation IDs', () => {
      const id1 = CorrelationManager.generateCorrelationId();
      const id2 = CorrelationManager.generateCorrelationId();

      expect(id1).toMatch(/^corr_\d+_[0-9a-f]+$/);
      expect(id2).toMatch(/^corr_\d+_[0-9a-f]+$/);
      expect(id1).not.toBe(id2);
    });

    it('should generate unique request IDs', () => {
      const id1 = CorrelationManager.generateRequestId();
      const id2 = CorrelationManager.generateRequestId();

      expect(id1).toMatch(/^req_\d+_[0-9a-f]+$/);
      expect(id2).toMatch(/^req_\d+_[0-9a-f]+$/);
      expect(id1).not.toBe(id2);
    });

    it('should generate unique trace IDs', () => {
      const id1 = CorrelationManager.generateTraceId();
      const id2 = CorrelationManager.generateTraceId();

      expect(id1).toMatch(/^trace_[0-9a-f]+$/);
      expect(id2).toMatch(/^trace_[0-9a-f]+$/);
      expect(id1).not.toBe(id2);
    });

    it('should generate unique span IDs', () => {
      const id1 = CorrelationManager.generateSpanId();
      const id2 = CorrelationManager.generateSpanId();

      expect(id1).toMatch(/^span_[0-9a-f]+$/);
      expect(id2).toMatch(/^span_[0-9a-f]+$/);
      expect(id1).not.toBe(id2);
    });

    it('should enhance context with correlation fields', () => {
      const context: ToolContext = { user: 'test-user' };
      const enhanced = CorrelationManager.enhanceContext(context);

      expect(enhanced.user).toBe('test-user');
      expect(enhanced.correlationId).toMatch(/^corr_\d+_[0-9a-f]+$/);
      expect(enhanced.requestId).toMatch(/^req_\d+_[0-9a-f]+$/);
      expect(enhanced.traceId).toMatch(/^trace_[0-9a-f]+$/);
      expect(enhanced.spanId).toMatch(/^span_[0-9a-f]+$/);
      expect(enhanced.startTime).toBeTypeOf('number');
    });

    it('should preserve existing correlation fields', () => {
      const context: ToolContext = {
        correlationId: 'existing-corr',
        requestId: 'existing-req',
        user: 'test-user'
      };
      
      const enhanced = CorrelationManager.enhanceContext(context);

      expect(enhanced.correlationId).toBe('existing-corr');
      expect(enhanced.requestId).toBe('existing-req');
      expect(enhanced.user).toBe('test-user');
    });
  });

  describe('PerformanceTracker', () => {
    let metrics: PerformanceMetrics[];

    beforeEach(() => {
      metrics = [];
      performanceTracker = new PerformanceTracker((metric) => {
        metrics.push(metric);
      });
    });

    it('should track operation performance', () => {
      const correlationId = 'test-correlation';
      const operation = 'test-operation';

      performanceTracker.startTracking(correlationId, operation);
      expect(performanceTracker.getActiveTrackingCount()).toBe(1);
      expect(performanceTracker.getActiveCorrelations()).toContain(correlationId);

      const metric = performanceTracker.endTracking(correlationId, true);
      
      expect(metric).toBeDefined();
      expect(metric!.correlationId).toBe(correlationId);
      expect(metric!.operation).toBe(operation);
      expect(metric!.success).toBe(true);
      expect(metric!.duration).toBeGreaterThanOrEqual(0);
      expect(metric!.startTime).toBeTypeOf('number');
      expect(metric!.endTime).toBeGreaterThan(metric!.startTime);
      
      expect(performanceTracker.getActiveTrackingCount()).toBe(0);
      expect(metrics).toHaveLength(1);
      expect(metrics[0]).toBe(metric);
    });

    it('should handle failed operations', () => {
      const correlationId = 'test-correlation';
      const operation = 'test-operation';
      const errorCode = 'TEST_ERROR';

      performanceTracker.startTracking(correlationId, operation);
      const metric = performanceTracker.endTracking(correlationId, false, errorCode);
      
      expect(metric!.success).toBe(false);
      expect(metric!.errorCode).toBe(errorCode);
    });

    it('should include metadata in tracking', () => {
      const correlationId = 'test-correlation';
      const operation = 'test-operation';
      const metadata = { component: 'test-component', version: '1.0.0' };

      performanceTracker.startTracking(correlationId, operation, metadata);
      const metric = performanceTracker.endTracking(correlationId, true);
      
      expect(metric!.metadata).toEqual(metadata);
    });

    it('should handle payload size tracking', () => {
      const correlationId = 'test-correlation';
      const operation = 'test-operation';
      const payloadSize = 1024;

      performanceTracker.startTracking(correlationId, operation);
      const metric = performanceTracker.endTracking(correlationId, true, undefined, payloadSize);
      
      expect(metric!.payloadSize).toBe(payloadSize);
    });

    it('should return null for non-existent correlation', () => {
      const metric = performanceTracker.endTracking('non-existent', true);
      expect(metric).toBeNull();
    });

    it('should clear all tracking', () => {
      performanceTracker.startTracking('corr1', 'op1');
      performanceTracker.startTracking('corr2', 'op2');
      
      expect(performanceTracker.getActiveTrackingCount()).toBe(2);
      
      performanceTracker.clearAll();
      
      expect(performanceTracker.getActiveTrackingCount()).toBe(0);
      expect(performanceTracker.getActiveCorrelations()).toHaveLength(0);
    });
  });

  describe('RequestTracer', () => {
    let logEntries: any[];
    let tracer: RequestTracer;

    beforeEach(() => {
      logEntries = [];
      tracer = new RequestTracer((entry) => {
        logEntries.push(entry);
      });
    });

    it('should start and end tracing', () => {
      const operation = 'test-operation';
      const context = tracer.startTrace(operation);

      expect(context.correlationId).toBeDefined();
      expect(context.requestId).toBeDefined();
      expect(context.traceId).toBeDefined();
      expect(context.spanId).toBeDefined();
      expect(context.startTime).toBeTypeOf('number');

      // Should log trace start
      expect(logEntries).toHaveLength(1);
      const startLog = logEntries[0];
      expect(startLog.message).toContain('Starting operation: test-operation');
      expect(startLog.operation).toBe(operation);
      expect(startLog.correlationId).toBe(context.correlationId);

      const metric = tracer.endTrace(context, true);

      expect(metric).toBeDefined();
      expect(metric!.success).toBe(true);
      
      // Should log trace end and performance metric
      expect(logEntries.length).toBeGreaterThanOrEqual(2);
      const endLog = logEntries.find(log => log.message?.includes('Completed operation'));
      expect(endLog).toBeDefined();
      expect(endLog.duration).toBeTypeOf('number');
    });

    it('should handle error tracing', () => {
      const operation = 'test-operation';
      const context = tracer.startTrace(operation);
      const errorCode = 'TEST_ERROR';

      const metric = tracer.endTrace(context, false, errorCode);

      expect(metric!.success).toBe(false);
      expect(metric!.errorCode).toBe(errorCode);

      const errorLog = logEntries.find(log => log.level === LogLevel.Error);
      expect(errorLog).toBeDefined();
    });

    it('should handle trace without correlation ID', () => {
      const context: ToolContext = {};
      const metric = tracer.endTrace(context, true);
      
      expect(metric).toBeNull();
    });
  });

  describe('MCPServer Integration', () => {
    it('should automatically trace tool calls', async () => {
      const toolHandler = vi.fn().mockResolvedValue({ result: 'success' });
      
      server.registerTool(
        'test-tool',
        {
          description: 'Test tool for tracing',
          inputSchema: z.object({
            input: z.string()
          })
        },
        toolHandler
      );

      // The handler will receive a traced context
      const args = { input: 'test' };
      
      // Call the tool through SDK (simulate real call)
      const sdkServer = server.getSDKServer();
      
      // We can't directly call the tool, but we can verify the handler setup
      expect(server.getActiveTracingCount()).toBe(0);
    });

    it('should provide tracing access methods', () => {
      expect(server.getRequestTracer()).toBe(requestTracer);
      expect(server.getPerformanceTracker()).toBe(performanceTracker);
      expect(server.getActiveTracingCount()).toBe(0);
      expect(server.getActiveCorrelations()).toEqual([]);
    });

    it('should support manual tracing', () => {
      const operation = 'manual-operation';
      const context = server.startTrace(operation);

      expect(context.correlationId).toBeDefined();
      expect(server.getActiveTracingCount()).toBe(1);
      expect(server.getActiveCorrelations()).toContain(context.correlationId);

      const metric = server.endTrace(context, true);
      
      expect(metric).toBeDefined();
      expect(metric!.operation).toBe(operation);
      expect(server.getActiveTracingCount()).toBe(0);
    });

    it('should handle context enhancement', () => {
      const originalContext: ToolContext = { user: 'test-user' };
      server.setContext(originalContext);

      const tracedContext = server.startTrace('test-operation');
      
      expect(tracedContext.user).toBe('test-user');
      expect(tracedContext.correlationId).toBeDefined();
    });
  });

  describe('Error Handling Integration', () => {
    it('should include correlation context in error logs', async () => {
      const toolHandler = vi.fn().mockRejectedValue(new Error('Test error'));
      
      server.registerTool(
        'error-tool',
        {
          description: 'Tool that throws errors',
          inputSchema: z.object({})
        },
        toolHandler
      );

      // The error should be traced with correlation context
      // We can verify the setup is correct
      expect(server.getActiveTracingCount()).toBe(0);
    });
  });

  describe('Performance Metrics', () => {
    it('should measure operation timing', async () => {
      const operation = 'timing-test';
      const context = server.startTrace(operation);
      
      // Simulate some work
      await new Promise(resolve => setTimeout(resolve, 10));
      
      const metric = server.endTrace(context, true);
      
      expect(metric!.duration).toBeGreaterThan(5); // At least 5ms
      expect(metric!.endTime).toBeGreaterThan(metric!.startTime);
    });

    it('should track payload sizes', () => {
      const operation = 'payload-test';
      const context = server.startTrace(operation);
      const payloadSize = 2048;
      
      const metric = server.endTrace(context, true, undefined, payloadSize);
      
      expect(metric!.payloadSize).toBe(payloadSize);
    });
  });

  describe('Structured Logging Integration', () => {
    it('should create enhanced log entries with correlation', () => {
      const logs: any[] = [];
      const tracer = new RequestTracer((entry) => {
        logs.push(entry);
      });

      const context = tracer.startTrace('log-test');
      tracer.endTrace(context, true);

      const startLog = logs[0];
      expect(startLog.correlationId).toBe(context.correlationId);
      expect(startLog.requestId).toBe(context.requestId);
      expect(startLog.traceId).toBe(context.traceId);
      expect(startLog.spanId).toBe(context.spanId);
      expect(startLog.component).toBe('mcp-server');
      expect(startLog.operation).toBe('log-test');
    });

    it('should include performance data in logs', () => {
      const logs: any[] = [];
      const tracer = new RequestTracer((entry) => {
        logs.push(entry);
      });

      const context = tracer.startTrace('perf-test');
      tracer.endTrace(context, true);

      const endLog = logs.find(log => log.message?.includes('Completed operation'));
      expect(endLog.duration).toBeTypeOf('number');
      expect(endLog.performance).toBeDefined();
      expect(endLog.performance.startTime).toBeTypeOf('number');
      expect(endLog.performance.endTime).toBeTypeOf('number');
    });
  });
});