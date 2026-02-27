import { describe, it, expect } from 'vitest';
import { 
  MCPErrorFactory, 
  MCPErrorClass, 
  MCPErrorCode, 
  isMCPError, 
  formatMCPError 
} from '../src/errors.js';

describe('MCP Error System', () => {
  describe('MCPErrorCode', () => {
    it('should have correct JSON-RPC 2.0 error codes', () => {
      expect(MCPErrorCode.ParseError).toBe(-32700);
      expect(MCPErrorCode.InvalidRequest).toBe(-32600);
      expect(MCPErrorCode.MethodNotFound).toBe(-32601);
      expect(MCPErrorCode.InvalidParams).toBe(-32602);
      expect(MCPErrorCode.InternalError).toBe(-32603);
    });

    it('should have correct MCP-specific error codes', () => {
      expect(MCPErrorCode.ServerError).toBe(-32000);
      expect(MCPErrorCode.ResourceNotFound).toBe(-32004);
      expect(MCPErrorCode.ToolNotFound).toBe(-32005);
      expect(MCPErrorCode.PromptNotFound).toBe(-32006);
    });
  });

  describe('MCPErrorClass', () => {
    it('should create error with basic properties', () => {
      const error = new MCPErrorClass(
        MCPErrorCode.InvalidParams,
        'Test error message'
      );

      expect(error.code).toBe(MCPErrorCode.InvalidParams);
      expect(error.message).toBe('Test error message');
      expect(error.name).toBe('MCPError');
      expect(error.data).toBeUndefined();
    });

    it('should create error with data', () => {
      const data = { type: 'test_error', details: { field: 'value' } };
      const error = new MCPErrorClass(
        MCPErrorCode.ServerError,
        'Test error with data',
        data
      );

      expect(error.code).toBe(MCPErrorCode.ServerError);
      expect(error.message).toBe('Test error with data');
      expect(error.data).toEqual(data);
    });

    it('should serialize to JSON correctly', () => {
      const data = { type: 'test_error', details: { field: 'value' } };
      const error = new MCPErrorClass(
        MCPErrorCode.InternalError,
        'JSON test error',
        data
      );

      const json = error.toJSON();
      expect(json).toEqual({
        code: MCPErrorCode.InternalError,
        message: 'JSON test error',
        data: data
      });
    });

    it('should extend Error class properly', () => {
      const error = new MCPErrorClass(MCPErrorCode.ServerError, 'Test');
      
      expect(error instanceof Error).toBe(true);
      expect(error instanceof MCPErrorClass).toBe(true);
      expect(error.stack).toBeDefined();
    });
  });

  describe('MCPErrorFactory', () => {
    describe('parseError', () => {
      it('should create parse error with default message', () => {
        const error = MCPErrorFactory.parseError();
        
        expect(error.code).toBe(MCPErrorCode.ParseError);
        expect(error.message).toBe('Parse error');
        expect(error.data).toBeUndefined();
      });

      it('should create parse error with custom message and details', () => {
        const details = { line: 5, column: 10 };
        const error = MCPErrorFactory.parseError('Invalid JSON syntax', details);
        
        expect(error.code).toBe(MCPErrorCode.ParseError);
        expect(error.message).toBe('Invalid JSON syntax');
        expect(error.data).toEqual({
          type: 'parse_error',
          details: details
        });
      });
    });

    describe('invalidRequest', () => {
      it('should create invalid request error', () => {
        const error = MCPErrorFactory.invalidRequest();
        
        expect(error.code).toBe(MCPErrorCode.InvalidRequest);
        expect(error.message).toBe('Invalid request');
        expect(error.data).toBeUndefined();
      });

      it('should create invalid request error with details', () => {
        const details = { missing: 'jsonrpc' };
        const error = MCPErrorFactory.invalidRequest('Missing jsonrpc field', details);
        
        expect(error.code).toBe(MCPErrorCode.InvalidRequest);
        expect(error.message).toBe('Missing jsonrpc field');
        expect(error.data).toEqual({
          type: 'invalid_request',
          details: details
        });
      });
    });

    describe('methodNotFound', () => {
      it('should create method not found error', () => {
        const error = MCPErrorFactory.methodNotFound('test/method');
        
        expect(error.code).toBe(MCPErrorCode.MethodNotFound);
        expect(error.message).toBe('Method \'test/method\' not found');
        expect(error.data).toEqual({
          type: 'method_not_found',
          method: 'test/method'
        });
      });
    });

    describe('invalidParams', () => {
      it('should create invalid params error', () => {
        const error = MCPErrorFactory.invalidParams();
        
        expect(error.code).toBe(MCPErrorCode.InvalidParams);
        expect(error.message).toBe('Invalid parameters');
        expect(error.data?.type).toBe('invalid_params');
      });

      it('should create invalid params error with details', () => {
        const details = { required: ['name'], provided: [] };
        const error = MCPErrorFactory.invalidParams('Missing required parameters', details);
        
        expect(error.code).toBe(MCPErrorCode.InvalidParams);
        expect(error.message).toBe('Missing required parameters');
        expect(error.data).toEqual({
          type: 'invalid_params',
          details: details
        });
      });
    });

    describe('internalError', () => {
      it('should create internal error', () => {
        const error = MCPErrorFactory.internalError();
        
        expect(error.code).toBe(MCPErrorCode.InternalError);
        expect(error.message).toBe('Internal error');
        expect(error.data).toBeUndefined();
      });

      it('should create internal error with details', () => {
        const details = { stack: 'Error at line 42' };
        const error = MCPErrorFactory.internalError('Database connection failed', details);
        
        expect(error.code).toBe(MCPErrorCode.InternalError);
        expect(error.message).toBe('Database connection failed');
        expect(error.data).toEqual({
          type: 'internal_error',
          details: details
        });
      });
    });

    describe('serverError', () => {
      it('should create server error', () => {
        const error = MCPErrorFactory.serverError();
        
        expect(error.code).toBe(MCPErrorCode.ServerError);
        expect(error.message).toBe('Server error');
        expect(error.data).toBeUndefined();
      });

      it('should create server error with details', () => {
        const details = { service: 'auth', status: 'unavailable' };
        const error = MCPErrorFactory.serverError('Authentication service unavailable', details);
        
        expect(error.code).toBe(MCPErrorCode.ServerError);
        expect(error.message).toBe('Authentication service unavailable');
        expect(error.data).toEqual({
          type: 'server_error',
          details: details
        });
      });
    });

    describe('resourceNotFound', () => {
      it('should create resource not found error', () => {
        const uri = 'file:///test/resource.txt';
        const error = MCPErrorFactory.resourceNotFound(uri);
        
        expect(error.code).toBe(MCPErrorCode.ResourceNotFound);
        expect(error.message).toBe(`Resource not found: ${uri}`);
        expect(error.data).toEqual({
          type: 'resource_not_found',
          uri: uri
        });
      });
    });

    describe('toolNotFound', () => {
      it('should create tool not found error', () => {
        const toolName = 'test-tool';
        const error = MCPErrorFactory.toolNotFound(toolName);
        
        expect(error.code).toBe(MCPErrorCode.ToolNotFound);
        expect(error.message).toBe(`Tool not found: ${toolName}`);
        expect(error.data).toEqual({
          type: 'tool_not_found',
          name: toolName
        });
      });
    });

    describe('promptNotFound', () => {
      it('should create prompt not found error', () => {
        const promptName = 'test-prompt';
        const error = MCPErrorFactory.promptNotFound(promptName);
        
        expect(error.code).toBe(MCPErrorCode.PromptNotFound);
        expect(error.message).toBe(`Prompt not found: ${promptName}`);
        expect(error.data).toEqual({
          type: 'prompt_not_found',
          name: promptName
        });
      });
    });

    describe('fromError', () => {
      it('should return MCP error as-is', () => {
        const originalError = MCPErrorFactory.serverError('Original error');
        const result = MCPErrorFactory.fromError(originalError);
        
        expect(result).toBe(originalError);
      });

      it('should convert Error to MCP error', () => {
        const originalError = new Error('Test error');
        originalError.name = 'TestError';
        const result = MCPErrorFactory.fromError(originalError);
        
        expect(result.code).toBe(MCPErrorCode.InternalError);
        expect(result.message).toBe('Test error');
        expect(result.data).toMatchObject({
          type: 'wrapped_error',
          name: 'TestError',
        });
      });

      it('should convert string to MCP error', () => {
        const result = MCPErrorFactory.fromError('String error');

        expect(result.code).toBe(MCPErrorCode.InternalError);
        expect(result.message).toBe('String error');
        expect(result.data).toEqual({
          type: 'unknown_error',
        });
      });

      it('should convert object to MCP error', () => {
        const errorObj = { custom: 'error', code: 500 };
        const result = MCPErrorFactory.fromError(errorObj);

        expect(result.code).toBe(MCPErrorCode.InternalError);
        expect(result.message).toBe('[object Object]');
        expect(result.data).toEqual({
          type: 'unknown_error',
        });
      });

      it('should convert null/undefined to MCP error', () => {
        const nullResult = MCPErrorFactory.fromError(null);
        expect(nullResult.code).toBe(MCPErrorCode.InternalError);
        expect(nullResult.message).toBe('null');
        
        const undefinedResult = MCPErrorFactory.fromError(undefined);
        expect(undefinedResult.code).toBe(MCPErrorCode.InternalError);
        expect(undefinedResult.message).toBe('undefined');
      });
    });
  });

  describe('isMCPError', () => {
    it('should return true for valid MCP error', () => {
      const error = MCPErrorFactory.serverError('Test');
      expect(isMCPError(error)).toBe(true);
    });

    it('should return true for plain MCP error object', () => {
      const error = {
        code: MCPErrorCode.InvalidParams,
        message: 'Test error'
      };
      expect(isMCPError(error)).toBe(true);
    });

    it('should return false for regular Error', () => {
      const error = new Error('Test');
      expect(isMCPError(error)).toBe(false);
    });

    it('should return false for invalid objects', () => {
      expect(isMCPError({})).toBe(false);
      expect(isMCPError({ code: 'invalid' })).toBe(false);
      expect(isMCPError({ message: 'no code' })).toBe(false);
      expect(isMCPError({ code: 123 })).toBe(false); // missing message
      expect(isMCPError({ message: 'test' })).toBe(false); // missing code
      expect(isMCPError(null)).toBe(false);
      expect(isMCPError(undefined)).toBe(false);
      expect(isMCPError('string')).toBe(false);
    });
  });

  describe('formatMCPError', () => {
    it('should format MCP error correctly', () => {
      const error = new MCPErrorClass(
        MCPErrorCode.InvalidParams,
        'Test error',
        { type: 'test', details: { field: 'value' } }
      );

      const formatted = formatMCPError(error);
      
      expect(formatted).toEqual({
        code: MCPErrorCode.InvalidParams,
        message: 'Test error',
        data: { type: 'test', details: { field: 'value' } }
      });
    });

    it('should format MCP error without data', () => {
      const error = new MCPErrorClass(MCPErrorCode.ServerError, 'Simple error');
      const formatted = formatMCPError(error);
      
      expect(formatted).toEqual({
        code: MCPErrorCode.ServerError,
        message: 'Simple error',
        data: undefined
      });
    });

    it('should format plain MCP error object', () => {
      const error = {
        code: MCPErrorCode.ResourceNotFound,
        message: 'Resource not found',
        data: { uri: 'file:///test.txt' }
      };

      const formatted = formatMCPError(error);
      
      expect(formatted).toEqual({
        code: MCPErrorCode.ResourceNotFound,
        message: 'Resource not found',
        data: { uri: 'file:///test.txt' }
      });
    });
  });
});