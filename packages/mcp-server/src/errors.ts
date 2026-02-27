/**
 * MCP-specific error codes and error handling utilities
 */

/**
 * MCP error codes according to specification
 */
export enum MCPErrorCode {
  // JSON-RPC 2.0 standard errors
  ParseError = -32700,
  InvalidRequest = -32600,
  MethodNotFound = -32601,
  InvalidParams = -32602,
  InternalError = -32603,
  
  // MCP-specific errors
  ServerError = -32000,
  ResourceNotFound = -32004,
  ToolNotFound = -32005,
  PromptNotFound = -32006
}

/**
 * MCP error interface extending JSON-RPC error structure
 */
export interface MCPError {
  code: MCPErrorCode;
  message: string;
  data?: {
    type?: string;
    details?: any;
    [key: string]: any;
  };
}

/**
 * MCP error class for throwing structured errors
 */
export class MCPErrorClass extends Error implements MCPError {
  code: MCPErrorCode;
  data?: {
    type?: string;
    details?: any;
    [key: string]: any;
  };

  constructor(code: MCPErrorCode, message: string, data?: MCPError['data']) {
    super(message);
    this.name = 'MCPError';
    this.code = code;
    this.data = data;
  }

  toJSON(): MCPError {
    return {
      code: this.code,
      message: this.message,
      data: this.data
    };
  }
}

/**
 * Factory class for creating MCP-compliant errors
 */
export class MCPErrorFactory {
  /**
   * Create a parse error
   */
  static parseError(message: string = 'Parse error', details?: any): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.ParseError,
      message,
      details ? { type: 'parse_error', details } : undefined
    );
  }

  /**
   * Create an invalid request error
   */
  static invalidRequest(message: string = 'Invalid request', details?: any): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.InvalidRequest,
      message,
      details ? { type: 'invalid_request', details } : undefined
    );
  }

  /**
   * Create a method not found error
   */
  static methodNotFound(method: string): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.MethodNotFound,
      `Method '${method}' not found`,
      { type: 'method_not_found', method }
    );
  }

  /**
   * Create an invalid params error
   */
  static invalidParams(message: string = 'Invalid parameters', details?: any): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.InvalidParams,
      message,
      { type: 'invalid_params', ...(details && { details }) }
    );
  }

  /**
   * Create an internal error
   */
  static internalError(message: string = 'Internal error', details?: any): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.InternalError,
      message,
      details ? { type: 'internal_error', details } : undefined
    );
  }

  /**
   * Create a generic server error
   */
  static serverError(message: string = 'Server error', details?: any): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.ServerError,
      message,
      details ? { type: 'server_error', details } : undefined
    );
  }

  /**
   * Create a resource not found error
   */
  static resourceNotFound(uri: string): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.ResourceNotFound,
      `Resource not found: ${uri}`,
      { type: 'resource_not_found', uri }
    );
  }

  /**
   * Create a tool not found error
   */
  static toolNotFound(name: string): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.ToolNotFound,
      `Tool not found: ${name}`,
      { type: 'tool_not_found', name }
    );
  }

  /**
   * Create a prompt not found error
   */
  static promptNotFound(name: string): MCPErrorClass {
    return new MCPErrorClass(
      MCPErrorCode.PromptNotFound,
      `Prompt not found: ${name}`,
      { type: 'prompt_not_found', name }
    );
  }

  /**
   * Convert any error to MCP error format
   */
  static fromError(error: any): MCPErrorClass {
    if (error instanceof MCPErrorClass) {
      return error;
    }

    if (error instanceof Error) {
      const data: Record<string, unknown> = {
        type: 'wrapped_error',
        name: error.name,
      };
      // Only include stack traces in development to avoid information disclosure
      if (process.env.NODE_ENV !== 'production') {
        data.stack = error.stack;
      }
      return new MCPErrorClass(
        MCPErrorCode.InternalError,
        error.message,
        data
      );
    }

    return new MCPErrorClass(
      MCPErrorCode.InternalError,
      String(error),
      { type: 'unknown_error' }
    );
  }
}

/**
 * Type guard to check if an error is an MCP error
 */
export function isMCPError(error: any): error is MCPError {
  return Boolean(
    error &&
    typeof error === 'object' &&
    'code' in error &&
    'message' in error &&
    typeof error.code === 'number' &&
    typeof error.message === 'string'
  );
}

/**
 * Convert MCP error to JSON-RPC error response format
 */
export function formatMCPError(error: MCPError | MCPErrorClass): {
  code: number;
  message: string;
  data?: any;
} {
  return {
    code: error.code,
    message: error.message,
    data: error.data
  };
}