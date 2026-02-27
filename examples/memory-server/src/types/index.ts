/**
 * Core type definitions for the MCP Memories server
 */

export interface Memory {
  id: string;
  userId: string;
  projectName: string;
  memoryTopic: string;
  memoryType: string;
  content: string;
  contentType: 'md' | 'json' | 'text';
  tags: string[];
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface MemorySearchQuery {
  query: string;
  projectName?: string;
  memoryTopic?: string;
  memoryType?: string;
  tags?: string[];
  userId: string;
  limit?: number;
  similarityThreshold?: number;
}

export interface MemorySearchResult {
  memory: Memory;
  similarity: number;
}

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  groups: string[];
}

export interface AuthConfig {
  oidcUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
  allowedGroups: string[];
}

export interface NATSConfig {
  servers: string[];
  user?: string;
  pass?: string;
  token?: string;
  streamName: string;
  consumerName: string;
}

export interface ServerConfig {
  port: number;
  host: string;
  baseUrl: string;
  sessionSecret: string;
  externalDomain?: string;
  corsOrigins: string[];
  enableApi: boolean;
  auth: AuthConfig;
  nats: NATSConfig;
  logging: {
    level: string;
    format: string;
  };
}

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, unknown>;
    required: string[];
  };
}

export interface MCPRequest {
  id: string;
  method: string;
  params: {
    name: string;
    arguments: Record<string, unknown>;
  };
}

export interface MCPResponse {
  content: Array<{
    type: string;
    text: string;
  }>;
}

export interface MCPError {
  code: number;
  message: string;
  data?: unknown;
}
