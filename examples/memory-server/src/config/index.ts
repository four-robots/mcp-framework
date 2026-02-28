import { z } from 'zod';
import type { ServerConfig } from '../types/index.js';

/**
 * Configuration schema validation
 */
const authConfigSchema = z.object({
  oidcUrl: z.string().url(),
  clientId: z.string().min(1),
  clientSecret: z.string(), // Allow empty for public clients
  redirectUri: z.string().url(),
  scope: z.string().default('openid profile email'),
  allowedGroups: z.array(z.string()).default([]),
});

const natsConfigSchema = z.object({
  servers: z.array(z.string()).default(['nats://localhost:4222']),
  user: z.string().optional(),
  pass: z.string().optional(),
  token: z.string().optional(),
  streamName: z.string().default('MEMORIES'),
  consumerName: z.string().default('mcp-memories-consumer')
});

const serverConfigSchema = z.object({
  port: z.number().int().min(1).max(65535).default(3000),
  host: z.string().default('localhost'),
  baseUrl: z.string().default('http://localhost:3000'),
  sessionSecret: z.string().min(32),
  externalDomain: z.string().optional(),
  corsOrigins: z.array(z.string()).default(['http://localhost:*', 'https://claude.ai']),
  enableApi: z.boolean().default(false),
  auth: authConfigSchema,
  nats: natsConfigSchema,
  logging: z.object({
    level: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
    format: z.enum(['json', 'simple']).default('json')
  }).default({})
});

/**
 * Load and validate configuration from environment variables
 */
export function loadConfig(): ServerConfig {
  const config = {
    port: parseInt(process.env.PORT || '3000', 10),
    host: process.env.HOST || 'localhost',
    baseUrl: process.env.BASE_URL || 'http://localhost:3000',
    sessionSecret: process.env.SESSION_SECRET || '',
    corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:*'],
    externalDomain: process.env.APP_EXTERNAL_DOMAIN,
    enableApi: process.env.ENABLE_API === 'true',
    auth: {
      oidcUrl: process.env.OIDC_URL || '',
      clientId: process.env.OIDC_CLIENT_ID || '',
      clientSecret: process.env.OIDC_CLIENT_SECRET || '',
      redirectUri: process.env.OIDC_REDIRECT_URI || '',
      scope: process.env.OIDC_SCOPE || 'openid profile email',
      allowedGroups: process.env.OIDC_ALLOWED_GROUPS?.split(',').filter(g => g.length > 0) || [],
    },
    nats: {
      servers: process.env.NATS_SERVERS?.split(',') || ['nats://localhost:4222'],
      user: process.env.NATS_USER,
      pass: process.env.NATS_PASS,
      token: process.env.NATS_TOKEN,
      streamName: process.env.NATS_STREAM_NAME || 'MEMORIES',
      consumerName: process.env.NATS_CONSUMER_NAME || 'mcp-memories-consumer'
    },
    logging: {
      level: (process.env.LOG_LEVEL as any) || 'info',
      format: (process.env.LOG_FORMAT as any) || 'json'
    }
  };

  // Validate configuration
  const result = serverConfigSchema.safeParse(config);
  if (!result.success) {
    console.error('Configuration validation failed:');
    console.error(result.error.format());
    process.exit(1);
  }

  return result.data;
}

/**
 * Environment variables documentation
 */
export const ENV_DOCS = {
  // Server
  PORT: 'Server port (default: 3000)',
  HOST: 'Server host (default: localhost)',
  SESSION_SECRET: 'Secret for session encryption (required, min 32 chars)',
  CORS_ORIGINS: 'Comma-separated list of allowed CORS origins',

  // OIDC OAuth
  OIDC_URL: 'OIDC provider URL (e.g., https://auth.example.com)',
  OIDC_CLIENT_ID: 'OAuth client ID',
  OIDC_CLIENT_SECRET: 'OAuth client secret',
  OIDC_REDIRECT_URI: 'OAuth redirect URI (e.g., http://localhost:3000/auth/callback)',
  OIDC_SCOPE: 'OAuth scopes (default: openid profile email)',

  // NATS
  NATS_SERVERS: 'Comma-separated NATS server URLs (default: nats://localhost:4222)',
  NATS_USER: 'NATS username (optional)',
  NATS_PASS: 'NATS password (optional)',
  NATS_TOKEN: 'NATS token (optional)',
  NATS_STREAM_NAME: 'NATS stream name (default: MEMORIES)',
  NATS_CONSUMER_NAME: 'NATS consumer name (default: mcp-memories-consumer)',

  // Logging
  LOG_LEVEL: 'Logging level: error, warn, info, debug (default: info)',
  LOG_FORMAT: 'Log format: json, simple (default: json)'
};
