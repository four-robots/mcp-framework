# Authentication Guide

This guide covers how to add authentication to your MCP servers using the available authentication providers.

## Overview

The MCP Framework provides pluggable authentication through the `@tylercoles/mcp-auth` package and various provider implementations. Authentication is primarily used with HTTP and WebSocket transports.

## Available Providers

### OIDC Provider (Generic)

The `@tylercoles/mcp-auth-oidc` package provides a generic OpenID Connect implementation:

```bash
npm install @tylercoles/mcp-auth-oidc
```

```typescript
import { OIDCProvider } from '@tylercoles/mcp-auth-oidc';
import { HttpTransport } from '@tylercoles/mcp-transport-http';

const oidcProvider = new OIDCProvider({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'https://your-app.com/auth/callback'
});

const httpTransport = new HttpTransport({
  port: 3000,
  auth: oidcProvider
});

server.useTransport(httpTransport);
```

### Pre-configured Providers

The OIDC package includes factory functions for popular providers:

```typescript
import { Providers } from '@tylercoles/mcp-auth-oidc';

// Authentik
const auth = Providers.Authentik('https://auth.example.com', 'my-app', 'client-id', 'client-secret');

// Auth0
const auth = Providers.Auth0('my-tenant.auth0.com', 'client-id', 'client-secret');

// Keycloak
const auth = Providers.Keycloak('https://keycloak.example.com', 'my-realm', 'client-id', 'client-secret');

// Google, Microsoft, Okta also available
```

### Session-Based Authentication

Enable browser login flows by adding a `session` config:

```typescript
import { Providers } from '@tylercoles/mcp-auth-oidc';

const auth = Providers.Authentik('https://auth.example.com', 'my-app', 'client-id', 'client-secret', {
  session: {
    secret: process.env.SESSION_SECRET!,
    callbackUrl: 'https://your-app.com/auth/callback',
  },
});

// This automatically creates /auth/login, /auth/callback, /auth/logout routes
```

## Configuration

### Environment Variables

Set up environment variables for secure configuration:

```bash
# .env file
OIDC_ISSUER=https://your-oidc-provider.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://your-app.com/auth/callback
SESSION_SECRET=your-session-secret
```

```typescript
import { config } from 'dotenv';
config();

const oidcProvider = new OIDCProvider({
  issuer: process.env.OIDC_ISSUER!,
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET!,
  redirectUri: process.env.OIDC_REDIRECT_URI!
});
```

### Advanced Configuration

#### Custom Scopes

```typescript
const oidcProvider = new OIDCProvider({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'https://your-app.com/auth/callback',
  scopes: ['openid', 'profile', 'email', 'roles']
});
```

#### Custom Claims

```typescript
const oidcProvider = new OIDCProvider({
  issuer: 'https://your-oidc-provider.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'https://your-app.com/auth/callback',
  claimsMapping: {
    userId: 'sub',
    email: 'email',
    name: 'name',
    roles: 'groups'
  }
});
```

## Using Authentication in Tools

### Accessing User Context

```typescript
server.addTool({
  name: 'user_info',
  description: 'Get current user information',
  inputSchema: {
    type: 'object',
    properties: {}
  }
}, async (params, context) => {
  // Access user information from context
  const user = context.user;
  
  if (!user) {
    throw new Error('Authentication required');
  }
  
  return {
    text: `Hello, ${user.name}!`,
    data: {
      userId: user.id,
      email: user.email,
      roles: user.roles
    }
  };
});
```

### Role-Based Access Control

```typescript
server.addTool({
  name: 'admin_tool',
  description: 'Admin-only tool',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string' }
    },
    required: ['action']
  }
}, async (params, context) => {
  const user = context.user;
  
  if (!user) {
    throw new Error('Authentication required');
  }
  
  if (!user.roles?.includes('admin')) {
    throw new Error('Insufficient permissions');
  }
  
  // Perform admin action
  return {
    text: `Admin action '${params.action}' completed by ${user.name}`
  };
});
```

### Custom Authorization Logic

```typescript
// Helper function for authorization
function requireRole(requiredRole: string) {
  return (context: any) => {
    const user = context.user;
    
    if (!user) {
      throw new Error('Authentication required');
    }
    
    if (!user.roles?.includes(requiredRole)) {
      throw new Error(`Role '${requiredRole}' required`);
    }
  };
}

// Use in tools
server.addTool({
  name: 'moderator_tool',
  description: 'Moderator-only tool',
  inputSchema: {
    type: 'object',
    properties: {
      action: { type: 'string' }
    },
    required: ['action']
  }
}, async (params, context) => {
  requireRole('moderator')(context);
  
  // Tool logic here
  return {
    text: `Moderator action completed`
  };
});
```

## Authentication Flow

### Authorization Code Flow with PKCE

The framework implements the OAuth 2.1 Authorization Code flow with PKCE:

1. **Client Request**: Client requests authentication
2. **Authorization URL**: Server generates authorization URL with PKCE challenge
3. **User Authorization**: User authorizes with OAuth provider
4. **Callback**: OAuth provider redirects to callback URL
5. **Token Exchange**: Server exchanges authorization code for tokens
6. **Session Creation**: Server creates authenticated session

### Session Management

```typescript
const httpTransport = new HttpTransport({
  port: 3000,
  auth: oidcProvider,
  session: {
    secret: process.env.SESSION_SECRET!,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
});
```

## Security Considerations

### Production Configuration

```typescript
const oidcProvider = new OIDCProvider({
  issuer: process.env.OIDC_ISSUER!,
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET!,
  redirectUri: process.env.OIDC_REDIRECT_URI!,
  
  // Security settings
  clockTolerance: 60, // 60 seconds
  tokenEndpointAuthMethod: 'client_secret_post',
  responseType: 'code',
  grantType: 'authorization_code',
  
  // PKCE settings
  codeChallenge: true,
  codeChallengeMethod: 'S256'
});
```

### HTTPS Requirements

Always use HTTPS in production:

```typescript
const httpTransport = new HttpTransport({
  port: 443,
  httpsOptions: {
    key: fs.readFileSync('path/to/private-key.pem'),
    cert: fs.readFileSync('path/to/certificate.pem')
  },
  auth: oidcProvider
});
```

### CORS Configuration

Configure CORS appropriately:

```typescript
const httpTransport = new HttpTransport({
  port: 3000,
  auth: oidcProvider,
  cors: {
    origin: ['https://your-frontend.com'],
    credentials: true,
    optionsSuccessStatus: 200
  }
});
```

## Testing Authentication

### Mock Authentication Provider

For testing, create a mock provider:

```typescript
class MockAuthProvider {
  async authenticate(req: any): Promise<any> {
    // Mock user for testing
    return {
      id: 'test-user-123',
      name: 'Test User',
      email: 'test@example.com',
      roles: ['user', 'admin']
    };
  }
  
  async getAuthUrl(): Promise<string> {
    return 'http://localhost:3000/mock-auth';
  }
}

// Use in tests
const mockAuth = new MockAuthProvider();
const httpTransport = new HttpTransport({
  port: 3000,
  auth: mockAuth
});
```

### Testing with Authentication

```typescript
import { MCPServer } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import request from 'supertest';

describe('Authenticated Tools', () => {
  let server: MCPServer;
  let app: any;
  
  beforeEach(async () => {
    server = new MCPServer({
      name: 'test-server',
      version: '1.0.0'
    });
    
    const httpTransport = new HttpTransport({
      port: 3000,
      auth: new MockAuthProvider()
    });
    
    server.useTransport(httpTransport);
    app = httpTransport.app;
  });
  
  it('should require authentication for protected tool', async () => {
    const response = await request(app)
      .post('/tools/admin_tool')
      .send({ action: 'test' });
    
    expect(response.status).toBe(401);
  });
  
  it('should allow authenticated user to use tool', async () => {
    // Mock authenticated session
    const response = await request(app)
      .post('/tools/admin_tool')
      .set('Authorization', 'Bearer mock-token')
      .send({ action: 'test' });
    
    expect(response.status).toBe(200);
  });
});
```

## Common Patterns

### Middleware for Authentication

```typescript
// Create a middleware function
function requireAuth(context: any) {
  if (!context.user) {
    throw new Error('Authentication required');
  }
  return context.user;
}

// Use in multiple tools
server.addTool({
  name: 'protected_tool',
  description: 'Protected tool',
  inputSchema: { type: 'object' }
}, async (params, context) => {
  const user = requireAuth(context);
  
  // Tool logic
  return { text: `Hello, ${user.name}!` };
});
```

### Permission Decorators

```typescript
// Permission decorator
function requirePermission(permission: string) {
  return function(target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function(params: any, context: any) {
      const user = context.user;
      
      if (!user) {
        throw new Error('Authentication required');
      }
      
      if (!user.permissions?.includes(permission)) {
        throw new Error(`Permission '${permission}' required`);
      }
      
      return originalMethod.call(this, params, context);
    };
  };
}

// Use with tools
class MyTools {
  @requirePermission('admin.read')
  async getUsers(params: any, context: any) {
    // Tool implementation
  }
}
```

## Troubleshooting

### Common Issues

1. **Token Validation Errors**
   - Check clock synchronization
   - Verify issuer URL
   - Ensure proper HTTPS configuration

2. **Redirect URI Mismatch**
   - Verify redirect URI in OAuth provider
   - Check for trailing slashes
   - Ensure HTTPS in production

3. **Session Issues**
   - Check session secret configuration
   - Verify cookie settings
   - Check session storage

### Debug Mode

Enable debug logging:

```typescript
const oidcProvider = new OIDCProvider({
  // ... config
  debug: true
});
```

### Token Inspection

```typescript
server.addTool({
  name: 'debug_token',
  description: 'Debug token information',
  inputSchema: { type: 'object' }
}, async (params, context) => {
  const user = context.user;
  
  return {
    text: 'Token information',
    data: {
      user: user,
      tokenExp: user?.tokenExp,
      tokenIat: user?.tokenIat
    }
  };
});
```

## Next Steps

- [Transport Guide](transports.md) - Learn about different transport options
- [Tool Development](tool-development.md) - Advanced tool development
- [Deployment Guide](deployment.md) - Deploy authenticated servers
- [Security Guide](../SECURITY.md) - Security best practices