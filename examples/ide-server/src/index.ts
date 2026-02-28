#!/usr/bin/env node

import { MCPServer, z } from "@tylercoles/mcp-server";
import { StdioTransport } from "@tylercoles/mcp-transport-stdio";
import { HttpTransport } from "@tylercoles/mcp-transport-http";
import { IMCPClient } from "@tylercoles/mcp-client";
import { StdioMCPClient } from "@tylercoles/mcp-client-stdio";
import { HttpMCPClient } from "@tylercoles/mcp-client-http";
import { spawn, ChildProcess } from "child_process";
import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";

interface ProjectConfig {
    name: string;
    type: "node" | "python" | "react" | "nextjs" | "generic";
    directory: string;
    git?: boolean;
    dependencies?: string[];
}

interface SerenaConfig {
    enabled: boolean;
    transport: "stdio" | "http";
    stdio?: {
        command: string;
        args?: string[];
    };
    http?: {
        url: string;
        headers?: Record<string, string>;
    };
}

class IdeMCPServer {
    private server: MCPServer;
    private serenaClient?: IMCPClient;
    private config: SerenaConfig;

    constructor() {
        this.server = new MCPServer({
            name: "mcp-ide-server",
            version: "1.0.0"
        });

        // Parse Serena configuration from environment or args
        this.config = this.parseSerenaConfig();

        this.setupTools();
        this.setupTransport();
    }

    private parseSerenaConfig(): SerenaConfig {
        // Check for Serena configuration
        const serenaEnabled = process.env.SERENA_ENABLED === 'true' || process.argv.includes('--serena');
        
        if (!serenaEnabled) {
            return { enabled: false, transport: "stdio" };
        }

        const transport = process.env.SERENA_TRANSPORT || 
                         (process.argv.includes('--serena-http') ? 'http' : 'stdio');

        if (transport === 'http') {
            return {
                enabled: true,
                transport: 'http',
                http: {
                    url: process.env.SERENA_URL || 'http://localhost:3000/mcp',
                    headers: process.env.SERENA_HEADERS ? (() => {
                        try {
                            return JSON.parse(process.env.SERENA_HEADERS!);
                        } catch {
                            console.error('Failed to parse SERENA_HEADERS as JSON, ignoring');
                            return undefined;
                        }
                    })() : undefined
                }
            };
        }

        return {
            enabled: true,
            transport: 'stdio',
            stdio: {
                command: process.env.SERENA_COMMAND || 'uvx',
                args: process.env.SERENA_ARGS ? process.env.SERENA_ARGS.split(' ') : [
                    '--from', 'git+https://github.com/oraios/serena',
                    'serena-mcp-server'
                ]
            }
        };
    }

    private async initializeSerena(): Promise<void> {
        if (!this.config.enabled) {
            console.error("Serena integration not enabled");
            return;
        }

        try {
            if (this.config.transport === 'http' && this.config.http) {
                console.error("Connecting to Serena via HTTP:", this.config.http.url);
                this.serenaClient = new HttpMCPClient(this.config.http);
            } else if (this.config.stdio) {
                console.error("Connecting to Serena via stdio:", this.config.stdio.command);
                this.serenaClient = new StdioMCPClient(this.config.stdio);
            }

            if (this.serenaClient) {
                await this.serenaClient.connect();
                console.error("Serena connected successfully");
                
                // Register proxied tools from Serena
                await this.registerSerenaTools();
            }
        } catch (error) {
            console.error("Failed to connect to Serena:", error);
            console.error("Continuing without Serena integration...");
            this.serenaClient = undefined;
        }
    }

    private async registerSerenaTools(): Promise<void> {
        if (!this.serenaClient) return;

        try {
            const tools = await this.serenaClient.listTools();
            console.error(`Found ${tools.length} Serena tools`);

            for (const tool of tools) {
                // Register each Serena tool as a proxied tool
                this.server.registerTool(
                    `serena_${tool.name}`,
                    {
                        title: `Serena: ${tool.title || tool.name}`,
                        description: `${tool.description} (via Serena)`,
                        inputSchema: tool.inputSchema || {}
                    },
                    async (args) => {
                        if (!this.serenaClient) {
                            throw new Error("Serena client not available");
                        }
                        return await this.serenaClient.callTool(tool.name, args);
                    }
                );
            }
        } catch (error) {
            console.error("Failed to register Serena tools:", error);
        }
    }

    private setupTransport(): void {
        // Check for stdio flag first (for backwards compatibility)
        const useStdio = process.argv.includes('--stdio');
        const useHttp = process.argv.includes('--http') || !useStdio; // Default to HTTP
        
        if (useStdio) {
            console.error("Starting stdio transport");
            this.server.useTransport(new StdioTransport({
                logStderr: process.env.DEBUG === 'true'
            }));
        } else {
            const port = parseInt(process.env.PORT || '3000');
            const host = process.env.HOST || '127.0.0.1';
            
            console.error(`Starting StreamableHTTP transport on ${host}:${port}`);
            this.server.useTransport(new HttpTransport({
                port,
                host,
                enableDnsRebindingProtection: true,
                allowedHosts: [host, 'localhost', '127.0.0.1'],
                cors: {
                    origin: true,
                    credentials: true
                }
            }));
        }
    }

    private setupTools(): void {
        // Project Management Tools
        this.server.registerTool(
            "create_project",
            {
                title: "Create Project",
                description: "Create a new project directory with proper structure and initial files",
                inputSchema: z.object({
                    name: z.string().describe("Project name"),
                    type: z.enum(["node", "python", "react", "nextjs", "generic"]).describe("Project type"),
                    directory: z.string().describe("Base directory path"),
                    git: z.boolean().optional().default(true).describe("Initialize git repository"),
                    dependencies: z.array(z.string()).optional().describe("Initial dependencies to install")
                })
            },
            async ({ name, type, directory, git, dependencies }) => {
                return await this.createProject({ name, type, directory, git, dependencies });
            }
        );

        this.server.registerTool(
            "setup_workspace",
            {
                title: "Setup Workspace",
                description: "Set up workspace with common configuration files and folder structure",
                inputSchema: z.object({
                    projectPath: z.string().describe("Path to the project"),
                    includeVSCode: z.boolean().optional().default(true).describe("Include VS Code settings"),
                    includeGitignore: z.boolean().optional().default(true).describe("Include .gitignore"),
                    includeEditorConfig: z.boolean().optional().default(true).describe("Include .editorconfig"),
                    includePrettier: z.boolean().optional().default(true).describe("Include Prettier config")
                })
            },
            async (args) => {
                return await this.setupWorkspace(args);
            }
        );

        this.server.registerTool(
            "manage_dependencies",
            {
                title: "Manage Dependencies",
                description: "Add, remove, or update project dependencies with proper validation",
                inputSchema: z.object({
                    projectPath: z.string().describe("Path to the project"),
                    type: z.enum(["npm", "pip", "cargo"]).describe("Package manager type"),
                    dependencies: z.array(z.string()).optional().describe("Dependencies to add"),
                    devDependencies: z.array(z.string()).optional().describe("Dev dependencies to add (npm only)"),
                    remove: z.array(z.string()).optional().describe("Dependencies to remove")
                })
            },
            async (args) => {
                return await this.manageDependencies(args);
            }
        );

        // Git Tools
        this.setupGitTools();

        // Serena Integration Info Tool
        this.server.registerTool(
            "serena_info",
            {
                title: "Serena Integration Info",
                description: "Get information about Serena integration status and available tools",
                inputSchema: z.object({})
            },
            async () => {
                if (!this.config.enabled) {
                    return {
                        content: [{
                            type: "text" as const,
                            text: "Serena integration is disabled. Enable with --serena or SERENA_ENABLED=true"
                        }]
                    };
                }

                if (!this.serenaClient) {
                    return {
                        content: [{
                            type: "text" as const,
                            text: `Serena integration is enabled but not connected. Transport: ${this.config.transport}\n` +
                                  `This usually means Serena failed to start (check console for errors).`
                        }]
                    };
                }

                try {
                    const tools = await this.serenaClient.listTools();
                    const resources = await this.serenaClient.listResources();
                    
                    return {
                        content: [{
                            type: "text" as const,
                            text: `Serena connected via ${this.config.transport}\n` +
                                  `Available tools: ${tools.length}\n` +
                                  `Available resources: ${resources.length}\n` +
                                  `Tools: ${tools.map((t: any) => t.name).join(', ')}`
                        }]
                    };
                } catch (error) {
                    return {
                        content: [{
                            type: "text" as const,
                            text: `Serena connection error: ${error instanceof Error ? error.message : 'Unknown error'}`
                        }]
                    };
                }
            }
        );

        // Health check tool
        this.server.registerTool(
            "health_check",
            {
                title: "Health Check",
                description: "Check server health and status",
                inputSchema: z.object({})
            },
            async () => {
                const capabilities = this.server.getCapabilities();
                return {
                    content: [{
                        type: "text" as const,
                        text: `IDE MCP Server is healthy\n` +
                              `Tools: ${capabilities.tools.length}\n` +
                              `Resources: ${capabilities.resources.length}\n` +
                              `Prompts: ${capabilities.prompts.length}\n` +
                              `Serena: ${this.serenaClient ? 'Connected' : 'Not connected'}`
                    }]
                };
            }
        );
    }

    private setupGitTools(): void {
        this.server.registerTool(
            "git_commit",
            {
                title: "Git Commit",
                description: "Stage and commit changes with a message",
                inputSchema: z.object({
                    projectPath: z.string().describe("Path to the git repository"),
                    message: z.string().describe("Commit message"),
                    addAll: z.boolean().optional().default(true).describe("Add all changes before committing"),
                    files: z.array(z.string()).optional().describe("Specific files to add (if addAll is false)")
                })
            },
            async (args) => {
                return await this.gitCommit(args);
            }
        );

        this.server.registerTool(
            "git_status",
            {
                title: "Git Status",
                description: "Get git repository status and information",
                inputSchema: z.object({
                    projectPath: z.string().describe("Path to the git repository"),
                    porcelain: z.boolean().optional().default(false).describe("Use porcelain format for parsing")
                })
            },
            async (args) => {
                return await this.gitStatus(args);
            }
        );

        this.server.registerTool(
            "git_clone",
            {
                title: "Git Clone",
                description: "Clone a git repository to a specified directory and return the project path",
                inputSchema: z.object({
                    url: z.string().describe("Git repository URL (https or ssh)"),
                    directory: z.string().describe("Base directory to clone into"),
                    projectName: z.string().optional().describe("Custom project name (defaults to repo name)"),
                    branch: z.string().optional().describe("Specific branch to clone"),
                    depth: z.number().optional().describe("Shallow clone depth (for faster cloning)"),
                    recursive: z.boolean().optional().default(false).describe("Clone submodules recursively"),
                    setupWorkspace: z.boolean().optional().default(false).describe("Automatically setup workspace after clone")
                })
            },
            async (args) => {
                return await this.gitClone(args);
            }
        );
    }

    // Implementation methods (simplified versions - the full implementations would be similar to the original)
    /**
     * Validate that a resolved path stays within the allowed base directory
     */
    private validatePath(basePath: string, targetPath: string): string {
        const resolved = path.resolve(basePath, targetPath);
        const resolvedBase = path.resolve(basePath);
        if (!resolved.startsWith(resolvedBase + path.sep) && resolved !== resolvedBase) {
            throw new Error(`Path traversal detected: target escapes base directory`);
        }
        return resolved;
    }

    private async createProject(config: ProjectConfig) {
        try {
            const projectPath = this.validatePath(config.directory, config.name);
            
            // Create project directory
            await fs.mkdir(projectPath, { recursive: true });
            
            // Initialize based on project type
            switch (config.type) {
                case "node":
                    await this.createNodeProject(projectPath, config);
                    break;
                case "python":
                    await this.createPythonProject(projectPath, config);
                    break;
                case "react":
                    await this.createReactProject(projectPath, config);
                    break;
                case "nextjs":
                    await this.createNextJSProject(projectPath, config);
                    break;
                default:
                    await this.createGenericProject(projectPath, config);
            }

            return {
                content: [{
                    type: "text" as const,
                    text: `Project '${config.name}' created successfully at ${projectPath}`
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text" as const,
                    text: `Failed to create project: ${error instanceof Error ? error.message : 'Unknown error'}`
                }],
                isError: true
            };
        }
    }

    private async createNodeProject(projectPath: string, config: ProjectConfig) {
        const packageJson = {
            name: config.name,
            version: "1.0.0",
            description: "",
            main: "index.js",
            scripts: {
                start: "node index.js",
                test: "echo \"Error: no test specified\" && exit 1"
            },
            dependencies: {},
            devDependencies: {}
        };

        await fs.writeFile(
            path.join(projectPath, "package.json"),
            JSON.stringify(packageJson, null, 2)
        );

        await fs.writeFile(
            path.join(projectPath, "index.js"),
            `console.log("Hello from ${config.name}!");\n`
        );

        if (config.git) {
            await this.execCommand("git", ["init"], { cwd: projectPath });
        }
    }

    private async createPythonProject(projectPath: string, config: ProjectConfig) {
        await fs.writeFile(
            path.join(projectPath, "main.py"),
            `#!/usr/bin/env python3\n\nprint("Hello from ${config.name}!")\n`
        );

        await fs.writeFile(
            path.join(projectPath, "requirements.txt"),
            "# Add your dependencies here\n"
        );

        if (config.git) {
            await this.execCommand("git", ["init"], { cwd: projectPath });
        }
    }

    private async createReactProject(projectPath: string, config: ProjectConfig) {
        // For React, we'd typically use create-react-app or Vite
        // This is a simplified version
        await this.createNodeProject(projectPath, config);
    }

    private async createNextJSProject(projectPath: string, config: ProjectConfig) {
        // For Next.js, we'd typically use create-next-app
        // This is a simplified version
        await this.createNodeProject(projectPath, config);
    }

    private async createGenericProject(projectPath: string, config: ProjectConfig) {
        await fs.writeFile(
            path.join(projectPath, "README.md"),
            `# ${config.name}\n\nA new project.\n`
        );

        if (config.git) {
            await this.execCommand("git", ["init"], { cwd: projectPath });
        }
    }

    private async setupWorkspace(args: any) {
        try {
            const { projectPath, includeVSCode, includeGitignore, includeEditorConfig, includePrettier } = args;
            const actions: string[] = [];

            if (includeVSCode) {
                const vscodeDir = path.join(projectPath, '.vscode');
                await fs.mkdir(vscodeDir, { recursive: true });
                
                const settings = {
                    "editor.formatOnSave": true,
                    "editor.codeActionsOnSave": {
                        "source.fixAll": true
                    }
                };
                
                await fs.writeFile(
                    path.join(vscodeDir, 'settings.json'),
                    JSON.stringify(settings, null, 2)
                );
                actions.push('VS Code settings');
            }

            if (includeGitignore) {
                const gitignore = `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Production
/build
/dist

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Logs
*.log
`;
                await fs.writeFile(path.join(projectPath, '.gitignore'), gitignore);
                actions.push('.gitignore');
            }

            if (includeEditorConfig) {
                const editorconfig = `root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 2

[*.md]
trim_trailing_whitespace = false
`;
                await fs.writeFile(path.join(projectPath, '.editorconfig'), editorconfig);
                actions.push('.editorconfig');
            }

            if (includePrettier) {
                const prettierrc = {
                    "semi": true,
                    "trailingComma": "es5",
                    "singleQuote": false,
                    "printWidth": 80,
                    "tabWidth": 2
                };
                
                await fs.writeFile(
                    path.join(projectPath, '.prettierrc'),
                    JSON.stringify(prettierrc, null, 2)
                );
                actions.push('Prettier config');
            }

            return {
                content: [{
                    type: "text" as const,
                    text: `Workspace setup completed for ${projectPath}\nConfigured: ${actions.join(', ')}`
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text" as const,
                    text: `Failed to setup workspace: ${error instanceof Error ? error.message : 'Unknown error'}`
                }],
                isError: true
            };
        }
    }

    private async manageDependencies(args: any) {
        try {
            const { projectPath, type, dependencies, devDependencies, remove } = args;
            const actions: string[] = [];

            if (type === 'npm') {
                if (dependencies && dependencies.length > 0) {
                    await this.execCommand('npm', ['install', ...dependencies], { cwd: projectPath });
                    actions.push(`Added dependencies: ${dependencies.join(', ')}`);
                }

                if (devDependencies && devDependencies.length > 0) {
                    await this.execCommand('npm', ['install', '--save-dev', ...devDependencies], { cwd: projectPath });
                    actions.push(`Added dev dependencies: ${devDependencies.join(', ')}`);
                }

                if (remove && remove.length > 0) {
                    await this.execCommand('npm', ['uninstall', ...remove], { cwd: projectPath });
                    actions.push(`Removed: ${remove.join(', ')}`);
                }
            } else if (type === 'pip') {
                if (dependencies && dependencies.length > 0) {
                    await this.execCommand('pip', ['install', ...dependencies], { cwd: projectPath });
                    actions.push(`Installed: ${dependencies.join(', ')}`);
                }

                if (remove && remove.length > 0) {
                    await this.execCommand('pip', ['uninstall', '-y', ...remove], { cwd: projectPath });
                    actions.push(`Removed: ${remove.join(', ')}`);
                }
            } else if (type === 'cargo') {
                if (dependencies && dependencies.length > 0) {
                    await this.execCommand('cargo', ['add', ...dependencies], { cwd: projectPath });
                    actions.push(`Added: ${dependencies.join(', ')}`);
                }

                if (remove && remove.length > 0) {
                    await this.execCommand('cargo', ['remove', ...remove], { cwd: projectPath });
                    actions.push(`Removed: ${remove.join(', ')}`);
                }
            }

            return {
                content: [{
                    type: "text" as const,
                    text: `Dependency management completed for ${projectPath}\n${actions.join('\n')}`
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text" as const,
                    text: `Failed to manage dependencies: ${error instanceof Error ? error.message : 'Unknown error'}`
                }],
                isError: true
            };
        }
    }

    private async gitCommit(args: any) {
        try {
            if (args.addAll) {
                await this.execCommand("git", ["add", "."], { cwd: args.projectPath });
            } else if (args.files) {
                await this.execCommand("git", ["add", ...args.files], { cwd: args.projectPath });
            }

            const result = await this.execCommand("git", ["commit", "-m", args.message], { cwd: args.projectPath });
            
            return {
                content: [{
                    type: "text" as const,
                    text: `Commit successful: ${result.stdout}`
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text" as const,
                    text: `Git commit failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }],
                isError: true
            };
        }
    }

    private async gitStatus(args: any) {
        try {
            const gitArgs = ["status"];
            if (args.porcelain) gitArgs.push("--porcelain");
            const result = await this.execCommand("git", gitArgs, { cwd: args.projectPath });
            
            return {
                content: [{
                    type: "text" as const,
                    text: result.stdout
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text" as const,
                    text: `Git status failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }],
                isError: true
            };
        }
    }

    private async gitClone(args: any) {
        try {
            const projectName = args.projectName || path.basename(args.url, '.git');
            const projectPath = this.validatePath(args.directory, projectName);

            const gitArgs = ["clone"];
            if (args.branch) gitArgs.push("-b", args.branch);
            if (args.depth) gitArgs.push("--depth", args.depth.toString());
            if (args.recursive) gitArgs.push("--recursive");
            gitArgs.push(args.url, projectPath);

            const result = await this.execCommand("git", gitArgs);

            if (args.setupWorkspace) {
                await this.setupWorkspace({ projectPath });
            }

            return {
                content: [{
                    type: "text" as const,
                    text: `Repository cloned successfully to ${projectPath}`
                }]
            };
        } catch (error) {
            return {
                content: [{
                    type: "text" as const,
                    text: `Git clone failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }],
                isError: true
            };
        }
    }

    private async execCommand(command: string, args: string[], options?: { cwd?: string }): Promise<{ stdout: string; stderr: string }> {
        const MAX_OUTPUT = 10 * 1024 * 1024; // 10 MB limit
        return new Promise((resolve, reject) => {
            const child = spawn(command, args, {
                cwd: options?.cwd,
                stdio: ['pipe', 'pipe', 'pipe']
            });

            let stdout = '';
            let stderr = '';
            let truncated = false;

            child.stdout?.on('data', (data) => {
                if (stdout.length < MAX_OUTPUT) {
                    stdout += data.toString();
                } else if (!truncated) {
                    truncated = true;
                    stdout += '\n[output truncated]';
                }
            });

            child.stderr?.on('data', (data) => {
                if (stderr.length < MAX_OUTPUT) {
                    stderr += data.toString();
                }
            });

            child.on('close', (code) => {
                if (code === 0) {
                    resolve({ stdout, stderr });
                } else {
                    reject(new Error(`Command failed with code ${code}: ${stderr}`));
                }
            });

            child.on('error', reject);
        });
    }

    async start() {
        // Initialize Serena if enabled
        await this.initializeSerena();
        
        // Start the server
        await this.server.start();
        console.error("IDE MCP Server started successfully");
    }

    async stop() {
        if (this.serenaClient) {
            await this.serenaClient.disconnect();
        }
        await this.server.stop();
    }
}

// Start the server
const server = new IdeMCPServer();

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.error("Shutting down gracefully...");
    await server.stop();
    process.exit(0);
});

server.start().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
});
