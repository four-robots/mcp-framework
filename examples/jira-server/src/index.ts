import { MCPServer, z } from "@tylercoles/mcp-server";
import { HttpTransport } from "@tylercoles/mcp-transport-http";
import { StdioTransport } from "@tylercoles/mcp-transport-stdio";
import { BearerTokenAuth, NoAuth } from "@tylercoles/mcp-auth";
import fetch from "node-fetch";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

interface JiraConfig {
    baseUrl: string;
    email: string;
    apiToken: string;
}

// Jira API response types
interface JiraIssue {
    key: string;
    id: string;
    fields: {
        summary: string;
        description?: {
            content?: Array<{
                content?: Array<{
                    text?: string;
                }>;
            }>;
        };
        status: {
            name: string;
            id: string;
        };
        issuetype: {
            name: string;
            id: string;
        };
        priority?: {
            name: string;
            id: string;
        };
        assignee?: {
            displayName: string;
            name: string;
            emailAddress: string;
        };
        reporter?: {
            displayName: string;
            name: string;
            emailAddress: string;
        };
        created: string;
        updated: string;
        duedate?: string;
        [key: string]: any; // For custom fields
    };
}

interface JiraSearchResult {
    issues: JiraIssue[];
    total: number;
    maxResults: number;
    startAt: number;
}

interface JiraProject {
    key: string;
    id: string;
    name: string;
    projectTypeKey: string;
    lead?: {
        displayName: string;
        name: string;
    };
    issueTypes: JiraIssueType[];
}

interface JiraIssueType {
    id: string;
    name: string;
    description?: string;
    iconUrl?: string;
}

interface JiraField {
    id: string;
    name: string;
    description?: string;
    custom: boolean;
    schema?: {
        type: string;
        system?: string;
        items?: string;
    };
}

interface JiraTransition {
    id: string;
    name: string;
    to: {
        id: string;
        name: string;
    };
}

interface JiraTransitionsResponse {
    transitions: JiraTransition[];
}

interface JiraCreateIssueResult {
    key: string;
    id: string;
}

interface JiraUser {
    id: string;
    username: string;
    email: string;
    groups: string[];
}

/**
 * Custom Bearer Token Auth for Jira API token authentication
 */
class JiraAuth extends BearerTokenAuth {
    private config: JiraConfig;

    constructor(config: JiraConfig) {
        super();
        this.config = config;
    }

    async verifyToken(token: string): Promise<JiraUser | null> {
        // For Jira, we don't verify the token from requests
        // Instead, we use the configured API token
        if (token !== this.config.apiToken) {
            return null;
        }

        // Return a simple user object
        return {
            id: this.config.email,
            username: this.config.email,
            email: this.config.email,
            groups: ["jira-users"],
        };
    }
}

/**
 * Jira MCP Server implementation
 */
async function createJiraServer() {
    const config: JiraConfig = {
        baseUrl: process.env.JIRA_BASE_URL || "",
        email: process.env.JIRA_EMAIL || "",
        apiToken: process.env.JIRA_API_TOKEN || "",
    };

    if (!config.baseUrl || !config.email || !config.apiToken) {
        throw new Error("Missing required environment variables: JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN");
    }

    const server = new MCPServer({
        name: "jira-server",
        version: "1.0.0",
    });

    // Validate Jira issue key format (e.g., PROJ-123)
    const isValidIssueKey = (key: string): boolean => /^[A-Z][A-Z0-9_]+-\d+$/.test(key);

    // Validate Jira project key format (e.g., PROJ)
    const isValidProjectKey = (key: string): boolean => /^[A-Z][A-Z0-9_]+$/.test(key);

    // Escape user input for safe JQL string interpolation
    const escapeJql = (value: string): string => value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

    // Helper function to make Jira API requests
    const makeJiraRequest = async <T = any>(endpoint: string, method: string = "GET", body?: any): Promise<T> => {
        const url = `${config.baseUrl}/rest/api/3${endpoint}`;
        const auth = Buffer.from(`${config.email}:${config.apiToken}`).toString("base64");

        const options: any = {
            method,
            headers: {
                Authorization: `Basic ${auth}`,
                Accept: "application/json",
                "Content-Type": "application/json",
            },
        };

        if (body) {
            options.body = JSON.stringify(body);
        }

        const response = await fetch(url, options);

        if (!response.ok) {
            throw new Error(`Jira API request failed: ${response.status} ${response.statusText}`);
        }

        return (await response.json()) as T;
    };

    // Search Issues Tool
    server.registerTool(
        "search_issues",
        {
            title: "Search Jira Issues",
            description: "Search for Jira issues using JQL (Jira Query Language)",
            inputSchema: z.object({
                jql: z.string().describe("JQL query to search for issues"),
                maxResults: z.number().optional().default(50).describe("Maximum number of results to return"),
            }),
        },
        async ({ jql, maxResults = 50 }) => {
            try {
                const result = await makeJiraRequest<JiraSearchResult>(`/search?jql=${encodeURIComponent(jql)}&maxResults=${maxResults}`);

                return {
                    content: [
                        {
                            type: "text",
                            text: `Found ${result.total} issues:\n\n` + result.issues.map((issue) => `• ${issue.key}: ${issue.fields.summary}\n  Status: ${issue.fields.status.name}\n  Type: ${issue.fields.issuetype.name}`).join("\n\n"),
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error searching issues: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Get Issues Assigned to User Tool
    server.registerTool(
        "get_assigned_issues",
        {
            title: "Get Assigned Issues",
            description: "Get issues assigned to a specific user or current user",
            inputSchema: z.object({
                assignee: z.string().optional().describe('Username, email, or "currentUser()" for current user. Leave empty for current user.'),
                status: z.string().optional().describe('Filter by status (e.g., "To Do", "In Progress", "Done")'),
                project: z.string().optional().describe("Filter by project key"),
                maxResults: z.number().optional().default(50).describe("Maximum number of results to return"),
            }),
        },
        async ({ assignee, status, project, maxResults = 50 }) => {
            try {
                // Build JQL query
                let jqlParts = [];

                // Assignee filter
                if (assignee) {
                    if (assignee.toLowerCase() === "currentuser()" || assignee === "") {
                        jqlParts.push("assignee = currentUser()");
                    } else {
                        jqlParts.push(`assignee = "${escapeJql(assignee)}"`);
                    }
                } else {
                    jqlParts.push("assignee = currentUser()");
                }

                // Status filter
                if (status) {
                    jqlParts.push(`status = "${escapeJql(status)}"`);
                }

                // Project filter
                if (project) {
                    if (!isValidProjectKey(project)) {
                        throw new Error(`Invalid project key format: "${project}". Expected uppercase letters/digits (e.g., PROJ)`);
                    }
                    jqlParts.push(`project = "${escapeJql(project)}"`);
                }

                const jql = jqlParts.join(" AND ");

                const result = await makeJiraRequest<JiraSearchResult>(`/search?jql=${encodeURIComponent(jql)}&maxResults=${maxResults}`);

                if (result.total === 0) {
                    const assigneeText = assignee || "current user";
                    return {
                        content: [
                            {
                                type: "text",
                                text: `No issues found assigned to ${assigneeText}${status ? ` with status "${status}"` : ""}${project ? ` in project "${project}"` : ""}.`,
                            },
                        ],
                    };
                }

                const assigneeText = assignee || "current user";
                const issuesList = result.issues
                    .map((issue) => {
                        const priority = issue.fields.priority?.name || "None";
                        const dueDate = issue.fields.duedate ? `\n  Due: ${new Date(issue.fields.duedate).toLocaleDateString()}` : "";
                        return `• ${issue.key}: ${issue.fields.summary}\n  Status: ${issue.fields.status.name}\n  Type: ${issue.fields.issuetype.name}\n  Priority: ${priority}${dueDate}`;
                    })
                    .join("\n\n");

                return {
                    content: [
                        {
                            type: "text",
                            text: `Found ${result.total} issues assigned to ${assigneeText}:\n\n${issuesList}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error getting assigned issues: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Get Issue Details Tool
    server.registerTool(
        "get_issue",
        {
            title: "Get Issue Details",
            description: "Get detailed information about a specific Jira issue",
            inputSchema: z.object({
                issueKey: z.string().describe("The issue key (e.g., PROJ-123)"),
            }),
        },
        async ({ issueKey }) => {
            try {
                if (!isValidIssueKey(issueKey)) {
                    throw new Error(`Invalid issue key format: "${issueKey}". Expected format: PROJECT-123`);
                }
                const issue = await makeJiraRequest<JiraIssue>(`/issue/${issueKey}`);

                let details = `Issue: ${issue.key}\nSummary: ${issue.fields.summary}\nStatus: ${issue.fields.status.name}\nType: ${issue.fields.issuetype.name}\nPriority: ${issue.fields.priority?.name || "None"}\nAssignee: ${issue.fields.assignee?.displayName || "Unassigned"}\nReporter: ${issue.fields.reporter?.displayName || "Unknown"}\nCreated: ${new Date(issue.fields.created).toLocaleDateString()}\nUpdated: ${new Date(issue.fields.updated).toLocaleDateString()}\n\nDescription:\n${issue.fields.description?.content?.[0]?.content?.[0]?.text || "No description"}`;

                // Add custom fields if present
                const customFieldEntries = Object.entries(issue.fields).filter(([key, value]) => key.startsWith("customfield_") && value !== null);

                if (customFieldEntries.length > 0) {
                    // Get field metadata to map IDs to names
                    const allFields = await makeJiraRequest<JiraField[]>("/field");
                    const fieldMap = new Map(allFields.map((f) => [f.id, f]));

                    details += `\n\nCustom Fields:`;

                    for (const [fieldId, value] of customFieldEntries) {
                        const fieldMeta = fieldMap.get(fieldId);
                        const fieldName = fieldMeta?.name || fieldId;

                        // Format the value
                        let formattedValue = "";
                        if (typeof value === "object" && value !== null) {
                            if (Array.isArray(value)) {
                                formattedValue = value.map((item: any) => item.value || item.name || item.displayName || JSON.stringify(item)).join(", ");
                            } else if ((value as any).value !== undefined) {
                                formattedValue = (value as any).value;
                            } else if ((value as any).displayName !== undefined) {
                                formattedValue = (value as any).displayName;
                            } else if ((value as any).name !== undefined) {
                                formattedValue = (value as any).name;
                            } else {
                                formattedValue = JSON.stringify(value);
                            }
                        } else {
                            formattedValue = String(value);
                        }

                        details += `\n${fieldName}: ${formattedValue}`;
                    }
                }

                return {
                    content: [
                        {
                            type: "text",
                            text: details,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error getting issue: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Create Issue Tool
    server.registerTool(
        "create_issue",
        {
            title: "Create Jira Issue",
            description: "Create a new issue in a Jira project",
            inputSchema: z.object({
                projectKey: z.string().describe("The project key"),
                summary: z.string().describe("Issue summary"),
                description: z.string().optional().describe("Issue description"),
                issueType: z.string().describe("Issue type (e.g., Story, Bug, Task)"),
                priority: z.string().optional().default("Medium").describe("Priority level"),
                customFields: z.record(z.any()).optional().describe("Custom field values as key-value pairs (fieldId or fieldName: value)"),
            }),
        },
        async ({ projectKey, summary, description, issueType, priority = "Medium", customFields }) => {
            try {
                if (!isValidProjectKey(projectKey)) {
                    throw new Error(`Invalid project key format: "${projectKey}". Expected uppercase letters/digits (e.g., PROJ)`);
                }
                const issueData: any = {
                    fields: {
                        project: { key: projectKey },
                        summary,
                        description: description
                            ? {
                                  type: "doc",
                                  version: 1,
                                  content: [
                                      {
                                          type: "paragraph",
                                          content: [
                                              {
                                                  type: "text",
                                                  text: description,
                                              },
                                          ],
                                      },
                                  ],
                              }
                            : undefined,
                        issuetype: { name: issueType },
                        priority: { name: priority },
                    },
                };

                // Add custom fields if provided
                if (customFields) {
                    // Get field metadata to resolve field names to IDs
                    const allFields = await makeJiraRequest<JiraField[]>("/field");
                    const fieldMap = new Map(allFields.map((f) => [f.name, f]));
                    const fieldIdMap = new Map(allFields.map((f) => [f.id, f]));

                    for (const [fieldKey, value] of Object.entries(customFields)) {
                        if (value === null || value === undefined) continue;

                        // Find field by name or ID
                        let fieldMeta = fieldMap.get(fieldKey) || fieldIdMap.get(fieldKey);
                        if (!fieldMeta) {
                            console.error(`Warning: Custom field "${fieldKey}" not found, skipping`);
                            continue;
                        }

                        const fieldId = fieldMeta.id;
                        const fieldType = fieldMeta.schema?.type;
                        const fieldSystem = fieldMeta.schema?.system;

                        // Format the value based on field type
                        let formattedValue: any = value;

                        if (fieldType === "option") {
                            // Single select field
                            formattedValue = { value: String(value) };
                        } else if (fieldType === "array" && fieldSystem === "option") {
                            // Multi-select field
                            const values = Array.isArray(value) ? value : [value];
                            formattedValue = values.map((v: any) => ({ value: String(v) }));
                        } else if (fieldType === "user") {
                            // User field
                            formattedValue = { name: String(value) };
                        } else if (fieldType === "number") {
                            // Number field
                            formattedValue = Number(value);
                        }
                        // For other types (string, date, etc.), use the value as-is

                        issueData.fields[fieldId] = formattedValue;
                    }
                }

                const result = await makeJiraRequest<JiraCreateIssueResult>("/issue", "POST", issueData);

                return {
                    content: [
                        {
                            type: "text",
                            text: `Created issue: ${result.key}\nURL: ${config.baseUrl}/browse/${result.key}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error creating issue: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Update Issue Tool
    server.registerTool(
        "update_issue",
        {
            title: "Update Jira Issue",
            description: "Update an existing Jira issue",
            inputSchema: z.object({
                issueKey: z.string().describe("The issue key to update"),
                summary: z.string().optional().describe("New summary"),
                description: z.string().optional().describe("New description"),
                status: z.string().optional().describe("New status"),
                customFields: z.record(z.any()).optional().describe("Custom field values to update as key-value pairs (fieldId or fieldName: value)"),
            }),
        },
        async ({ issueKey, summary, description, status, customFields }) => {
            try {
                if (!isValidIssueKey(issueKey)) {
                    throw new Error(`Invalid issue key format: "${issueKey}". Expected format: PROJECT-123`);
                }
                const updateData: any = { fields: {} };

                if (summary) updateData.fields.summary = summary;
                if (description) {
                    updateData.fields.description = {
                        type: "doc",
                        version: 1,
                        content: [
                            {
                                type: "paragraph",
                                content: [
                                    {
                                        type: "text",
                                        text: description,
                                    },
                                ],
                            },
                        ],
                    };
                }

                // Add custom fields if provided
                if (customFields) {
                    // Get field metadata to resolve field names to IDs
                    const allFields = await makeJiraRequest<JiraField[]>("/field");
                    const fieldMap = new Map(allFields.map((f) => [f.name, f]));
                    const fieldIdMap = new Map(allFields.map((f) => [f.id, f]));

                    for (const [fieldKey, value] of Object.entries(customFields)) {
                        // Find field by name or ID
                        let fieldMeta = fieldMap.get(fieldKey) || fieldIdMap.get(fieldKey);
                        if (!fieldMeta) {
                            console.error(`Warning: Custom field "${fieldKey}" not found, skipping`);
                            continue;
                        }

                        const fieldId = fieldMeta.id;
                        const fieldType = fieldMeta.schema?.type;
                        const fieldSystem = fieldMeta.schema?.system;

                        // Format the value based on field type
                        let formattedValue: any = value;

                        if (value === null) {
                            formattedValue = null;
                        } else if (fieldType === "option") {
                            // Single select field
                            formattedValue = { value: String(value) };
                        } else if (fieldType === "array" && fieldSystem === "option") {
                            // Multi-select field
                            const values = Array.isArray(value) ? value : [value];
                            formattedValue = values.map((v: any) => ({ value: String(v) }));
                        } else if (fieldType === "user") {
                            // User field
                            formattedValue = { name: String(value) };
                        } else if (fieldType === "number") {
                            // Number field
                            formattedValue = Number(value);
                        }
                        // For other types (string, date, etc.), use the value as-is

                        updateData.fields[fieldId] = formattedValue;
                    }
                }

                if (Object.keys(updateData.fields).length > 0) {
                    await makeJiraRequest(`/issue/${issueKey}`, "PUT", updateData);
                }

                // Handle status transition if provided
                if (status) {
                    const transitions = await makeJiraRequest<JiraTransitionsResponse>(`/issue/${issueKey}/transitions`);
                    const transition = transitions.transitions.find((t) => t.to.name.toLowerCase() === status.toLowerCase());

                    if (transition) {
                        await makeJiraRequest(`/issue/${issueKey}/transitions`, "POST", {
                            transition: { id: transition.id },
                        });
                    } else {
                        throw new Error(`Status "${status}" not available for this issue`);
                    }
                }

                return {
                    content: [
                        {
                            type: "text",
                            text: `Successfully updated issue ${issueKey}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error updating issue: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Add Comment Tool
    server.registerTool(
        "add_comment",
        {
            title: "Add Comment",
            description: "Add a comment to a Jira issue",
            inputSchema: z.object({
                issueKey: z.string().describe("The issue key"),
                comment: z.string().describe("Comment text"),
            }),
        },
        async ({ issueKey, comment }) => {
            try {
                if (!isValidIssueKey(issueKey)) {
                    throw new Error(`Invalid issue key format: "${issueKey}". Expected format: PROJECT-123`);
                }
                const commentData = {
                    body: {
                        type: "doc",
                        version: 1,
                        content: [
                            {
                                type: "paragraph",
                                content: [
                                    {
                                        type: "text",
                                        text: comment,
                                    },
                                ],
                            },
                        ],
                    },
                };

                await makeJiraRequest(`/issue/${issueKey}/comment`, "POST", commentData);

                return {
                    content: [
                        {
                            type: "text",
                            text: `Added comment to ${issueKey}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error adding comment: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Get Projects Tool
    server.registerTool(
        "get_projects",
        {
            title: "Get Projects",
            description: "List all available Jira projects",
            inputSchema: z.object({}),
        },
        async () => {
            try {
                const projects = await makeJiraRequest<JiraProject[]>("/project");

                const projectList = projects.map((project) => `• ${project.key}: ${project.name}\n  Type: ${project.projectTypeKey}\n  Lead: ${project.lead?.displayName || "Unknown"}`).join("\n\n");

                return {
                    content: [
                        {
                            type: "text",
                            text: `Available Projects:\n\n${projectList}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error getting projects: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Get Issue Types Tool
    server.registerTool(
        "get_issue_types",
        {
            title: "Get Issue Types",
            description: "Get available issue types for a project",
            inputSchema: z.object({
                projectKey: z.string().describe("The project key"),
            }),
        },
        async ({ projectKey }) => {
            try {
                if (!isValidProjectKey(projectKey)) {
                    throw new Error(`Invalid project key format: "${projectKey}". Expected uppercase letters/digits (e.g., PROJ)`);
                }
                const project = await makeJiraRequest<JiraProject>(`/project/${projectKey}`);

                const typesList = project.issueTypes.map((type) => `• ${type.name}: ${type.description || "No description"}`).join("\n");

                return {
                    content: [
                        {
                            type: "text",
                            text: `Issue Types for ${projectKey}:\n\n${typesList}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error getting issue types: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Get Custom Fields Tool
    server.registerTool(
        "get_custom_fields",
        {
            title: "Get Custom Fields",
            description: "Get custom fields available in Jira with their IDs and types",
            inputSchema: z.object({
                projectKey: z.string().optional().describe("Filter by project key to see project-specific fields"),
                search: z.string().optional().describe("Search term to filter field names"),
            }),
        },
        async ({ projectKey, search }) => {
            try {
                let endpoint = "/field";
                if (projectKey) {
                    // Get project-specific fields
                    endpoint = `/project/${projectKey}/fields`;
                }

                const fields = await makeJiraRequest<JiraField[]>(endpoint);

                // Filter to custom fields (they start with customfield_)
                let customFields = fields.filter((field) => field.id.startsWith("customfield_") || field.custom);

                // Apply search filter if provided
                if (search) {
                    const searchLower = search.toLowerCase();
                    customFields = customFields.filter((field) => field.name.toLowerCase().includes(searchLower) || field.id.toLowerCase().includes(searchLower));
                }

                if (customFields.length === 0) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: search ? `No custom fields found matching "${search}"${projectKey ? ` in project ${projectKey}` : ""}.` : `No custom fields found${projectKey ? ` in project ${projectKey}` : ""}.`,
                            },
                        ],
                    };
                }

                const fieldsList = customFields
                    .map((field) => {
                        const fieldType = field.schema?.type || "unknown";
                        const description = field.description ? `\n  Description: ${field.description}` : "";
                        return `• ${field.name} (${field.id})\n  Type: ${fieldType}${description}`;
                    })
                    .join("\n\n");

                return {
                    content: [
                        {
                            type: "text",
                            text: `Custom Fields${projectKey ? ` for ${projectKey}` : ""}:\n\n${fieldsList}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error getting custom fields: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Get Issue Custom Fields Tool
    server.registerTool(
        "get_issue_custom_fields",
        {
            title: "Get Issue Custom Fields",
            description: "Get custom field values for a specific issue",
            inputSchema: z.object({
                issueKey: z.string().describe("The issue key (e.g., PROJ-123)"),
                fieldNames: z.array(z.string()).optional().describe("Specific custom field names to retrieve (if not provided, gets all)"),
            }),
        },
        async ({ issueKey, fieldNames }) => {
            try {
                if (!isValidIssueKey(issueKey)) {
                    throw new Error(`Invalid issue key format: "${issueKey}". Expected format: PROJECT-123`);
                }
                const issue = await makeJiraRequest<JiraIssue>(`/issue/${issueKey}`);
                const fields = issue.fields;

                // Get all custom fields (start with customfield_ or have custom schema)
                const customFieldEntries = Object.entries(fields).filter(([key, value]) => key.startsWith("customfield_") && value !== null);

                if (customFieldEntries.length === 0) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `No custom fields found for issue ${issueKey}.`,
                            },
                        ],
                    };
                }

                // Get field metadata to map IDs to names
                const allFields = await makeJiraRequest<JiraField[]>("/field");
                const fieldMap = new Map(allFields.map((f) => [f.id, f]));

                let customFieldsData: string[] = [];

                for (const [fieldId, value] of customFieldEntries) {
                    const fieldMeta = fieldMap.get(fieldId);
                    const fieldName = fieldMeta?.name || fieldId;

                    // Skip if specific fields requested and this isn't one of them
                    if (fieldNames && !fieldNames.includes(fieldName) && !fieldNames.includes(fieldId)) {
                        continue;
                    }

                    // Format the value based on type
                    let formattedValue = "";
                    if (typeof value === "object" && value !== null) {
                        if (Array.isArray(value)) {
                            // Handle arrays (like multi-select fields)
                            formattedValue = value.map((item: any) => item.value || item.name || item.displayName || JSON.stringify(item)).join(", ");
                        } else if ((value as any).value !== undefined) {
                            // Handle single select fields
                            formattedValue = (value as any).value;
                        } else if ((value as any).displayName !== undefined) {
                            // Handle user fields
                            formattedValue = (value as any).displayName;
                        } else if ((value as any).name !== undefined) {
                            // Handle other named objects
                            formattedValue = (value as any).name;
                        } else {
                            // Fallback to JSON representation
                            formattedValue = JSON.stringify(value, null, 2);
                        }
                    } else {
                        formattedValue = String(value);
                    }

                    const fieldType = fieldMeta?.schema?.type || "unknown";
                    customFieldsData.push(`• ${fieldName} (${fieldId})\n  Type: ${fieldType}\n  Value: ${formattedValue}`);
                }

                if (customFieldsData.length === 0) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: fieldNames ? `No matching custom fields found for issue ${issueKey}.` : `No custom field values found for issue ${issueKey}.`,
                            },
                        ],
                    };
                }

                return {
                    content: [
                        {
                            type: "text",
                            text: `Custom Fields for ${issueKey}:\n\n${customFieldsData.join("\n\n")}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error getting issue custom fields: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    // Set Issue Custom Field Tool
    server.registerTool(
        "set_issue_custom_field",
        {
            title: "Set Issue Custom Field",
            description: "Set a custom field value for an issue",
            inputSchema: z.object({
                issueKey: z.string().describe("The issue key (e.g., PROJ-123)"),
                fieldId: z.string().describe("Custom field ID (e.g., customfield_10001) or field name"),
                value: z.union([z.string(), z.number(), z.boolean(), z.array(z.string()), z.null()]).describe("The value to set (format depends on field type)"),
                valueType: z.enum(["text", "number", "select", "multiselect", "user", "date", "datetime"]).optional().describe("Type hint for value formatting"),
            }),
        },
        async ({ issueKey, fieldId, value, valueType }) => {
            try {
                if (!isValidIssueKey(issueKey)) {
                    throw new Error(`Invalid issue key format: "${issueKey}". Expected format: PROJECT-123`);
                }
                // Get field metadata to understand the field type
                const allFields = await makeJiraRequest<JiraField[]>("/field");
                let fieldMeta = allFields.find((f) => f.id === fieldId || f.name === fieldId);

                if (!fieldMeta) {
                    throw new Error(`Custom field "${fieldId}" not found`);
                }

                const actualFieldId = fieldMeta.id;
                const fieldType = fieldMeta.schema?.type;
                const fieldSystem = fieldMeta.schema?.system;

                // Format the value based on field type
                let formattedValue: any = value;

                if (value === null) {
                    formattedValue = null;
                } else if (fieldType === "option" || valueType === "select") {
                    // Single select field
                    formattedValue = { value: String(value) };
                } else if ((fieldType === "array" && fieldSystem === "option") || valueType === "multiselect") {
                    // Multi-select field
                    const values = Array.isArray(value) ? value : [value];
                    formattedValue = values.map((v: any) => ({ value: String(v) }));
                } else if (fieldType === "user" || valueType === "user") {
                    // User field
                    formattedValue = { name: String(value) };
                } else if (fieldType === "date" || valueType === "date") {
                    // Date field (YYYY-MM-DD format)
                    formattedValue = String(value);
                } else if (fieldType === "datetime" || valueType === "datetime") {
                    // DateTime field (ISO format)
                    formattedValue = String(value);
                } else if (fieldType === "number" || valueType === "number") {
                    // Number field
                    formattedValue = Number(value);
                } else {
                    // Default to string or preserve original value
                    formattedValue = value;
                }

                const updateData = {
                    fields: {
                        [actualFieldId]: formattedValue,
                    },
                };

                await makeJiraRequest(`/issue/${issueKey}`, "PUT", updateData);

                return {
                    content: [
                        {
                            type: "text",
                            text: `Successfully set custom field "${fieldMeta.name}" (${actualFieldId}) for issue ${issueKey}`,
                        },
                    ],
                };
            } catch (error) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error setting custom field: ${error instanceof Error ? error.message : String(error)}`,
                        },
                    ],
                    isError: true,
                };
            }
        }
    );

    return server;
}

async function main() {
    try {
        const server = await createJiraServer();

        // Determine transport based on environment
        const transportType = process.env.TRANSPORT || "stdio";

        if (transportType === "http") {
            const port = parseInt(process.env.PORT || "3000", 10);
            const useAuth = process.env.USE_AUTH !== "false";

            const config: JiraConfig = {
                baseUrl: process.env.JIRA_BASE_URL || "",
                email: process.env.JIRA_EMAIL || "",
                apiToken: process.env.JIRA_API_TOKEN || "",
            };

            const transport = new HttpTransport({
                port,
                host: "127.0.0.1",
                auth: useAuth ? new JiraAuth(config) : new NoAuth(),
                cors: {
                    origin: true,
                },
            });

            server.useTransport(transport);
            await server.start();

            console.log(`[Jira Server] HTTP server started on http://127.0.0.1:${port}`);
            console.log(`[Jira Server] Auth: ${useAuth ? "Jira API Token" : "Disabled"}`);
        } else {
            // Default to stdio
            const transport = new StdioTransport({
                logStderr: process.env.DEBUG === "true",
            });

            server.useTransport(transport);
            await server.start();

            if (process.env.DEBUG === "true") {
                console.error("[Jira Server] Started on stdio transport (debug mode)");
            }
        }
    } catch (error) {
        console.error("[Jira Server] Failed to start:", error);
        process.exit(1);
    }
}

// Handle shutdown
process.on("SIGINT", () => {
    if (process.env.TRANSPORT === "http") {
        console.log("\n[Jira Server] Shutting down...");
    }
    process.exit(0);
});

// Run the server
main();
