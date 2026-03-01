import { CallToolResult, ToolAnnotations, Icon } from "@modelcontextprotocol/sdk/types.js";
import { ZodRawShape } from "zod";

export type SdkToolConfig<InputArgs extends ZodRawShape = ZodRawShape> = {
    title?: string;
    description?: string;
    inputSchema?: InputArgs;
    outputSchema?: InputArgs;
    annotations?: ToolAnnotations;
    icons?: Icon[];
}

export interface SdkToolResult extends CallToolResult {
}

/**
 * Create a success result with structured content.
 * When a tool declares an outputSchema, the structuredContent MUST conform to that schema.
 */
export const createSuccessObjectResult = <T>(value: T, message?: string): SdkToolResult => {
    return {
        content: [
            {
                type: 'text',
                text: message ?? JSON.stringify(value),
            },
        ],
        structuredContent: value as any,
    };
};


export const createErrorResult = (error: unknown): SdkToolResult => {
    return {
        content: [
            {
                type: 'text',
                text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
            },
        ],
        isError: true,
    };
};

export const createSuccessResult = (message: string): SdkToolResult => {
    return {
        content: [
            {
                type: 'text',
                text: message,
            },
        ],
    };
};

/**
 * Create a resource link result referencing a server resource.
 * New in MCP 2025-11-25 spec.
 */
export const createResourceLinkResult = (options: {
    uri: string;
    name?: string;
    description?: string;
    mimeType?: string;
    message?: string;
}): SdkToolResult => {
    return {
        content: [
            {
                type: 'resource_link' as any,
                uri: options.uri,
                name: options.name,
                description: options.description,
                mimeType: options.mimeType,
            } as any,
        ],
    };
};
