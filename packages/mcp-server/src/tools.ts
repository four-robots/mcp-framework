import { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types";
import { ZodRawShape } from "zod";

export type SdkToolConfig<InputArgs extends ZodRawShape = ZodRawShape> = {
    title?: string;
    description?: string;
    inputSchema?: InputArgs;
    annotations?: ToolAnnotations;
}

export interface SdkToolResult extends CallToolResult {
}

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