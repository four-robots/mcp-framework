import { ToolModule, ToolResult } from '@tylercoles/mcp-server';
import {
  CreateCommentSchema,
  CardIdSchema,
  CommentIdSchema,
  NotFoundError,
} from '../../types/index.js';
import { createErrorResult, createSuccessResult } from '@tylercoles/mcp-server/dist/tools.js';
import { KanbanDatabase } from '../../database/index.js';
import { KanbanWebSocketServer } from '../../websocket-server.js';

export const registerAddCommentTool = (db: KanbanDatabase, wsServer: KanbanWebSocketServer): ToolModule => ({
  name: 'add_comment',
  config: {
    title: 'Add Comment',
    description: 'Add a comment to a card',
    inputSchema: CreateCommentSchema,
  },
  handler: async (args: any): Promise<ToolResult> => {
    try {
      const input = CreateCommentSchema.parse(args);

      // Verify card exists before adding comment
      const card = await db.getCardById(input.card_id);
      if (!card) {
        throw new NotFoundError('Card', input.card_id);
      }

      const comment = await db.addComment({
        card_id: input.card_id,
        content: input.content,
        author: input.author || null,
      });

      return createSuccessResult(`✅ Successfully added comment to card ${comment.card_id}`);
    } catch (error) {
      return createErrorResult(error);
    }
  }
});

export const registerGetCommentsTool = (db: KanbanDatabase, wsServer: KanbanWebSocketServer): ToolModule => ({
  name: 'get_comments',
  config: {
    title: 'Get Card Comments',
    description: 'Get all comments for a card',
    inputSchema: CardIdSchema,
  },
  handler: async (args: any): Promise<ToolResult> => {
    try {
      const { card_id } = args;
      const comments = await db.getCardComments(card_id);

      return createSuccessResult(`Found ${comments.length} comments for card ${card_id}:\n\n${comments
        .map(
          (comment) =>
            `**${comment.author || 'Anonymous'}** (${new Date(comment.created_at).toLocaleString()}):\n${comment.content}`
        )
        .join('\n\n')}`);
    } catch (error) {
      return createErrorResult(error);
    }
  }
});

export const registerDeleteCommentTool = (db: KanbanDatabase, wsServer: KanbanWebSocketServer): ToolModule => ({
  name: 'delete_comment',
  config: {
    title: 'Delete Comment',
    description: 'Delete a comment',
    inputSchema: CommentIdSchema,
  },
  handler: async (args: any): Promise<ToolResult> => {
    try {
      const { comment_id } = args;
      const deleted = await db.deleteComment(comment_id);

      if (!deleted) {
        throw new NotFoundError('Comment', comment_id);
      }

      return createSuccessResult(`✅ Successfully deleted comment (ID: ${comment_id})`);
    } catch (error) {
      return createErrorResult(error);
    }
  }
});