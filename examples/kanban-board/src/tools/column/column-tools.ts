import { ToolModule, ToolResult } from '@tylercoles/mcp-server';
import {
  CreateColumnSchema,
  UpdateColumnSchema,
  ColumnIdSchema,
  UpdateColumnWithIdSchema,
  NotFoundError,
} from '../../types/index.js';
import { createErrorResult, createSuccessResult } from '@tylercoles/mcp-server/dist/tools.js';
import { KanbanDatabase } from '../../database/index.js';
import { KanbanWebSocketServer } from '../../websocket-server.js';

export const registerCreateColumnTool = (db: KanbanDatabase, wsServer: KanbanWebSocketServer): ToolModule => ({
  name: 'create_column',
  config: {
    title: 'Create Column',
    description: 'Create a new column in a kanban board',
    inputSchema: CreateColumnSchema,
  },
  handler: async (args: any): Promise<ToolResult> => {
    try {
      const input = CreateColumnSchema.safeParse(args);
      if (input.success) {
        // Verify board exists before creating column
        const board = await db.getBoardById(input.data.board_id);
        if (!board) {
          throw new NotFoundError('Board', input.data.board_id);
        }

        const column = await db.createColumn(input.data as any);

        // Broadcast the column creation to all clients connected to this board
        if (wsServer) {
          wsServer.broadcastToBoardClients(column.board_id!, 'column_created', column);
        }

        return createSuccessResult(`✅ Successfully created column "${column.name}" (ID: ${column.id})`);
      }

      throw input.error;
    } catch (error) {
      return createErrorResult(error);
    }
  }
});

export const registerUpdateColumnTool = (db: KanbanDatabase, wsServer: KanbanWebSocketServer): ToolModule => ({
  name: 'update_column',
  config: {
    title: 'Update Column',
    description: 'Update an existing column',
    inputSchema: UpdateColumnWithIdSchema,
  },
  handler: async (args: any): Promise<ToolResult> => {
    try {
      const { column_id, ...updates } = args;
      const input = UpdateColumnSchema.parse(updates);
      const column = await db.updateColumn(column_id, input);

      if (!column) {
        throw new NotFoundError('Column', column_id);
      }

      // Broadcast the column update to all clients connected to this board
      if (wsServer) {
        wsServer.broadcastToBoardClients(column.board_id!, 'column_updated', column);
      }

      return createSuccessResult(`✅ Successfully updated column "${column.name}" (ID: ${column.id})`);
    } catch (error) {
      return createErrorResult(error);
    }
  }
});

export const registerDeleteColumnTool = (db: KanbanDatabase, wsServer: KanbanWebSocketServer): ToolModule => ({
  name: 'delete_column',
  config: {
    title: 'Delete Column',
    description: 'Delete a column and all its cards',
    inputSchema: ColumnIdSchema,
  },
  handler: async (args: any): Promise<ToolResult> => {
    try {
      const { column_id } = args;

      // Get the column before deleting to get board_id for broadcasting
      const column = await db.getColumn(column_id);
      if (!column) {
        throw new NotFoundError('Column', column_id);
      }

      const deleted = await db.deleteColumn(column_id);

      if (!deleted) {
        throw new NotFoundError('Column', column_id);
      }

      // Broadcast the column deletion to all clients connected to this board
      if (wsServer) {
        wsServer.broadcastToBoardClients(column.board_id, 'column_deleted', { column_id });
      }

      return createSuccessResult(`✅ Successfully deleted column (ID: ${column_id})`);
    } catch (error) {
      return createErrorResult(error);
    }
  }
});