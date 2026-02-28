import { z } from 'zod';

// Priority levels for cards
export const PrioritySchema = z.enum(['low', 'medium', 'high', 'urgent']);
export type Priority = z.infer<typeof PrioritySchema>;

// Board schemas
export const CreateBoardSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(2000).optional(),
  color: z.string().regex(/^#[0-9A-Fa-f]{6}$/).default('#6366f1'),
});

export const UpdateBoardSchema = CreateBoardSchema.partial();

export type CreateBoardInput = z.infer<typeof CreateBoardSchema>;
export type UpdateBoardInput = z.infer<typeof UpdateBoardSchema>;

// Column schemas
export const CreateColumnSchema = z.object({
  board_id: z.number().int().positive(),
  name: z.string().min(1).max(255),
  position: z.number().int().min(0).default(0),
  color: z.string().regex(/^#[0-9A-Fa-f]{6}$/).default('#64748b'),
});

export const UpdateColumnSchema = CreateColumnSchema.partial().omit({ board_id: true });

export type CreateColumnInput = z.infer<typeof CreateColumnSchema>;
export type UpdateColumnInput = z.infer<typeof UpdateColumnSchema>;

// Card schemas
export const CreateCardSchema = z.object({
  board_id: z.number().int().positive(),
  column_name: z.string().min(1).max(255).optional(),
  column_position: z.number().int().min(0).optional(),
  title: z.string().min(1).max(255),
  description: z.string().max(5000).optional(),
  position: z.number().int().min(0).default(0),
  priority: PrioritySchema.default('medium'),
  assigned_to: z.string().max(255).optional(),
  due_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
});

export const UpdateCardSchema = CreateCardSchema.partial().omit({ board_id: true });

export const MoveCardSchema = z.object({
  card_id: z.number().int().positive(),
  column_name: z.string().min(1).max(255).optional(),
  column_position: z.number().int().min(0).optional(),
  position: z.number().int().min(0),
});

export type CreateCardInput = z.infer<typeof CreateCardSchema>;
export type UpdateCardInput = z.infer<typeof UpdateCardSchema>;
export type MoveCardInput = z.infer<typeof MoveCardSchema>;

// Tag schemas
export const CreateTagSchema = z.object({
  name: z.string().min(1).max(100),
  color: z.string().regex(/^#[0-9A-Fa-f]{6}$/).default('#64748b'),
});

export type CreateTagInput = z.infer<typeof CreateTagSchema>;

// Comment schemas
export const CreateCommentSchema = z.object({
  card_id: z.number().int().positive(),
  content: z.string().min(1).max(10000),
  author: z.string().max(255).optional(),
});

export type CreateCommentInput = z.infer<typeof CreateCommentSchema>;

// Additional schemas for tools that need simple ID-based inputs
export const BoardIdSchema = z.object({
  board_id: z.number().int().positive(),
});

export const UpdateBoardWithIdSchema = z.object({
  board_id: z.number().int().positive(),
}).merge(UpdateBoardSchema);

export const ColumnIdSchema = z.object({
  column_id: z.number().int().positive(),
});

export const UpdateColumnWithIdSchema = z.object({
  column_id: z.number().int().positive(),
}).merge(UpdateColumnSchema);

export const CardIdSchema = z.object({
  card_id: z.number().int().positive(),
});

export const UpdateCardWithIdSchema = z.object({
  card_id: z.number().int().positive(),
}).merge(UpdateCardSchema);

export const CommentIdSchema = z.object({
  comment_id: z.number().int().positive(),
});

export const CardTagSchema = z.object({
  card_id: z.number().int().positive(),
  tag_id: z.number().int().positive(),
});

export const SearchCardsSchema = z.object({
  query: z.string().min(1).max(500),
  board_id: z.number().int().positive().optional(),
  priority: PrioritySchema.optional(),
  assigned_to: z.string().max(255).optional(),
});

// API response types
export interface KanbanBoardData {
  board: {
    id: number;
    name: string;
    description: string | null;
    color: string;
    created_at: string;
    updated_at: string;
  };
  columns: Array<{
    id: number;
    name: string;
    position: number;
    color: string;
    cards: Array<{
      id: number;
      title: string;
      description: string | null;
      position: number;
      priority: Priority;
      assigned_to: string | null;
      due_date: string | null;
      created_at: string;
      updated_at: string;
      tags: Array<{
        id: number;
        name: string;
        color: string;
      }>;
    }>;
  }>;
}

export interface KanbanStats {
  total_boards: number;
  total_cards: number;
  cards_by_priority: Record<Priority, number>;
  cards_by_status: Record<string, number>;
  overdue_cards: number;
  recent_activity: Array<{
    type: 'card_created' | 'card_moved' | 'card_updated' | 'comment_added';
    card_id: number;
    card_title: string;
    timestamp: string;
    details?: string;
  }>;
}

// Error types
export class KanbanError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 400
  ) {
    super(message);
    this.name = 'KanbanError';
  }
}

export class NotFoundError extends KanbanError {
  constructor(resource: string, id: number | string) {
    super(`${resource} with id ${id} not found`, 'NOT_FOUND', 404);
  }
}

export class ValidationError extends KanbanError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR', 400);
  }
}