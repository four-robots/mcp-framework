import { WebSocketServer, WebSocket } from 'ws';
import { IncomingMessage } from 'http';
import { KanbanDatabase } from './database';

interface WebSocketMessage {
  type: string;
  payload?: any;
  id?: string;
}

interface WebSocketResponse {
  type: string;
  payload?: any;
  id?: string;
}

interface ConnectedClient {
  ws: WebSocket;
  id: string;
  boardId?: number;
}

export class KanbanWebSocketServer {
  private wss: WebSocketServer;
  private clients: Map<string, ConnectedClient> = new Map();
  private db: KanbanDatabase;

  constructor(port: number, db: KanbanDatabase) {
    this.db = db;
    this.wss = new WebSocketServer({ port });
    
    this.wss.on('connection', (ws: WebSocket, request: IncomingMessage) => {
      this.handleConnection(ws, request);
    });
    
    console.log(`WebSocket server started on port ${port}`);
  }

  private handleConnection(ws: WebSocket, request: IncomingMessage): void {
    const clientId = this.generateClientId();
    const client: ConnectedClient = { ws, id: clientId };
    
    this.clients.set(clientId, client);
    console.log(`Client ${clientId} connected`);

    ws.on('message', async (data: Buffer) => {
      let messageId: string | undefined;
      try {
        const message: WebSocketMessage = JSON.parse(data.toString());
        messageId = message.id;
        await this.handleMessage(client, message);
      } catch (error) {
        console.error('Error handling message:', error);
        this.sendError(client, 'Invalid message format', messageId);
      }
    });

    ws.on('close', () => {
      this.clients.delete(clientId);
      console.log(`Client ${clientId} disconnected`);
    });

    ws.on('error', (error) => {
      console.error(`Client ${clientId} error:`, error);
      this.clients.delete(clientId);
    });

    // Send welcome message
    this.sendResponse(client, 'connected', { clientId });
  }

  private async handleMessage(client: ConnectedClient, message: WebSocketMessage): Promise<void> {
    const { type, payload, id } = message;

    try {
      let result: any;

      switch (type) {
        // Board operations
        case 'get_boards':
          result = await this.handleGetBoards();
          break;
        case 'get_board':
          result = await this.handleGetBoard(payload);
          if (payload?.board_id) {
            client.boardId = payload.board_id;
          }
          break;
        case 'create_board':
          result = await this.handleCreateBoard(payload);
          this.broadcastToAll('board_created', result);
          break;
        case 'update_board':
          result = await this.handleUpdateBoard(payload);
          this.broadcastToAll('board_updated', result);
          break;
        case 'delete_board':
          result = await this.handleDeleteBoard(payload);
          this.broadcastToAll('board_deleted', { board_id: payload.board_id });
          break;

        // Column operations
        case 'create_column':
          result = await this.handleCreateColumn(payload);
          this.broadcastToBoardClients(payload.board_id, 'column_created', result);
          break;
        case 'update_column':
          result = await this.handleUpdateColumn(payload);
          this.broadcastToBoardClients(result.board_id, 'column_updated', result);
          break;
        case 'delete_column':
          result = await this.handleDeleteColumn(payload);
          this.broadcastToBoardClients(result.board_id, 'column_deleted', { column_id: payload.column_id });
          break;

        // Card operations
        case 'create_card':
          result = await this.handleCreateCard(payload);
          this.broadcastToBoardClients(payload.board_id, 'card_created', result);
          break;
        case 'update_card':
          result = await this.handleUpdateCard(payload);
          this.broadcastToBoardClients(result.board_id, 'card_updated', result);
          break;
        case 'move_card':
          result = await this.handleMoveCard(payload);
          this.broadcastToBoardClients(result.board_id, 'card_moved', result);
          break;
        case 'delete_card':
          result = await this.handleDeleteCard(payload);
          this.broadcastToBoardClients(result.board_id, 'card_deleted', { card_id: payload.card_id });
          break;

        // Tag operations
        case 'get_tags':
          result = await this.handleGetTags();
          break;
        case 'create_tag':
          result = await this.handleCreateTag(payload);
          this.broadcastToAll('tag_created', result);
          break;
        case 'add_card_tag':
          result = await this.handleAddCardTag(payload);
          this.broadcastToBoardClients(result.board_id, 'card_tag_added', result);
          break;
        case 'remove_card_tag':
          result = await this.handleRemoveCardTag(payload);
          this.broadcastToBoardClients(result.board_id, 'card_tag_removed', result);
          break;

        // Comment operations
        case 'add_comment':
          result = await this.handleAddComment(payload);
          this.broadcastToBoardClients(result.board_id, 'comment_added', result);
          break;
        case 'get_comments':
          result = await this.handleGetComments(payload);
          break;
        case 'delete_comment':
          result = await this.handleDeleteComment(payload);
          this.broadcastToBoardClients(result.board_id, 'comment_deleted', { comment_id: payload.comment_id });
          break;

        // Analytics
        case 'get_stats':
          result = await this.handleGetStats();
          break;
        case 'search_cards':
          result = await this.handleSearchCards(payload);
          break;

        default:
          throw new Error(`Unknown message type: ${type}`);
      }

      this.sendResponse(client, 'success', result, id);
    } catch (error) {
      console.error(`Error handling ${type}:`, error);
      this.sendError(client, error instanceof Error ? error.message : 'Unknown error', id);
    }
  }

  // Board operations
  private async handleGetBoards(): Promise<any> {
    const boards = await this.db.getBoards();
    return { boards };
  }

  private async handleGetBoard(payload: any): Promise<any> {
    const { board_id } = payload;
    const board = await this.db.getBoardById(board_id);
    if (!board) {
      throw new Error(`Board ${board_id} not found`);
    }

    const columns = await this.db.getColumnsByBoard(board_id);
    const boardData = {
      board: board as any,
      columns: await Promise.all(
        columns.map(async (column) => {
          const cards = await this.db.getCardsByColumn(column.id!);
          const cardsWithTags = await Promise.all(
            cards.map(async (card) => {
              const tags = await this.db.getCardTags(card.id!);
              return { ...card, id: card.id!, tags: tags.map(tag => ({ ...tag, id: tag.id! })) };
            })
          );
          return { ...column, id: column.id!, cards: cardsWithTags };
        })
      ),
    };

    return boardData;
  }

  private async handleCreateBoard(payload: any): Promise<any> {
    return await this.db.createBoard(payload);
  }

  private async handleUpdateBoard(payload: any): Promise<any> {
    const { board_id, ...updates } = payload;
    return await this.db.updateBoard(board_id, updates);
  }

  private async handleDeleteBoard(payload: any): Promise<any> {
    const { board_id } = payload;
    return await this.db.deleteBoard(board_id);
  }

  // Column operations
  private async handleCreateColumn(payload: any): Promise<any> {
    return await this.db.createColumn(payload);
  }

  private async handleUpdateColumn(payload: any): Promise<any> {
    const { column_id, ...updates } = payload;
    return await this.db.updateColumn(column_id, updates);
  }

  private async handleDeleteColumn(payload: any): Promise<any> {
    const { column_id } = payload;
    return await this.db.deleteColumn(column_id);
  }

  // Card operations
  private async handleCreateCard(payload: any): Promise<any> {
    return await this.db.createCard(payload);
  }

  private async handleUpdateCard(payload: any): Promise<any> {
    const { card_id, ...updates } = payload;
    return await this.db.updateCard(card_id, updates);
  }

  private async handleMoveCard(payload: any): Promise<any> {
    const { card_id, column_id, position } = payload;
    return await this.db.moveCard(card_id, column_id, position);
  }

  private async handleDeleteCard(payload: any): Promise<any> {
    const { card_id } = payload;
    return await this.db.deleteCard(card_id);
  }

  // Tag operations
  private async handleGetTags(): Promise<any> {
    const tags = await this.db.getTags();
    return { tags };
  }

  private async handleCreateTag(payload: any): Promise<any> {
    return await this.db.createTag(payload);
  }

  private async handleAddCardTag(payload: any): Promise<any> {
    const { card_id, tag_id } = payload;
    await this.db.addCardTag(card_id, tag_id);
    return { card_id, tag_id };
  }

  private async handleRemoveCardTag(payload: any): Promise<any> {
    const { card_id, tag_id } = payload;
    await this.db.removeCardTag(card_id, tag_id);
    return { card_id, tag_id };
  }

  // Comment operations
  private async handleAddComment(payload: any): Promise<any> {
    return await this.db.addComment(payload);
  }

  private async handleGetComments(payload: any): Promise<any> {
    const { card_id } = payload;
    const comments = await this.db.getCardComments(card_id);
    return { comments };
  }

  private async handleDeleteComment(payload: any): Promise<any> {
    const { comment_id } = payload;
    return await this.db.deleteComment(comment_id);
  }

  // Analytics
  private async handleGetStats(): Promise<any> {
    const boards = await this.db.getBoards();
    const allCards = await Promise.all(
      boards.map(board => this.db.getCardsByBoard(board.id!))
    ).then(cardArrays => cardArrays.flat());

    const cardsByPriority = allCards.reduce(
      (acc, card) => {
        acc[card.priority] = (acc[card.priority] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    const today = new Date().toISOString().split('T')[0];
    const overdueCards = allCards.filter(
      card => card.due_date && card.due_date < today
    ).length;

    return {
      total_boards: boards.length,
      total_cards: allCards.length,
      cards_by_priority: cardsByPriority,
      cards_by_status: {},
      overdue_cards: overdueCards,
      recent_activity: [],
    };
  }

  private async handleSearchCards(payload: any): Promise<any> {
    const { query, board_id, priority, assigned_to } = payload;

    let cards: any[];
    if (board_id) {
      cards = await this.db.getCardsByBoard(board_id);
    } else {
      const boards = await this.db.getBoards();
      const allCards = await Promise.all(
        boards.map(board => this.db.getCardsByBoard(board.id!))
      );
      cards = allCards.flat();
    }

    const filteredCards = cards.filter(card => {
      const matchesQuery =
        card.title.toLowerCase().includes(query.toLowerCase()) ||
        (card.description && card.description.toLowerCase().includes(query.toLowerCase()));

      const matchesPriority = !priority || card.priority === priority;
      const matchesAssignee = !assigned_to || card.assigned_to === assigned_to;

      return matchesQuery && matchesPriority && matchesAssignee;
    });

    return { cards: filteredCards };
  }

  private sendResponse(client: ConnectedClient, type: string, payload?: any, id?: string): void {
    if (client.ws.readyState !== WebSocket.OPEN) return;
    const response: WebSocketResponse = { type, payload, id };
    client.ws.send(JSON.stringify(response));
  }

  private sendError(client: ConnectedClient, message: string, id?: string): void {
    if (client.ws.readyState !== WebSocket.OPEN) return;
    const response: WebSocketResponse = {
      type: 'error',
      payload: { message },
      id
    };
    client.ws.send(JSON.stringify(response));
  }

  broadcastToAll(type: string, payload: any): void {
    const message = JSON.stringify({ type, payload });
    this.clients.forEach(client => {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(message);
      }
    });
  }

  broadcastToBoardClients(boardId: number, type: string, payload: any): void {
    const message = JSON.stringify({ type, payload });
    console.log(`Broadcasting to board ${boardId} clients:`, type, 'Clients with this board:', 
      Array.from(this.clients.values()).filter(c => c.boardId === boardId).length);
    
    this.clients.forEach(client => {
      if (client.boardId === boardId && client.ws.readyState === WebSocket.OPEN) {
        console.log(`Sending ${type} to client ${client.id}`);
        client.ws.send(message);
      }
    });
  }

  private generateClientId(): string {
    return Math.random().toString(36).substring(2, 15);
  }

  close(): void {
    this.wss.close();
  }
}