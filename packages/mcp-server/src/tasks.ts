/**
 * MCP Tasks (Experimental) — MCP 2025-11-25
 *
 * Tasks enable durable request tracking with polling and deferred result retrieval
 * for long-running operations like expensive computations and batch processing.
 */
import { randomBytes } from "node:crypto";

/**
 * Task lifecycle states
 */
export type TaskStatus = 'working' | 'input_required' | 'completed' | 'failed' | 'cancelled';

/**
 * Core Task object
 */
export interface Task {
  taskId: string;
  status: TaskStatus;
  statusMessage?: string;
  createdAt: string;
  lastUpdatedAt: string;
  ttl: number | null;
  pollInterval?: number;
}

/**
 * Task metadata for task-augmented requests
 */
export interface TaskMetadata {
  ttl?: number;
}

/**
 * Tool-level task support negotiation
 */
export interface ToolExecution {
  taskSupport?: 'forbidden' | 'optional' | 'required';
}

/**
 * Configuration for task system behavior
 */
export interface TaskConfig {
  /** Default TTL for tasks in ms (default: 3600000 = 1 hour) */
  defaultTTL?: number;
  /** Default poll interval suggestion in ms (default: 5000) */
  defaultPollInterval?: number;
  /** Maximum concurrent tasks (default: 1000) */
  maxTasks?: number;
  /** How often to run cleanup of expired tasks in ms (default: 60000) */
  cleanupInterval?: number;
}

/**
 * Internal stored task with result
 */
interface StoredTask {
  task: Task;
  result: any | null;
  expiresAt: number | null;
}

/**
 * In-memory task store
 */
export class InMemoryTaskStore {
  private tasks: Map<string, StoredTask> = new Map();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(cleanupIntervalMs: number = 60000) {
    if (cleanupIntervalMs > 0) {
      this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
      this.cleanupTimer.unref();
    }
  }

  createTask(ttl: number | null, pollInterval?: number): Task {
    const taskId = randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    const task: Task = {
      taskId,
      status: 'working',
      createdAt: now,
      lastUpdatedAt: now,
      ttl,
      pollInterval,
    };

    const stored: StoredTask = {
      task,
      result: null,
      expiresAt: ttl ? Date.now() + ttl : null,
    };

    this.tasks.set(taskId, stored);
    return task;
  }

  getTask(taskId: string): Task | null {
    const stored = this.tasks.get(taskId);
    if (!stored) return null;
    if (stored.expiresAt && Date.now() > stored.expiresAt && isTerminal(stored.task.status)) {
      this.tasks.delete(taskId);
      return null;
    }
    return stored.task;
  }

  updateTaskStatus(taskId: string, status: TaskStatus, statusMessage?: string): Task | null {
    const stored = this.tasks.get(taskId);
    if (!stored) return null;

    stored.task.status = status;
    stored.task.lastUpdatedAt = new Date().toISOString();
    if (statusMessage !== undefined) {
      stored.task.statusMessage = statusMessage;
    }

    // Reset TTL expiry when reaching terminal state
    if (isTerminal(status) && stored.task.ttl) {
      stored.expiresAt = Date.now() + stored.task.ttl;
    }

    return stored.task;
  }

  storeResult(taskId: string, result: any): void {
    const stored = this.tasks.get(taskId);
    if (stored) {
      stored.result = result;
    }
  }

  getResult(taskId: string): any | null {
    const stored = this.tasks.get(taskId);
    return stored?.result ?? null;
  }

  listTasks(): Task[] {
    this.cleanup();
    return Array.from(this.tasks.values()).map(s => s.task);
  }

  cancelTask(taskId: string): Task | null {
    return this.updateTaskStatus(taskId, 'cancelled', 'Task cancelled by client');
  }

  get size(): number {
    return this.tasks.size;
  }

  cleanup(): void {
    const now = Date.now();
    for (const [taskId, stored] of this.tasks) {
      if (stored.expiresAt && now > stored.expiresAt && isTerminal(stored.task.status)) {
        this.tasks.delete(taskId);
      }
    }
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.tasks.clear();
  }
}

/**
 * Task manager — orchestrates task lifecycle
 */
export class TaskManager {
  private store: InMemoryTaskStore;
  private config: Required<TaskConfig>;

  constructor(config: TaskConfig = {}) {
    this.config = {
      defaultTTL: config.defaultTTL ?? 3600000,
      defaultPollInterval: config.defaultPollInterval ?? 5000,
      maxTasks: config.maxTasks ?? 1000,
      cleanupInterval: config.cleanupInterval ?? 60000,
    };
    this.store = new InMemoryTaskStore(this.config.cleanupInterval);
  }

  createTask(ttl?: number, pollInterval?: number): Task {
    if (this.store.size >= this.config.maxTasks) {
      this.store.cleanup();
      if (this.store.size >= this.config.maxTasks) {
        throw new Error(`Maximum concurrent tasks (${this.config.maxTasks}) reached`);
      }
    }

    return this.store.createTask(
      ttl ?? this.config.defaultTTL,
      pollInterval ?? this.config.defaultPollInterval
    );
  }

  getTask(taskId: string): Task | null {
    return this.store.getTask(taskId);
  }

  updateStatus(taskId: string, status: TaskStatus, message?: string): Task | null {
    return this.store.updateTaskStatus(taskId, status, message);
  }

  setResult(taskId: string, result: any): void {
    this.store.storeResult(taskId, result);
  }

  getResult(taskId: string): any | null {
    return this.store.getResult(taskId);
  }

  listTasks(): Task[] {
    return this.store.listTasks();
  }

  cancelTask(taskId: string): Task | null {
    const task = this.store.getTask(taskId);
    if (!task) return null;
    if (isTerminal(task.status)) {
      throw new Error(`Cannot cancel task in terminal state: ${task.status}`);
    }
    return this.store.cancelTask(taskId);
  }

  destroy(): void {
    this.store.destroy();
  }
}

/**
 * Check if a task status is terminal (no further state changes)
 */
export function isTerminal(status: TaskStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled';
}
