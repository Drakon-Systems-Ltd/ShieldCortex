/**
 * Custom Error Classes
 *
 * Provides actionable error messages that help users understand
 * what went wrong and how to fix it.
 */

/**
 * Base class for Claude Memory errors
 */
export class MemoryError extends Error {
  public readonly code: string;
  public readonly suggestion: string;

  constructor(message: string, code: string, suggestion: string) {
    super(message);
    this.name = 'MemoryError';
    this.code = code;
    this.suggestion = suggestion;
  }

  toUserMessage(): string {
    return `${this.message}\n\nSuggestion: ${this.suggestion}`;
  }
}

/**
 * Database blocked due to size limits
 */
export class DatabaseBlockedError extends MemoryError {
  constructor(currentSize: string) {
    super(
      `Database blocked: ${currentSize} exceeds the 100MB limit`,
      'DB_BLOCKED',
      'Run "consolidate" to clean up old memories, or use "forget" to remove memories you no longer need.'
    );
    this.name = 'DatabaseBlockedError';
  }
}

/**
 * Database size warning (approaching limit)
 */
export class DatabaseSizeWarning extends MemoryError {
  constructor(currentSize: string) {
    super(
      `Database size warning: ${currentSize} is approaching the 100MB limit`,
      'DB_SIZE_WARNING',
      'Consider running "consolidate" to clean up old memories before reaching the limit.'
    );
    this.name = 'DatabaseSizeWarning';
  }
}

/**
 * Memory not found
 */
export class MemoryNotFoundError extends MemoryError {
  constructor(id: number) {
    super(
      `Memory with ID ${id} not found`,
      'MEMORY_NOT_FOUND',
      'Use "recall" to search for existing memories, or check if the memory was deleted by consolidation.'
    );
    this.name = 'MemoryNotFoundError';
  }
}

/**
 * Invalid search query
 */
export class InvalidQueryError extends MemoryError {
  constructor(query: string, reason: string) {
    super(
      `Invalid search query "${query}": ${reason}`,
      'INVALID_QUERY',
      'Try simpler search terms. Avoid special characters like *, ^, ( ). Use quotes around phrases.'
    );
    this.name = 'InvalidQueryError';
  }
}

/**
 * Content too large
 */
export class ContentTooLargeError extends MemoryError {
  constructor(contentSize: number, maxSize: number) {
    const sizeKB = (contentSize / 1024).toFixed(1);
    const maxKB = (maxSize / 1024).toFixed(1);
    super(
      `Content size (${sizeKB}KB) exceeds maximum allowed (${maxKB}KB)`,
      'CONTENT_TOO_LARGE',
      'Split large content into multiple smaller memories. Focus on the key points rather than storing everything.'
    );
    this.name = 'ContentTooLargeError';
  }
}

/**
 * Bulk delete safety guard
 */
export class BulkDeleteSafetyError extends MemoryError {
  constructor(count: number) {
    super(
      `Bulk delete blocked: ${count} memories would be deleted`,
      'BULK_DELETE_BLOCKED',
      'This operation would delete many memories. Use "dryRun: true" first to preview what would be deleted, then set "confirm: true" to proceed.'
    );
    this.name = 'BulkDeleteSafetyError';
  }
}

/**
 * Database not initialized
 */
export class DatabaseNotInitializedError extends MemoryError {
  constructor() {
    super(
      'Database not initialized',
      'DB_NOT_INIT',
      'This usually means the MCP server failed to start properly. Check that the database path is accessible and try restarting the server.'
    );
    this.name = 'DatabaseNotInitializedError';
  }
}

/**
 * Session not found
 */
export class SessionNotFoundError extends MemoryError {
  constructor(sessionId: number) {
    super(
      `Session ${sessionId} not found`,
      'SESSION_NOT_FOUND',
      'The session may have already ended or was never started. Use "start_session" to begin a new session.'
    );
    this.name = 'SessionNotFoundError';
  }
}

/**
 * Invalid memory relationship
 */
export class InvalidRelationshipError extends MemoryError {
  constructor(sourceId: number, targetId: number, reason: string) {
    super(
      `Cannot create relationship between memory ${sourceId} and ${targetId}: ${reason}`,
      'INVALID_RELATIONSHIP',
      'Ensure both memories exist and are not the same memory. Use "get_memory" to verify the memory IDs.'
    );
    this.name = 'InvalidRelationshipError';
  }
}

/**
 * Format error for MCP tool output
 */
export function formatErrorForMcp(error: unknown): string {
  if (error instanceof MemoryError) {
    return error.toUserMessage();
  }

  if (error instanceof Error) {
    // Try to make common errors more helpful
    if (error.message.includes('SQLITE_BUSY')) {
      return 'Database is busy (another operation in progress). Please try again in a moment.';
    }
    if (error.message.includes('SQLITE_LOCKED')) {
      return 'Database is locked. This may happen if multiple processes are accessing the database. Wait a moment and try again.';
    }
    if (error.message.includes('SQLITE_CORRUPT')) {
      return 'Database corruption detected. Try running "consolidate" to repair, or restore from backup.';
    }
    if (error.message.includes('no such table')) {
      return 'Database schema error. The database may need to be reinitialized. Try restarting the MCP server.';
    }

    return `Error: ${error.message}`;
  }

  return 'An unknown error occurred. Please try again or check the server logs.';
}
