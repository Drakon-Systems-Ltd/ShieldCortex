/**
 * Visualization API Server
 *
 * Provides REST endpoints and WebSocket for the Brain Dashboard.
 * Runs alongside or instead of the MCP server.
 */

import express, { Request, Response } from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { getDatabase, initDatabase } from '../database/init.js';
import { Memory, MemoryConfig, DEFAULT_CONFIG } from '../memory/types.js';
import {
  searchMemories,
  getRecentMemories,
  getHighPriorityMemories,
  getMemoryStats,
  getMemoryById,
  addMemory,
  deleteMemory,
  accessMemory,
  updateDecayScores,
} from '../memory/store.js';
import {
  consolidate,
  generateContextSummary,
  formatContextSummary,
} from '../memory/consolidate.js';
import { calculateDecayedScore } from '../memory/decay.js';
import { memoryEvents, MemoryEvent, emitDecayTick } from './events.js';

const PORT = process.env.PORT || 3001;

// Track connected WebSocket clients
const clients = new Set<WebSocket>();

/**
 * Start the visualization API server
 */
export function startVisualizationServer(dbPath?: string): void {
  // Initialize database
  initDatabase(dbPath || DEFAULT_CONFIG.dbPath);

  const app = express();
  const server = createServer(app);

  // Middleware
  app.use(cors());
  app.use(express.json());

  // ============================================
  // REST API ENDPOINTS
  // ============================================

  // Health check
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Get all memories with filters and pagination
  app.get('/api/memories', (req: Request, res: Response) => {
    try {
      // Extract query params as strings
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const type = typeof req.query.type === 'string' ? req.query.type : undefined;
      const category = typeof req.query.category === 'string' ? req.query.category : undefined;
      const limitStr = typeof req.query.limit === 'string' ? req.query.limit : '50';
      const offsetStr = typeof req.query.offset === 'string' ? req.query.offset : '0';
      const mode = typeof req.query.mode === 'string' ? req.query.mode : 'recent';
      const query = typeof req.query.query === 'string' ? req.query.query : undefined;

      const limit = Math.min(parseInt(limitStr), 200); // Cap at 200
      const offset = parseInt(offsetStr);

      let memories: Memory[];

      if (mode === 'search' && query) {
        const results = searchMemories({
          query,
          project,
          type: type as Memory['type'] | undefined,
          category: category as Memory['category'] | undefined,
          limit: limit + offset + 1, // Fetch extra to check hasMore
        });
        memories = results.map(r => r.memory);
      } else if (mode === 'important') {
        memories = getHighPriorityMemories(limit + offset + 1, project);
      } else {
        memories = getRecentMemories(limit + offset + 1, project);
      }

      // Filter by type and category if provided
      if (type) {
        memories = memories.filter(m => m.type === type);
      }
      if (category) {
        memories = memories.filter(m => m.category === category);
      }

      // Get total count for pagination
      const stats = getMemoryStats(project);
      const total = stats.total;

      // Apply pagination
      const hasMore = memories.length > offset + limit;
      const paginatedMemories = memories.slice(offset, offset + limit);

      // Add computed decayed score to each memory
      const memoriesWithDecay = paginatedMemories.map(m => ({
        ...m,
        decayedScore: calculateDecayedScore(m),
      }));

      res.json({
        memories: memoriesWithDecay,
        pagination: {
          offset,
          limit,
          total,
          hasMore,
        },
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get single memory by ID
  app.get('/api/memories/:id', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const memory = getMemoryById(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json({
        ...memory,
        decayedScore: calculateDecayedScore(memory),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Create memory
  app.post('/api/memories', (req: Request, res: Response) => {
    try {
      const { title, content, type, category, project, tags, salience } = req.body;

      if (!title || !content) {
        return res.status(400).json({ error: 'Title and content required' });
      }

      const memory = addMemory({
        title,
        content,
        type: type || 'short_term',
        category: category || 'note',
        project,
        tags: tags || [],
        salience,
      });

      res.status(201).json(memory);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Delete memory
  app.delete('/api/memories/:id', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const success = deleteMemory(id);
      if (!success) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Access/reinforce memory
  app.post('/api/memories/:id/access', (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id as string);
      const memory = accessMemory(id);
      if (!memory) {
        return res.status(404).json({ error: 'Memory not found' });
      }
      res.json({
        ...memory,
        decayedScore: calculateDecayedScore(memory),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get statistics
  app.get('/api/stats', (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const stats = getMemoryStats(project);

      // Add decay distribution
      const db = getDatabase();
      const allMemories = db.prepare(
        project
          ? 'SELECT * FROM memories WHERE project = ?'
          : 'SELECT * FROM memories'
      ).all(project ? [project] : []) as Memory[];

      const decayDistribution = {
        healthy: 0,  // > 0.7
        fading: 0,   // 0.4 - 0.7
        critical: 0, // < 0.4
      };

      for (const m of allMemories) {
        const score = calculateDecayedScore(m);
        if (score > 0.7) decayDistribution.healthy++;
        else if (score > 0.4) decayDistribution.fading++;
        else decayDistribution.critical++;
      }

      res.json({
        ...stats,
        decayDistribution,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get memory links/relationships
  app.get('/api/links', (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const links = db.prepare(`
        SELECT
          ml.*,
          m1.title as source_title,
          m1.category as source_category,
          m1.type as source_type,
          m2.title as target_title,
          m2.category as target_category,
          m2.type as target_type
        FROM memory_links ml
        JOIN memories m1 ON ml.source_id = m1.id
        JOIN memories m2 ON ml.target_id = m2.id
        ORDER BY ml.created_at DESC
        LIMIT 500
      `).all();

      res.json(links);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Trigger consolidation
  app.post('/api/consolidate', (_req: Request, res: Response) => {
    try {
      const result = consolidate();
      res.json({
        success: true,
        ...result,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get context summary
  app.get('/api/context', (req: Request, res: Response) => {
    try {
      const project = typeof req.query.project === 'string' ? req.query.project : undefined;
      const summary = generateContextSummary(project);
      const formatted = formatContextSummary(summary);

      res.json({
        summary,
        formatted,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // Get search suggestions (for autocomplete)
  app.get('/api/suggestions', (req: Request, res: Response) => {
    try {
      const query = typeof req.query.q === 'string' ? req.query.q : '';
      const limit = typeof req.query.limit === 'string' ? parseInt(req.query.limit) : 10;

      if (!query || query.length < 2) {
        return res.json({ suggestions: [] });
      }

      const db = getDatabase();

      // Get suggestions from memory titles, categories, tags, and projects
      const suggestions: Array<{ text: string; type: string; count: number }> = [];

      // Search titles that contain the query
      const titleMatches = db.prepare(`
        SELECT DISTINCT title, COUNT(*) as count
        FROM memories
        WHERE title LIKE ?
        GROUP BY title
        ORDER BY count DESC, last_accessed DESC
        LIMIT ?
      `).all(`%${query}%`, limit) as { title: string; count: number }[];

      for (const match of titleMatches) {
        suggestions.push({ text: match.title, type: 'title', count: match.count });
      }

      // Get matching categories
      const categoryMatches = db.prepare(`
        SELECT DISTINCT category, COUNT(*) as count
        FROM memories
        WHERE category LIKE ?
        GROUP BY category
        ORDER BY count DESC
        LIMIT 5
      `).all(`%${query}%`) as { category: string; count: number }[];

      for (const match of categoryMatches) {
        suggestions.push({ text: match.category, type: 'category', count: match.count });
      }

      // Get matching projects
      const projectMatches = db.prepare(`
        SELECT DISTINCT project, COUNT(*) as count
        FROM memories
        WHERE project IS NOT NULL AND project LIKE ?
        GROUP BY project
        ORDER BY count DESC
        LIMIT 5
      `).all(`%${query}%`) as { project: string; count: number }[];

      for (const match of projectMatches) {
        suggestions.push({ text: match.project, type: 'project', count: match.count });
      }

      // Sort by count and limit total results
      suggestions.sort((a, b) => b.count - a.count);
      const limitedSuggestions = suggestions.slice(0, limit);

      res.json({ suggestions: limitedSuggestions });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  // ============================================
  // WEBSOCKET SERVER
  // ============================================

  const wss = new WebSocketServer({ server, path: '/ws/events' });

  wss.on('connection', (ws: WebSocket) => {
    clients.add(ws);
    console.log(`[WS] Client connected. Total: ${clients.size}`);

    // Send initial state
    const stats = getMemoryStats();
    const memories = getRecentMemories(100);
    const memoriesWithDecay = memories.map(m => ({
      ...m,
      decayedScore: calculateDecayedScore(m),
    }));

    ws.send(JSON.stringify({
      type: 'initial_state',
      timestamp: new Date().toISOString(),
      data: {
        stats,
        memories: memoriesWithDecay,
      },
    }));

    ws.on('close', () => {
      clients.delete(ws);
      console.log(`[WS] Client disconnected. Total: ${clients.size}`);
    });

    ws.on('error', (error) => {
      console.error('[WS] Error:', error);
      clients.delete(ws);
    });
  });

  // Broadcast events to all connected clients
  function broadcast(event: MemoryEvent): void {
    const message = JSON.stringify(event);
    for (const client of clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    }
  }

  // Subscribe to memory events
  memoryEvents.onMemoryEvent((event) => {
    broadcast(event);
  });

  // Decay tick - update clients with decay changes every 30 seconds
  let decayTickCount = 0;
  setInterval(() => {
    const db = getDatabase();
    const memories = db.prepare(
      'SELECT * FROM memories ORDER BY last_accessed DESC LIMIT 200'
    ).all() as Memory[];

    const updates: Array<{ memoryId: number; oldScore: number; newScore: number }> = [];

    for (const memory of memories) {
      const newScore = calculateDecayedScore(memory);
      // Only include memories that have decayed significantly
      if (Math.abs(newScore - memory.salience) > 0.01) {
        updates.push({
          memoryId: memory.id,
          oldScore: memory.salience,
          newScore,
        });
      }
    }

    if (updates.length > 0) {
      emitDecayTick(updates);
    }

    // Persist decay scores to database every 5 minutes (10 ticks)
    decayTickCount++;
    if (decayTickCount >= 10) {
      decayTickCount = 0;
      try {
        updateDecayScores();
      } catch (error) {
        console.error('[Decay] Failed to persist decay scores:', error);
      }
    }
  }, 30000);

  // ============================================
  // START SERVER
  // ============================================

  server.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║           Claude Memory Visualization Server                  ║
╠══════════════════════════════════════════════════════════════╣
║  REST API:    http://localhost:${PORT}/api                        ║
║  WebSocket:   ws://localhost:${PORT}/ws/events                    ║
║                                                              ║
║  Endpoints:                                                  ║
║    GET  /api/health         - Health check                   ║
║    GET  /api/memories       - List memories                  ║
║    GET  /api/memories/:id   - Get memory                     ║
║    POST /api/memories       - Create memory                  ║
║    DEL  /api/memories/:id   - Delete memory                  ║
║    POST /api/memories/:id/access - Reinforce memory          ║
║    GET  /api/stats          - Memory statistics              ║
║    GET  /api/links          - Memory relationships           ║
║    POST /api/consolidate    - Trigger consolidation          ║
║    GET  /api/context        - Context summary                ║
║    GET  /api/suggestions    - Search autocomplete            ║
╚══════════════════════════════════════════════════════════════╝
    `);
  });
}
