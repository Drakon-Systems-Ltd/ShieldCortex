export interface RecallFrame { id: string; OPEN: string; NOTICE: string; CLOSE: string }
export function newFrameId(): string;
export function recallFrame(frameId?: string): Readonly<RecallFrame>;
export function recallFrameTail(frameId?: string): Readonly<{ id: string; NOTICE: string; CLOSE: string }>;
export function recallFrameFields(frameId?: string): { untrusted_data_notice: string; frame_id: string };
export const RECALL_FRAME_OVERHEAD_CHARS: number;
export const RECALL_FRAME_TAIL_OVERHEAD_CHARS: number;
export const MARKER_REMOVED: '[frame marker removed]';
export function neutraliseFrameMarkers(value: string): string;
export function flattenRecallField(value: unknown): string;
export function frameRecallBlock(body: string, options?: { frameId?: string }): string | null;
export function formatRecallContext(memories: Array<{ id?: number | null; title?: string; content?: string }>, maxContentLength: number, options?: { frameId?: string }): string | null;
