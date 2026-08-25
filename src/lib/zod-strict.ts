/**
 * #412 — closed-by-default Zod objects for security-relevant schemas.
 * Unknown keys fail validation instead of being silently stripped/ignored.
 */
import { z } from 'zod';

/** `z.object(shape).strict()` — reject unknown keys at this level. */
export function strictObject<T extends z.ZodRawShape>(shape: T) {
  return z.object(shape).strict();
}
