const MAX_REDIRECTS = 10;
const MAX_BYTES = 2 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 15000;
const USER_AGENT = 'ShieldCortex-EnvScanner/1.0 (+https://shieldcortex.ai)';

export interface FetchOutcome {
  finalUrl: string;
  redirectChain: string[];
  statusCode: number | null;
  contentType: string | null;
  body: string;
  bytesReceived: number;
  durationMs: number;
  error: string | null;
}

export async function fetchWithProvenance(rawUrl: string): Promise<FetchOutcome> {
  const started = Date.now();
  const redirectChain: string[] = [];
  let current: URL;
  try {
    current = new URL(rawUrl);
  } catch {
    return {
      finalUrl: rawUrl,
      redirectChain: [],
      statusCode: null,
      contentType: null,
      body: '',
      bytesReceived: 0,
      durationMs: Date.now() - started,
      error: 'Invalid URL',
    };
  }

  if (current.protocol !== 'http:' && current.protocol !== 'https:') {
    return {
      finalUrl: current.toString(),
      redirectChain: [],
      statusCode: null,
      contentType: null,
      body: '',
      bytesReceived: 0,
      durationMs: Date.now() - started,
      error: `Unsupported protocol: ${current.protocol}`,
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      const res = await fetch(current.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });

      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        if (!loc) break;
        redirectChain.push(current.toString());
        current = new URL(loc, current);
        if (i === MAX_REDIRECTS) {
          return {
            finalUrl: current.toString(),
            redirectChain,
            statusCode: res.status,
            contentType: res.headers.get('content-type'),
            body: '',
            bytesReceived: 0,
            durationMs: Date.now() - started,
            error: 'Too many redirects',
          };
        }
        continue;
      }

      const reader = res.body?.getReader();
      let received = 0;
      const chunks: Uint8Array[] = [];
      if (reader) {
        while (received < MAX_BYTES) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value) {
            received += value.length;
            chunks.push(value);
            if (received >= MAX_BYTES) break;
          }
        }
        try {
          await reader.cancel();
        } catch {
          // ignore
        }
      }

      const buffer = new Uint8Array(received);
      let offset = 0;
      for (const chunk of chunks) {
        buffer.set(chunk.subarray(0, Math.min(chunk.length, MAX_BYTES - offset)), offset);
        offset += chunk.length;
        if (offset >= MAX_BYTES) break;
      }
      const body = new TextDecoder('utf-8', { fatal: false }).decode(buffer);

      return {
        finalUrl: res.url || current.toString(),
        redirectChain,
        statusCode: res.status,
        contentType: res.headers.get('content-type'),
        body,
        bytesReceived: received,
        durationMs: Date.now() - started,
        error: null,
      };
    }

    return {
      finalUrl: current.toString(),
      redirectChain,
      statusCode: null,
      contentType: null,
      body: '',
      bytesReceived: 0,
      durationMs: Date.now() - started,
      error: 'Redirect loop without body',
    };
  } catch (error) {
    return {
      finalUrl: current.toString(),
      redirectChain,
      statusCode: null,
      contentType: null,
      body: '',
      bytesReceived: 0,
      durationMs: Date.now() - started,
      error: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timer);
  }
}
