/**
 * Small, strict TOML 1.0 reader for the agent configuration watch (#916).
 *
 * The watch only needs the parsed value tree of `~/.codex/config.toml` so it
 * can hash `mcp_servers` and `hooks` semantically. A line-based reader missed
 * tables with trailing comments, dotted keys and multiline strings; this
 * parser handles the TOML 1.0 grammar the watch can meet and THROWS
 * `TomlParseError` on anything it does not understand, so the caller can
 * report a parse error instead of hashing an empty snapshot.
 *
 * Deliberate simplifications (the output is only hashed, never executed):
 *  - Offset/local date-times, local dates/times, inf and nan become a tagged
 *    object `{ "\u0000toml": <kind>, raw: <token> }` so they never collide with
 *    a string of the same text.
 *  - Integers and finite floats become JS numbers.
 * Objects are null-prototype, so a `__proto__` key is plain data.
 */

export class TomlParseError extends Error {
  constructor(message: string, readonly offset: number) {
    super(message);
    this.name = 'TomlParseError';
  }
}

type Table = Record<string, unknown>;

const newTable = (): Table => Object.create(null) as Table;
const isTable = (v: unknown): v is Table => !!v && typeof v === 'object' && !Array.isArray(v) && !(TAG in (v as object));
const TAG = '\u0000toml';
const tagged = (kind: string, raw: string): Table => {
  const t = newTable();
  t[TAG] = kind;
  t.raw = raw;
  return t;
};

const BARE_KEY = /[A-Za-z0-9_-]/;
const RE_DEC_INT = /^[+-]?(?:0|[1-9](?:_?[0-9])*)$/;
const RE_HEX = /^0x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*$/;
const RE_OCT = /^0o[0-7](?:_?[0-7])*$/;
const RE_BIN = /^0b[01](?:_?[01])*$/;
const RE_FLOAT = /^[+-]?(?:0|[1-9](?:_?[0-9])*)(?:\.[0-9](?:_?[0-9])*)?(?:[eE][+-]?[0-9](?:_?[0-9])*)?$/;
const RE_SPECIAL_FLOAT = /^[+-]?(?:inf|nan)$/;
const RE_DATE = /^\d{4}-\d{2}-\d{2}$/;
const RE_DATETIME = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})?$/;
const RE_TIME = /^\d{2}:\d{2}:\d{2}(?:\.\d+)?$/;

class Parser {
  private i = 0;
  private readonly root = newTable();
  /** Tables opened by a `[header]` (cannot be opened again). */
  private readonly headerDefined = new Set<Table>();
  /** Tables created by dotted keys (cannot be reopened by a header). */
  private readonly dottedDefined = new Set<Table>();
  /** Inline tables and static arrays are immutable once written. */
  private readonly sealed = new Set<unknown>();
  /** Arrays created by `[[header]]`. */
  private readonly tableArrays = new Set<unknown[]>();

  constructor(private readonly src: string) {}

  private fail(msg: string): never {
    throw new TomlParseError(msg, this.i);
  }

  private peek(n = 0): string {
    return this.src[this.i + n] ?? '';
  }

  private eof(): boolean {
    return this.i >= this.src.length;
  }

  private skipWs(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.i++;
  }

  private skipComment(): void {
    if (this.peek() !== '#') return;
    while (!this.eof() && this.peek() !== '\n' && !(this.peek() === '\r' && this.peek(1) === '\n')) this.i++;
  }

  private newline(): boolean {
    if (this.peek() === '\n') { this.i++; return true; }
    if (this.peek() === '\r' && this.peek(1) === '\n') { this.i += 2; return true; }
    return false;
  }

  /** Whitespace, comments and newlines (between statements and inside arrays). */
  private skipBlank(): void {
    for (;;) {
      this.skipWs();
      this.skipComment();
      if (!this.newline()) return;
    }
  }

  private endOfLine(): void {
    this.skipWs();
    this.skipComment();
    if (this.eof()) return;
    if (!this.newline()) this.fail('expected end of line');
  }

  parse(): Table {
    let current = this.root;
    for (;;) {
      this.skipBlank();
      if (this.eof()) break;
      if (this.peek() === '[') {
        const isArray = this.peek(1) === '[';
        this.i += isArray ? 2 : 1;
        const keys = this.parseKey();
        this.skipWs();
        if (isArray) {
          if (this.peek() !== ']' || this.peek(1) !== ']') this.fail('expected ]]');
          this.i += 2;
          current = this.openArrayTable(keys);
        } else {
          if (this.peek() !== ']') this.fail('expected ]');
          this.i++;
          current = this.openTable(keys);
        }
        this.endOfLine();
        continue;
      }
      this.parseKeyValue(current);
      this.endOfLine();
    }
    return this.root;
  }

  private parseKeyValue(target: Table): void {
    const keys = this.parseKey();
    this.skipWs();
    if (this.peek() !== '=') this.fail('expected =');
    this.i++;
    this.skipWs();
    const value = this.parseValue();
    this.assignDotted(target, keys, value);
  }

  private parseKey(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.skipWs();
      const c = this.peek();
      if (c === '"') parts.push(this.parseBasicString());
      else if (c === "'") parts.push(this.parseLiteralString());
      else {
        const start = this.i;
        while (BARE_KEY.test(this.peek())) this.i++;
        if (this.i === start) this.fail('invalid key');
        parts.push(this.src.slice(start, this.i));
      }
      this.skipWs();
      if (this.peek() !== '.') break;
      this.i++;
    }
    return parts;
  }

  /** Walk/create the intermediate tables of a header path. */
  private descend(from: Table, keys: string[]): Table {
    let cur = from;
    for (const k of keys) {
      const existing = Object.prototype.hasOwnProperty.call(cur, k) ? cur[k] : undefined;
      if (existing === undefined) {
        const t = newTable();
        cur[k] = t;
        cur = t;
      } else if (Array.isArray(existing) && this.tableArrays.has(existing)) {
        const last = existing[existing.length - 1];
        if (!isTable(last)) this.fail('invalid array of tables');
        cur = last;
      } else if (isTable(existing) && !this.sealed.has(existing)) {
        cur = existing;
      } else {
        this.fail(`cannot extend key ${JSON.stringify(k)}`);
      }
    }
    return cur;
  }

  private openTable(keys: string[]): Table {
    const parent = this.descend(this.root, keys.slice(0, -1));
    const last = keys[keys.length - 1];
    const existing = Object.prototype.hasOwnProperty.call(parent, last) ? parent[last] : undefined;
    if (existing === undefined) {
      const t = newTable();
      parent[last] = t;
      this.headerDefined.add(t);
      return t;
    }
    if (isTable(existing) && !this.headerDefined.has(existing) && !this.dottedDefined.has(existing) && !this.sealed.has(existing)) {
      this.headerDefined.add(existing);
      return existing;
    }
    return this.fail(`duplicate table ${JSON.stringify(keys.join('.'))}`);
  }

  private openArrayTable(keys: string[]): Table {
    const parent = this.descend(this.root, keys.slice(0, -1));
    const last = keys[keys.length - 1];
    const existing = Object.prototype.hasOwnProperty.call(parent, last) ? parent[last] : undefined;
    let arr: unknown[];
    if (existing === undefined) {
      arr = [];
      parent[last] = arr;
      this.tableArrays.add(arr);
    } else if (Array.isArray(existing) && this.tableArrays.has(existing)) {
      arr = existing;
    } else {
      return this.fail(`cannot redefine ${JSON.stringify(keys.join('.'))} as an array of tables`);
    }
    const t = newTable();
    arr.push(t);
    return t;
  }

  private assignDotted(target: Table, keys: string[], value: unknown): void {
    let cur = target;
    for (const k of keys.slice(0, -1)) {
      const existing = Object.prototype.hasOwnProperty.call(cur, k) ? cur[k] : undefined;
      if (existing === undefined) {
        const t = newTable();
        cur[k] = t;
        this.dottedDefined.add(t);
        cur = t;
      } else if (isTable(existing) && !this.headerDefined.has(existing) && !this.sealed.has(existing)) {
        cur = existing;
      } else {
        this.fail(`cannot extend key ${JSON.stringify(k)}`);
      }
    }
    const last = keys[keys.length - 1];
    if (Object.prototype.hasOwnProperty.call(cur, last)) this.fail(`duplicate key ${JSON.stringify(last)}`);
    cur[last] = value;
  }

  private parseValue(): unknown {
    const c = this.peek();
    if (c === '"') return this.peek(1) === '"' && this.peek(2) === '"' ? this.parseMultilineBasic() : this.parseBasicString();
    if (c === "'") return this.peek(1) === "'" && this.peek(2) === "'" ? this.parseMultilineLiteral() : this.parseLiteralString();
    if (c === '[') return this.parseArray();
    if (c === '{') return this.parseInlineTable();
    return this.parseScalar();
  }

  private parseArray(): unknown[] {
    this.i++; // [
    const arr: unknown[] = [];
    for (;;) {
      this.skipBlank();
      if (this.peek() === ']') { this.i++; break; }
      if (this.eof()) this.fail('unterminated array');
      arr.push(this.parseValue());
      this.skipBlank();
      if (this.peek() === ',') { this.i++; continue; }
      if (this.peek() === ']') { this.i++; break; }
      this.fail('expected , or ] in array');
    }
    this.sealed.add(arr);
    return arr;
  }

  private parseInlineTable(): Table {
    this.i++; // {
    const t = newTable();
    this.skipBlank();
    if (this.peek() === '}') { this.i++; this.sealed.add(t); return t; }
    for (;;) {
      this.skipBlank();
      this.parseKeyValue(t);
      this.skipBlank();
      if (this.peek() === ',') { this.i++; this.skipBlank(); if (this.peek() === '}') { this.i++; break; } continue; }
      if (this.peek() === '}') { this.i++; break; }
      this.fail('expected , or } in inline table');
    }
    this.sealed.add(t);
    return t;
  }

  private parseEscape(): string {
    const c = this.peek();
    this.i++;
    switch (c) {
      case 'b': return '\b';
      case 't': return '\t';
      case 'n': return '\n';
      case 'f': return '\f';
      case 'r': return '\r';
      case 'e': return '\u001b';
      case '"': return '"';
      case '\\': return '\\';
      case 'u':
      case 'U': {
        const len = c === 'u' ? 4 : 8;
        const hex = this.src.slice(this.i, this.i + len);
        if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== len) this.fail('invalid unicode escape');
        this.i += len;
        const cp = parseInt(hex, 16);
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) this.fail('invalid unicode scalar');
        return String.fromCodePoint(cp);
      }
      default:
        return this.fail('invalid escape');
    }
  }

  private parseBasicString(): string {
    this.i++; // "
    let out = '';
    for (;;) {
      if (this.eof()) this.fail('unterminated string');
      const c = this.peek();
      if (c === '"') { this.i++; return out; }
      if (c === '\n' || c === '\r') this.fail('newline in string');
      if (c === '\\') { this.i++; out += this.parseEscape(); continue; }
      out += c;
      this.i++;
    }
  }

  private parseLiteralString(): string {
    this.i++; // '
    const start = this.i;
    for (;;) {
      if (this.eof()) this.fail('unterminated string');
      const c = this.peek();
      if (c === "'") { const s = this.src.slice(start, this.i); this.i++; return s; }
      if (c === '\n' || c === '\r') this.fail('newline in string');
      this.i++;
    }
  }

  /** Count a closing run of quotes: 3..5 ends the string (1-2 extra belong to the content). */
  private closingRun(q: string): number {
    let n = 0;
    while (this.peek(n) === q) n++;
    return n;
  }

  private parseMultilineBasic(): string {
    this.i += 3;
    this.newline();
    let out = '';
    for (;;) {
      if (this.eof()) this.fail('unterminated multiline string');
      const c = this.peek();
      if (c === '"') {
        const n = this.closingRun('"');
        if (n >= 3) {
          if (n > 5) this.fail('too many quotes');
          out += '"'.repeat(n - 3);
          this.i += n;
          return out;
        }
        out += '"'.repeat(n);
        this.i += n;
        continue;
      }
      if (c === '\\') {
        // Line-ending backslash: trim whitespace and newlines up to the next content.
        let j = this.i + 1;
        while (this.src[j] === ' ' || this.src[j] === '\t') j++;
        if (this.src[j] === '\n' || (this.src[j] === '\r' && this.src[j + 1] === '\n')) {
          this.i = j;
          while (this.peek() === ' ' || this.peek() === '\t' || this.peek() === '\n' || (this.peek() === '\r' && this.peek(1) === '\n')) this.i++;
          continue;
        }
        this.i++;
        out += this.parseEscape();
        continue;
      }
      if (c === '\r') {
        if (this.peek(1) !== '\n') this.fail('bare carriage return');
        out += '\n';
        this.i += 2;
        continue;
      }
      out += c;
      this.i++;
    }
  }

  private parseMultilineLiteral(): string {
    this.i += 3;
    this.newline();
    let out = '';
    for (;;) {
      if (this.eof()) this.fail('unterminated multiline string');
      const c = this.peek();
      if (c === "'") {
        const n = this.closingRun("'");
        if (n >= 3) {
          if (n > 5) this.fail('too many quotes');
          out += "'".repeat(n - 3);
          this.i += n;
          return out;
        }
        out += "'".repeat(n);
        this.i += n;
        continue;
      }
      if (c === '\r') {
        if (this.peek(1) !== '\n') this.fail('bare carriage return');
        out += '\n';
        this.i += 2;
        continue;
      }
      out += c;
      this.i++;
    }
  }

  private parseScalar(): unknown {
    const start = this.i;
    while (!this.eof() && !/[\s,\]}#]/.test(this.peek())) this.i++;
    let tok = this.src.slice(start, this.i);
    // A date and a time separated by one space is a single date-time.
    if (RE_DATE.test(tok) && this.peek() === ' ' && /\d/.test(this.peek(1))) {
      const save = this.i;
      this.i++;
      while (!this.eof() && !/[\s,\]}#]/.test(this.peek())) this.i++;
      const joined = this.src.slice(start, this.i);
      if (RE_DATETIME.test(joined)) tok = joined;
      else this.i = save;
    }
    if (tok === '') this.fail('expected a value');
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (RE_DEC_INT.test(tok)) return Number(tok.replace(/_/g, ''));
    if (RE_HEX.test(tok) || RE_OCT.test(tok) || RE_BIN.test(tok)) return Number(BigInt(tok.replace(/_/g, '')));
    if (RE_FLOAT.test(tok)) return Number(tok.replace(/_/g, ''));
    if (RE_SPECIAL_FLOAT.test(tok)) return tagged('float', tok.replace(/^\+/, ''));
    if (RE_DATETIME.test(tok)) return tagged('datetime', tok);
    if (RE_DATE.test(tok)) return tagged('date', tok);
    if (RE_TIME.test(tok)) return tagged('time', tok);
    return this.fail('unsupported value');
  }
}

/** Parse a TOML document. Throws `TomlParseError` on malformed or unsupported input. */
export function parseToml(src: string): Record<string, unknown> {
  return new Parser(src.charCodeAt(0) === 0xfeff ? src.slice(1) : src).parse();
}
