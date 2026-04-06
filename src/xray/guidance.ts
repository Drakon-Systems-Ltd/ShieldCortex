/**
 * X-Ray Finding Guidance
 *
 * Human-readable explanations for each finding category.
 * Tells users what a finding means, what to do about it,
 * and whether it's likely a false positive.
 */

import type { XRayCategory } from './types.js';

export interface FindingGuidance {
  /** Plain-language explanation of what this means */
  whatItMeans: string;
  /** What the user should do */
  whatToDo: string;
  /** When this is typically a false positive */
  falsePositiveNote: string;
  /** How serious this usually is: 'usually-safe' | 'investigate' | 'act-now' */
  urgency: 'usually-safe' | 'investigate' | 'act-now';
}

const GUIDANCE: Record<XRayCategory, { default: FindingGuidance; bySeverity?: Partial<Record<string, Partial<FindingGuidance>>> }> = {

  'prompt-injection': {
    default: {
      whatItMeans: 'This file contains text that looks like it\'s trying to override AI instructions — phrases like "ignore previous instructions" or "you are now in developer mode". If an AI agent reads this file, it could be tricked into doing something unintended.',
      whatToDo: 'If this is a file you wrote or trust, it\'s probably fine (security research, test fixtures, documentation about prompt injection). If it came from an untrusted source — an npm package, a downloaded file, a PR from someone you don\'t know — quarantine it and investigate.',
      falsePositiveNote: 'Common in security research files, AI safety documentation, and test fixtures that deliberately contain injection examples.',
      urgency: 'investigate',
    },
    bySeverity: {
      critical: { urgency: 'act-now', whatToDo: 'This contains strong injection patterns. Quarantine immediately if the source is untrusted. Do not let AI agents process this file until you\'ve reviewed it.' },
    },
  },

  'eval-exec': {
    default: {
      whatItMeans: 'This file uses dynamic code execution — things like eval(), new Function(), or vm.runInContext(). These can run arbitrary code at runtime, which is how many supply chain attacks work.',
      whatToDo: 'If this is your own code or a well-known library, it\'s likely intentional (bundlers, template engines, and test frameworks use eval legitimately). If it\'s in an unfamiliar dependency, investigate why it needs to execute code dynamically.',
      falsePositiveNote: 'Very common in bundlers (webpack, esbuild), template engines (EJS, Handlebars), and testing frameworks. Also appears in legitimate serialisation libraries.',
      urgency: 'investigate',
    },
  },

  'shell-execution': {
    default: {
      whatItMeans: 'This file runs shell commands using child_process, exec, or spawn. It can execute anything your terminal can — install software, delete files, or send data to external servers.',
      whatToDo: 'If this is a build tool, CLI utility, or dev script you recognise, it\'s expected. If it\'s inside an npm package you didn\'t write, check exactly what commands it runs. Packages should not need shell access at runtime.',
      falsePositiveNote: 'Normal in CLI tools, build scripts, and developer utilities. Suspicious in libraries that claim to be pure JavaScript (e.g. a "string formatting" package that spawns shells).',
      urgency: 'investigate',
    },
    bySeverity: {
      critical: { urgency: 'act-now', whatToDo: 'Shell execution in a context where it shouldn\'t be needed. Review the exact commands being run. If this is an npm package, check if the commands make sense for what the package claims to do.' },
    },
  },

  'network-beacon': {
    default: {
      whatItMeans: 'This file makes network requests (fetch, http.get, XMLHttpRequest) at load time — not when called by your code, but as soon as the file is imported. This is how data exfiltration works: the package phones home the moment it\'s installed.',
      whatToDo: 'If this is an analytics SDK, telemetry module, or API client, it may be intentional. If it\'s a utility library that shouldn\'t need network access, this is a red flag. Check where the requests go.',
      falsePositiveNote: 'Expected in analytics SDKs, telemetry, update checkers, and API clients. Suspicious in utility libraries, parsers, or formatting tools.',
      urgency: 'investigate',
    },
    bySeverity: {
      critical: { urgency: 'act-now', whatToDo: 'Network requests at module load time are the #1 supply chain attack pattern. Check the destination URL immediately. If it points anywhere you don\'t recognise, quarantine this file.' },
    },
  },

  'obfuscation': {
    default: {
      whatItMeans: 'This file contains code that\'s been deliberately made hard to read — hex-encoded strings, base64 decoding chains, String.fromCharCode sequences, or extremely long single lines. Legitimate code is rarely obfuscated this way.',
      whatToDo: 'If this is a minified production bundle (like a .min.js file), it\'s normal — minification looks like obfuscation to a scanner. If this is source code that should be readable, it\'s suspicious. Check if there\'s a readable version elsewhere in the package.',
      falsePositiveNote: 'Very common in minified bundles, compiled WASM, production builds, and binary data files. Also triggers on long JSON files and machine-generated code.',
      urgency: 'usually-safe',
    },
    bySeverity: {
      high: { urgency: 'investigate', whatToDo: 'Heavy obfuscation beyond simple minification. Check if this file has a source map or unminified equivalent. If not, investigate what it does.' },
    },
  },

  'steganography': {
    default: {
      whatItMeans: 'This file appears to contain hidden data — extra bytes after the end of an image, data embedded in metadata, or content disguised as a different file type. Attackers sometimes hide payloads this way.',
      whatToDo: 'If this is a system log, browser cache file, or macOS diagnostic file, it\'s almost certainly a false positive — these file formats naturally contain multiple data sections that look like different formats. If this is an image or document from an untrusted source, investigate further.',
      falsePositiveNote: 'Very common false positive on system files, browser caches, macOS .tracev3 logs, Outlook cache files, and any binary file that contains compressed data sections.',
      urgency: 'usually-safe',
    },
    bySeverity: {
      critical: { urgency: 'investigate', whatToDo: 'Multiple format signatures detected. This could be a polyglot file designed to bypass security filters. If this is a system file, it\'s safe to ignore. If it came from an external source, quarantine and examine.' },
    },
  },

  'unicode-trick': {
    default: {
      whatItMeans: 'This file contains invisible Unicode characters — zero-width spaces, right-to-left overrides, or homoglyph characters that look identical to normal letters but aren\'t. These can make code appear to do one thing while actually doing another.',
      whatToDo: 'This is almost never legitimate in source code. Check the file in a hex editor to see the actual characters. If they\'re in comments or strings, someone may be trying to hide instructions from human reviewers while keeping them visible to AI agents.',
      falsePositiveNote: 'Can appear in files with international text (Arabic, Hebrew), copy-pasted content from web pages, or markdown with special formatting.',
      urgency: 'investigate',
    },
    bySeverity: {
      critical: { urgency: 'act-now', whatToDo: 'Multiple invisible characters in source code. This is the classic prompt injection steganography attack. Quarantine this file and inspect in a hex editor before allowing any AI agent to read it.' },
    },
  },

  'metadata-exploit': {
    default: {
      whatItMeans: 'This file\'s metadata (package.json fields, image EXIF data, document properties) contains text that looks like AI instructions. Attackers embed directives in metadata because AI agents often read it without the user noticing.',
      whatToDo: 'Check the metadata fields manually. If description, keywords, or author fields contain instructions ("ignore", "execute", "override"), that\'s a supply chain injection attempt. If it\'s normal descriptive text, it\'s fine.',
      falsePositiveNote: 'Can trigger on packages with detailed descriptions that happen to use instructional language.',
      urgency: 'investigate',
    },
  },

  'persistence-hook': {
    default: {
      whatItMeans: 'This package has lifecycle scripts (postinstall, preinstall, prepare) that run automatically when you install it. Most packages don\'t need these — they\'re the most common vector for supply chain attacks.',
      whatToDo: 'Check what the scripts actually do. Legitimate uses: native module compilation (like node-gyp), husky git hooks, or initial setup. Suspicious uses: downloading files, running encoded commands, or making network requests.',
      falsePositiveNote: 'Common in packages with native bindings (better-sqlite3, sharp, node-canvas) and developer tooling (husky, lint-staged).',
      urgency: 'investigate',
    },
  },

  'covert-channel': {
    default: {
      whatItMeans: 'This file appears to use hidden communication channels — DNS exfiltration, steganographic data encoding, or other methods to send data without obvious network calls.',
      whatToDo: 'This is rarely a false positive. Review the code carefully to understand what data is being sent and where. If you can\'t explain why this code exists, quarantine the file.',
      falsePositiveNote: 'Rare false positive. May trigger on DNS libraries, image processing code, or encoding utilities.',
      urgency: 'act-now',
    },
  },

  'dependency-risk': {
    default: {
      whatItMeans: 'This package has risky dependency patterns — wildcard version ranges (\"*\"), git URLs instead of registry versions, multiple suspicious lifecycle hooks, or an unusual number of recent version bumps.',
      whatToDo: 'Check if the dependency versions are pinned. Wildcard ranges mean you could get a compromised version without realising. Git URLs bypass npm\'s security scanning. Consider locking to specific versions.',
      falsePositiveNote: 'Common in early-stage packages, monorepo setups, and packages that depend on pre-release versions.',
      urgency: 'usually-safe',
    },
    bySeverity: {
      high: { urgency: 'investigate', whatToDo: 'Multiple dependency risk signals combined. This package has an unusual dependency profile — review each flagged dependency individually.' },
    },
  },

  'ai-directive': {
    default: {
      whatItMeans: 'This file contains text that looks like instructions meant for an AI agent — phrases like "you must", "system prompt", "assistant instructions", or role-play directives. If an agent reads this file, it could alter its behaviour.',
      whatToDo: 'If this is a .cursorrules, CLAUDE.md, or similar AI configuration file, it\'s expected. If it\'s inside an npm package, a data file, or somewhere AI instructions shouldn\'t be, it\'s a prompt injection attempt. Quarantine and review.',
      falsePositiveNote: 'Expected in AI agent configuration files (CLAUDE.md, .cursorrules, system prompts). Suspicious in library code, data files, or package metadata.',
      urgency: 'investigate',
    },
    bySeverity: {
      critical: { urgency: 'act-now', whatToDo: 'Strong AI directive patterns in a file that shouldn\'t contain them. This looks like a deliberate prompt injection. Quarantine immediately and do not let AI agents process this file.' },
    },
  },
};

/**
 * Get human-readable guidance for a finding.
 */
export function getGuidance(category: XRayCategory, severity: string): FindingGuidance {
  const entry = GUIDANCE[category];
  if (!entry) {
    return {
      whatItMeans: 'An unusual pattern was detected in this file.',
      whatToDo: 'Review the file manually to determine if this is expected behaviour.',
      falsePositiveNote: 'May be a false positive depending on the file type and context.',
      urgency: 'investigate',
    };
  }

  const base = entry.default;
  const override = entry.bySeverity?.[severity];

  if (!override) return base;

  return {
    ...base,
    ...override,
  };
}

/**
 * Check if a file path looks like a system/cache file that commonly triggers false positives.
 */
export function isLikelySystemFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  const systemPatterns = [
    '/library/caches/',
    '/library/application support/',
    '/library/group containers/',
    '/library/logs/',
    '/library/preferences/',
    '/library/saved application state/',
    '/private/var/',
    '/var/db/',
    '/var/log/',
    '/var/folders/',
    '/.shieldcortex/',
    '/.npm/',
    '/.cache/',
    '/cache_data/',
    '/code cache/',
    '/gpucache/',
    '/serviceworker/',
    '.tracev3',
    '.diagnostics',
    '.plist',
  ];

  return systemPatterns.some(p => lower.includes(p));
}
