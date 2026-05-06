// Stub for OpenClaw 2026.5.5+ install-time hook-pack validation.
// The real llm_input handler is registered at runtime via the plugin entry
// (./dist/index.js, see openclaw.extensions in ../package.json) which calls
// api.registerHook("llm_input", ...) during plugin init. This file exists
// purely so validateHookDir's existence check passes.
export default function llmInputStub() {}
