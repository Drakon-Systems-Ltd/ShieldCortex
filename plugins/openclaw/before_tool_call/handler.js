// Stub for OpenClaw 2026.5.5+ install-time hook-pack validation.
// The real before_tool_call handler is registered at runtime via the plugin
// entry (./dist/index.js, see openclaw.extensions in ../package.json) which
// calls api.registerHook("before_tool_call", ...) during plugin init. This
// file exists purely so validateHookDir's existence check passes.
export default function beforeToolCallStub() {}
