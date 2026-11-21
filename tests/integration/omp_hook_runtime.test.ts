import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { executeCommand, parseDescriptor, registerHooks } from "../../src/apm_cli/integration/omp_hook_runtime";

let root: string;
let source: string;
let cwd: string;
let fixture: string;
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "apm-hook-runtime-"));
  source = join(root, "package with spaces");
  cwd = join(root, "project");
  fixture = join(source, "hook.cjs");
  await mkdir(source);
  await mkdir(cwd);
  await mkdir(join(root, "data"));
  await writeFile(join(source, "policy.txt"), "package sibling policy");
  await writeFile(fixture, `
const fs = require('node:fs');
const {spawn} = require('node:child_process');
let stdin = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => stdin += chunk);
process.stdin.on('end', () => {
  const input = JSON.parse(stdin);
  const mode = process.env.FIXTURE_MODE;
  if (process.env.CAPTURE) fs.writeFileSync(process.env.CAPTURE, JSON.stringify({input, cwd:process.cwd(), root:process.env.PLUGIN_ROOT, claudeRoot:process.env.CLAUDE_PLUGIN_ROOT, data:process.env.APM_HOOK_DATA_DIR, marker:process.env.MARKER}));
  if (mode === 'deny') {
    if (input.tool_input.command.includes('forbidden')) { process.stderr.write('policy denied shell command'); process.exitCode = 2; }
    return;
  }
  if (mode === 'path-policy') {
    if (input.tool_input.file_path && input.tool_input.file_path.includes('protected')) {
      process.stderr.write('protected file denied'); process.exitCode = 2;
    } else process.stdout.write('{}');
    return;
  }
  if (mode === 'task-policy') {
    if (input.tool_input.subagent_type === 'unsafe') {
      process.stderr.write('unsafe subagent denied'); process.exitCode = 2;
    } else process.stdout.write('{}');
    return;
  }
  if (mode === 'rewrite') {
    const policy = fs.readFileSync(process.env.PLUGIN_ROOT + '/policy.txt', 'utf8');
    const updated = {...input.tool_input, file_path:process.env.REWRITE_PATH || 'renamed.txt'};
    if (process.env.REWRITE_OFFSET) updated.offset = Number(process.env.REWRITE_OFFSET);
    if (process.env.REWRITE_LIMIT) updated.limit = Number(process.env.REWRITE_LIMIT);
    process.stdout.write(JSON.stringify({hookSpecificOutput:{hookEventName:input.hook_event_name,updatedInput:updated,additionalContext:policy}}));
    return;
  }
  if (mode === 'session') { process.stdout.write(fs.readFileSync(process.env.PLUGIN_ROOT + '/policy.txt','utf8')); return; }
  if (mode === 'stop') {
    process.stdout.write(JSON.stringify(input.stop_hook_active ? {} : {decision:'block', reason:'finish verification'}));
    return;
  }
  if (mode === 'post') {
    process.stdout.write(JSON.stringify({hookSpecificOutput:{hookEventName:input.hook_event_name, additionalContext:input.error ? 'recover: ' + input.error : 'tool succeeded'}}));
    return;
  }
  if (mode === 'compact') { process.stderr.write('keep current history'); process.exitCode = 2; return; }
  if (mode === 'output') { process.stdout.write(process.env.OUTPUT); return; }
  if (mode === 'overflow') { process.stdout.write('x'.repeat(1024 * 1024 + 1)); return; }
  if (mode === 'hang') {
    const child = spawn(process.execPath, ['-e','setInterval(() => {}, 1000)'], {stdio:'ignore'});
    fs.writeFileSync(process.env.PID_FILE, JSON.stringify([process.pid, child.pid]));
    setInterval(() => {}, 1000);
  }
});
`);
});
afterEach(async () => { await rm(root, { recursive: true, force: true }); });

function command(mode: string, env: Record<string, string> = {}) {
  return {
    type: "command" as const,
    command: `${quote(process.execPath)} ${quote(fixture)}`,
    env: { FIXTURE_MODE: mode, ...env },
    apm: { owner: "fixtures/policy", root: source, dataDir: join(root, "data") },
  };
}
function harness(hooks: Record<string, unknown>) {
  type Result = Record<string, unknown>;
  const handlers = new Map<string, ((event: Result, ctx: ExtensionContext) => Promise<Result | undefined>)[]>();
  const notices: string[] = [];
  const statuses: unknown[] = [];
  const ctx = {
    cwd, mode: "rpc",
    sessionManager: { getSessionId: () => "session-fixture", getSessionFile: () => join(root, "session.jsonl") },
    ui: { notify: (message: string) => notices.push(message), setStatus: (...args: unknown[]) => statuses.push(args) },
  } as unknown as ExtensionContext;
  registerHooks({ on: (name: string, handler: (event: Result, ctx: ExtensionContext) => Promise<Result | undefined>) => {
    const list = handlers.get(name) ?? [];
    list.push(handler);
    handlers.set(name, list);
  } } as unknown as ExtensionAPI, { hooks });
  return {
    notices, statuses, handlers,
    async emit(name: string, event: Record<string, unknown> = {}) {
      const results: Result[] = [];
      for (const handler of handlers.get(name) ?? []) {
        const result = await handler({ type: name, ...event }, ctx);
        if (result) results.push(result);
        if (result?.block || result?.decision === "block" || result?.cancel) break;
      }
      return results;
    },
  };
}

const tool = (name: string, input: Record<string, unknown>) => ({ toolName: name, toolCallId: "call-1", input });

test("declared shell receives JSON literally, native cwd, package resources and environment", async () => {
  const capture = join(root, "captured.json");
  const bridge = harness({ PreToolUse: [{ matcher: "^Bash$", hooks: [command("deny", { CAPTURE: capture, MARKER: "declared" })] }] });
  const dangerous = `forbidden $(touch ${join(root, "injected")}) ' \"\nline`;
  expect(await bridge.emit("tool_call", tool("bash", { command: dangerous }))).toEqual([{ block: true, reason: "policy denied shell command" }]);
  const recorded = JSON.parse(await readFile(capture, "utf8"));
  expect(recorded).toMatchObject({ cwd, root: source, claudeRoot: source, data: join(root, "data"), marker: "declared", input: { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: dangerous }, cwd, session_id: "session-fixture" } });
  expect(await readFile(join(root, "injected"), "utf8").catch(() => null)).toBeNull();
});

test("foreign Read update and context become native path selectors", async () => {
  const capture = join(root, "read-input.json");
  const bridge = harness({ PreToolUse: [{ matcher: "Read|write", hooks: [command("rewrite", { CAPTURE: capture, REWRITE_OFFSET: "2", REWRITE_LIMIT: "3" })] }] });
  expect(await bridge.emit("tool_call", tool("read", { path: "notes.txt" }))).toEqual([{ input: { path: "renamed.txt:raw:2+3" }, additionalContext: "package sibling policy" }]);
  expect(JSON.parse(await readFile(capture, "utf8")).input.tool_input).toEqual({ file_path: "notes.txt" });
  expect(await bridge.emit("tool_call", tool("bash", { command: "forbidden" }))).toEqual([]);
});

test("each command registers separately and native and foreign tool vocabulary both match", async () => {
  const capture = join(root, "capture.json");
  const bridge = harness({ PreToolUse: [{ matcher: "^bash$", hooks: [command("deny", { CAPTURE: capture }), command("deny")] }] });
  expect(bridge.handlers.get("tool_call")).toHaveLength(2);
  expect(await bridge.emit("tool_call", tool("bash", { command: "safe" }))).toEqual([]);
  expect(JSON.parse(await readFile(capture, "utf8")).input.tool_name).toBe("Bash");
});

test("plaintext SessionStart context is delivered once as hidden before-agent message", async () => {
  const bridge = harness({ SessionStart: [{ hooks: [{ ...command("session"), statusMessage: "Reading policy" }] }] });
  expect(await bridge.emit("session_start")).toEqual([]);
  expect(await bridge.emit("before_agent_start")).toEqual([{ message: { customType: "apm-hooks", content: "package sibling policy", display: false } }]);
  expect(await bridge.emit("before_agent_start")).toEqual([]);
  expect(bridge.statuses).toEqual([["apm-hook-0", "Reading policy"], ["apm-hook-0", undefined]]);
});

test("success and failure hooks do not alias each other; feedback reaches native context", async () => {
  const bridge = harness({
    PostToolUse: [{ hooks: [command("post")] }],
    PostToolUseFailure: [{ hooks: [command("post")] }],
  });
  const event = { ...tool("bash", { command: "run" }), content: [{ type: "text", text: "failed command" }] };
  expect(await bridge.emit("tool_result", { ...event, isError: false })).toEqual([{ additionalContext: "tool succeeded" }]);
  expect(await bridge.emit("tool_result", { ...event, isError: true })).toEqual([{ additionalContext: "recover: failed command" }]);
});

test("Stop receives continuation guard and returns actual native block; PreCompact exit2 cancels", async () => {
  const bridge = harness({ Stop: [{ hooks: [command("stop")] }], PreCompact: [{ hooks: [command("compact")] }] });
  expect(await bridge.emit("session_stop", { stop_hook_active: false })).toEqual([{ decision: "block", reason: "finish verification" }]);
  expect(await bridge.emit("session_stop", { stop_hook_active: true })).toEqual([]);
  expect(await bridge.emit("session_before_compact")).toEqual([{ cancel: true }]);
  expect(bridge.notices).toContain("keep current history");
});

test("MCP post output replacement uses supported native content", async () => {
  const output = JSON.stringify({ hookSpecificOutput: { hookEventName: "PostToolUse", updatedMCPToolOutput: { answer: 42 } } });
  const bridge = harness({ PostToolUse: [{ hooks: [command("output", { OUTPUT: output })] }] });
  expect(await bridge.emit("tool_result", { ...tool("mcp__fixture_answer", {}), isError: false, content: [] })).toEqual([{ content: [{ type: "text", text: '{"answer":42}' }] }]);
});

test("unsafe hashline/batch rewrites, ask decisions and invalid Read offsets fail explicitly", async () => {
  for (const [name, specific] of [
    ["edit", { updatedInput: { file_path: "x", old_string: "a", new_string: "b" } }],
    ["task", { updatedInput: { prompt: "single task" } }],
    ["read", { updatedInput: { file_path: "x", offset: -1 } }],
    ["bash", { permissionDecision: "ask" }],
  ] as const) {
    const bridge = harness({ PreToolUse: [{ hooks: [command("output", { OUTPUT: JSON.stringify({ hookSpecificOutput: specific }) })] }] });
    const input = name === "edit" ? { path: "ordinary.txt", old_string: "before", new_string: "after" } : {};
    await expect(bridge.emit("tool_call", tool(name, input))).rejects.toThrow();
  }
});

test("invalid output cannot bypass PreCompact or Stop gates", async () => {
  const bridge = harness({ PreCompact: [{ hooks: [command("output", { OUTPUT: "{broken" })] }], Stop: [{ hooks: [command("output", { OUTPUT: '{"unrecognized":true}' })] }] });
  expect(await bridge.emit("session_before_compact")).toEqual([{ cancel: true }]);
  const stopped = await bridge.emit("session_stop");
  expect(stopped[0].decision).toBe("block");
  expect(stopped[0].reason).toContain("unsupported fields");
});

test("descriptor rejects incompatible events, matchers, async and native budget overruns", () => {
  for (const event of ["UserPromptSubmit", "PermissionRequest", "Notification", "SubagentStop"]) {
    expect(() => harness({ [event]: [{ hooks: [command("deny")] }] })).toThrow("Unsupported omp hook event");
  }
  for (const [event, entry] of [
    ["SessionStart", { matcher: "startup", hooks: [command("session")] }],
    ["PreToolUse", { matcher: "mcp__server__tool", hooks: [command("deny")] }],
    ["PreToolUse", { hooks: [{ ...command("deny"), async: true }] }],
    ["PreToolUse", { hooks: [{ ...command("deny"), timeout: 30 }] }],
    ["SessionEnd", { hooks: [{ ...command("deny"), timeout: 2 }] }],
  ]) expect(() => harness({ [event as string]: [entry] })).toThrow();
});

test("unmanaged descriptor entries are neither executed nor treated as APM declarations", async () => {
  const managed = command("deny");
  const { apm, ...foreign } = command("output", { OUTPUT: "invalid" });
  const descriptor = { foreignSetting: true, hooks: {
    Notification: [{ hooks: [foreign] }],
    PreToolUse: [{ hooks: [foreign, managed] }],
  } };
  expect(parseDescriptor(descriptor)).toHaveLength(1);
  const bridge = harness(descriptor.hooks);
  expect(await bridge.emit("tool_call", tool("bash", { command: "forbidden" }))).toEqual([{ block: true, reason: "policy denied shell command" }]);
});

// A child process offers no readiness event beyond the file it writes; poll for that real signal.
async function recordedPids(path: string): Promise<number[]> {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const text = await readFile(path, "utf8").catch(() => "");
    if (text) return JSON.parse(text);
    await Bun.sleep(10);
  }
  throw new Error("Fixture did not create process tree");
}
async function expectDead(pid: number): Promise<void> {
  // Linux may retain an orphan zombie until its reaper runs; it cannot execute.
  const stat = await readFile(`/proc/${pid}/stat`, "utf8").catch(() => "");
  if (stat) expect(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[0]).toBe("Z");
}

test("cancellation kills actual hook process and its descendant", async () => {
  const pidFile = join(root, "pids.json");
  const controller = new AbortController();
  const pending = executeCommand(command("hang", { PID_FILE: pidFile }), {}, cwd, 5000, controller.signal);
  const rejection = pending.then(() => undefined, (error: unknown) => error);
  const pids = await recordedPids(pidFile);
  controller.abort();
  const error = await rejection;
  expect(error).toBeInstanceOf(Error);
  expect(error).toMatchObject({ message: expect.stringContaining("cancelled") });
  for (const pid of pids) await expectDead(pid);
});

test("bounded timeout and output terminate shell commands", async () => {
  const pidFile = join(root, "pids.json");
  await expect(executeCommand(command("hang", { PID_FILE: pidFile }), {}, cwd, 500)).rejects.toThrow("timed out");
  for (const pid of JSON.parse(await readFile(pidFile, "utf8"))) await expectDead(pid);
  await expect(executeCommand(command("overflow"), {}, cwd, 3000)).rejects.toThrow("output exceeds");
});

test("native Stop cancellation is passed to the child process", async () => {
  const pidFile = join(root, "pids.json");
  const controller = new AbortController();
  const bridge = harness({ Stop: [{ hooks: [command("hang", { PID_FILE: pidFile })] }] });
  const pending = bridge.emit("session_stop", { signal: controller.signal });
  const pids = await recordedPids(pidFile);
  controller.abort();
  expect((await pending)[0].decision).toBe("block");
  for (const pid of pids) await expectDead(pid);
});

test("shutdown terminates an in-flight tool hook", async () => {
  const pidFile = join(root, "pids.json");
  const bridge = harness({ PreToolUse: [{ hooks: [command("hang", { PID_FILE: pidFile })] }] });
  const pending = bridge.emit("tool_call", tool("bash", { command: "safe" }));
  const rejected = pending.then(() => undefined, (error: unknown) => error);
  const pids = await recordedPids(pidFile);
  await bridge.emit("session_shutdown");
  const error = await rejected;
  expect(error).toBeInstanceOf(Error);
  expect(error).toMatchObject({ message: expect.stringContaining("cancelled") });
  for (const pid of pids) await expectDead(pid);
});

test("Bash timeout milliseconds roundtrip to native seconds", async () => {
  const capture = join(root, "timeout-input.json");
  const output = JSON.stringify({ hookSpecificOutput: { updatedInput: { command: "safe replacement", timeout: 2500 } } });
  const bridge = harness({ PreToolUse: [{ hooks: [command("output", { OUTPUT: output, CAPTURE: capture })] }] });
  expect(await bridge.emit("tool_call", tool("bash", { command: "safe", timeout: 10 }))).toEqual([{ input: { command: "safe replacement", timeout: 2.5 } }]);
  expect(JSON.parse(await readFile(capture, "utf8")).input.tool_input.timeout).toBe(10000);
});

test("Stop preserves block context and treats continue:true as a no-op acknowledgement", async () => {
  const output = JSON.stringify({ decision: "block", reason: "finish checks", additionalContext: "check sibling package", hookSpecificOutput: { additionalContext: "run final validation" } });
  const bridge = harness({ Stop: [{ hooks: [command("output", { OUTPUT: output })] }] });
  expect(await bridge.emit("session_stop")).toEqual([{ decision: "block", reason: "finish checks", additionalContext: "check sibling package\n\nrun final validation" }]);
  const acknowledged = harness({ Stop: [{ hooks: [command("output", { OUTPUT: '{"continue":true}' })] }] });
  expect(await acknowledged.emit("session_stop")).toEqual([]);
  const incompatible = harness({ Stop: [{ hooks: [command("output", { OUTPUT: '{"continue":false}' })] }] });
  const rejected = await incompatible.emit("session_stop");
  expect(rejected[0].reason).toContain("cannot represent a native session halt");
});

test("declared shell selection is honored without interpolating payload", async () => {
  const declared = command("deny");
  declared.command = `[[ -n "$CLAUDE_PLUGIN_ROOT" ]] && ${declared.command}`;
  const bridge = harness({ PreToolUse: [{ hooks: [{ ...declared, shell: "/bin/bash" }] }] });
  expect(await bridge.emit("tool_call", tool("bash", { command: "forbidden" }))).toEqual([{ block: true, reason: "policy denied shell command" }]);
});

test("Stop payload flattens text blocks and preserves string and absent assistant messages", async () => {
  const capture = join(root, "stop-input.json");
  const bridge = harness({ Stop: [{ hooks: [command("output", { CAPTURE: capture, OUTPUT: "{}" })] }] });
  const last = { role: "assistant", content: [{ type: "text", text: "first paragraph" }, { type: "thinking", thinking: "private" }, { type: "toolCall", name: "read", arguments: {} }, { type: "text", text: "second paragraph" }] };
  await bridge.emit("session_stop", { last_assistant_message: last });
  expect(JSON.parse(await readFile(capture, "utf8")).input.last_assistant_message).toBe("first paragraph\nsecond paragraph");
  await bridge.emit("session_stop", { last_assistant_message: "already text" });
  expect(JSON.parse(await readFile(capture, "utf8")).input.last_assistant_message).toBe("already text");
  await bridge.emit("session_stop");
  expect(Object.hasOwn(JSON.parse(await readFile(capture, "utf8")).input, "last_assistant_message")).toBe(false);
});

test("Write full-input rewrites receive one canonical path field and preserve content", async () => {
  const capture = join(root, "write-input.json");
  const bridge = harness({ PreToolUse: [{ hooks: [command("rewrite", { CAPTURE: capture, REWRITE_PATH: "renamed.md" })] }] });
  expect(await bridge.emit("tool_call", tool("write", { path: "old.md", content: "keep this body" }))).toEqual([{ input: { path: "renamed.md", content: "keep this body" }, additionalContext: "package sibling policy" }]);
  expect(JSON.parse(await readFile(capture, "utf8")).input.tool_input).toEqual({ file_path: "old.md", content: "keep this body" });
});

test("Read numeric selectors expose truthful file paths and roundtrip path-only full-input updates", async () => {
  const capture = join(root, "selected-read.json");
  const bridge = harness({ PreToolUse: [{ hooks: [command("rewrite", { CAPTURE: capture })] }] });
  await writeFile(join(cwd, "notes.txt"), "first\nsecond\nthird\nfourth\nfifth\n");
  for (const [selector, selection] of [
    [":2-4", { offset: 2, limit: 3 }], [":3", { offset: 3 }], [":3-", { offset: 3 }],
    [":raw:3", { offset: 3, limit: 1 }], [":2+3:raw", { offset: 2, limit: 3 }],
    [":L2-L4", { offset: 2, limit: 3 }], [":raw", {}],
  ] as const) {
    const result = await bridge.emit("tool_call", tool("read", { path: `notes.txt${selector}` }));
    expect(result[0].input).toEqual({ path: `renamed.txt${selector}` });
    expect(JSON.parse(await readFile(capture, "utf8")).input.tool_input).toEqual({ file_path: "notes.txt", ...selection });
  }
});

test("Read preserves existing literal colon filenames instead of silently inventing selectors", async () => {
  const capture = join(root, "literal-read.json");
  await writeFile(join(cwd, "notes.txt:2-4"), "a literal file");
  const bridge = harness({ PreToolUse: [{ hooks: [command("rewrite", { CAPTURE: capture })] }] });
  expect((await bridge.emit("tool_call", tool("read", { path: "notes.txt:2-4" })))[0].input).toEqual({ path: "renamed.txt" });
  expect(JSON.parse(await readFile(capture, "utf8")).input.tool_input).toEqual({ file_path: "notes.txt:2-4" });
});

test("Read rejects unrepresentable native selectors/resources before executing foreign hooks", async () => {
  const capture = join(root, "unsupported-read.json");
  const bridge = harness({ PreToolUse: [{ hooks: [command("output", { CAPTURE: capture, OUTPUT: "{}" })] }] });
  for (const path of ["notes.txt:1,3", "notes.txt:-5", "notes.txt:img", "data.db:users", "archive.zip:member.txt:2-4", "https://example.com/file:2-4", "local://notes.txt:2-4", "data.json?q=.x", "clip.mp4:12", "notes.txt:raw:1,3"]) {
    await expect(bridge.emit("tool_call", tool("read", { path }))).rejects.toThrow("cannot faithfully map");
  }
  expect(await readFile(capture, "utf8").catch(() => null)).toBeNull();
});

test("continue:true is also a no-op for non-Stop hooks", async () => {
  const bridge = harness({ PreToolUse: [{ hooks: [command("output", { OUTPUT: '{"continue":true}' })] }] });
  expect(await bridge.emit("tool_call", tool("bash", { command: "safe" }))).toEqual([]);
});

test("multi-file hashline edits cannot reach a foreign policy that allows missing file_path", async () => {
  const capture = join(root, "edit-policy.json");
  const declared = command("path-policy", { CAPTURE: capture });
  // Exercise the actual policy's permissive missing-path branch first, so the
  // regression proves the bridge closes this gap rather than relying on a deny-all hook.
  const legacyPayload = { tool_name: "Edit", tool_input: { input: "native patch", paths: ["ordinary.txt", "protected.txt"] } };
  expect(await executeCommand(declared, legacyPayload, cwd, 3000)).toMatchObject({ code: 0, stdout: "{}" });
  await rm(capture);
  const bridge = harness({ PreToolUse: [{ matcher: "Edit", hooks: [declared] }] });
  const patch = "[ordinary.txt#1234]\nPUT 1.=1:\n+change\n[protected.txt#5678]\nPUT 1.=1:\n+change";
  // Native ExtensionRunner turns this tool_call exception into block:true.
  await expect(bridge.emit("tool_call", tool("edit", { input: patch, paths: ["ordinary.txt", "protected.txt"] }))).rejects.toThrow("cannot faithfully map");
  expect(await readFile(capture, "utf8").catch(() => null)).toBeNull();
});

test("only native single-file replace edits expose the complete foreign Edit payload", async () => {
  const capture = join(root, "replace-policy.json");
  const bridge = harness({ PreToolUse: [{ matcher: "Edit", hooks: [command("path-policy", { CAPTURE: capture })] }] });
  const input = { path: "protected.txt", old_string: "original text", new_string: "replacement text", replace_all: true };
  expect(await bridge.emit("tool_call", tool("edit", input))).toEqual([{ block: true, reason: "protected file denied" }]);
  expect(JSON.parse(await readFile(capture, "utf8")).input.tool_input).toEqual({ file_path: "protected.txt", old_string: "original text", new_string: "replacement text", replace_all: true });
  expect(await bridge.emit("tool_call", tool("edit", { ...input, path: "ordinary.txt" }))).toEqual([]);
});

test("singular derived paths and patch rename destinations do not masquerade as foreign Edit", async () => {
  const capture = join(root, "unsupported-edit.json");
  const bridge = harness({ PreToolUse: [{ matcher: "Edit", hooks: [command("path-policy", { CAPTURE: capture })] }] });
  for (const input of [
    { input: "[ordinary.txt#1234]\nMV protected.txt", path: "ordinary.txt", paths: ["ordinary.txt"] },
    { path: "ordinary.txt", edits: [{ rename: "protected.txt", diff: "@@\n-before\n+after" }] },
    { path: "ordinary.txt", edits: [{ old_string: "before", new_string: "after" }] },
    { path: "ordinary.txt" },
    { path: "ordinary.txt", old_string: "before", new_string: "after", file_path: "protected.txt" },
  ]) await expect(bridge.emit("tool_call", tool("edit", input))).rejects.toThrow("cannot faithfully map");
  expect(await readFile(capture, "utf8").catch(() => null)).toBeNull();
});

test("native task batches never reach a foreign guard that allows missing subagent_type", async () => {
  const capture = join(root, "task-policy.json");
  const declared = command("task-policy", { CAPTURE: capture });
  const input = { tasks: [{ agent: "unsafe", task: "protected action" }, { agent: "safe", task: "ordinary action" }] };
  expect(await executeCommand(declared, { tool_name: "Task", tool_input: input }, cwd, 3000)).toMatchObject({ code: 0, stdout: "{}" });
  await rm(capture);
  const bridge = harness({ PreToolUse: [{ matcher: "Task", hooks: [declared] }] });
  // Native tool_call dispatch converts this pre-execution failure to block:true.
  await expect(bridge.emit("tool_call", tool("task", input))).rejects.toThrow("cannot faithfully map");
  expect(await readFile(capture, "utf8").catch(() => null)).toBeNull();
});
