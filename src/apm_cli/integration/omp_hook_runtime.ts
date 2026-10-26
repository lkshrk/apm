import { spawn } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

// Copied verbatim to <targetRoot>/extensions/<scope-specific bridge name>/index.ts.
const EVENTS = {
  PreToolUse: "tool_call",
  PostToolUse: "tool_result",
  PostToolUseFailure: "tool_result",
  SessionStart: "session_start",
  SessionEnd: "session_shutdown",
  Stop: "session_stop",
  PreCompact: "session_before_compact",
  PostCompact: "session_compact",
} as const;
type HookEvent = keyof typeof EVENTS;
type ObjectValue = Record<string, unknown>;
interface Command {
  type: "command";
  command: string;
  timeout?: number;
  shell?: string;
  env?: Record<string, string>;
  statusMessage?: string;
  apm: { owner: string; root: string; dataDir: string };
}
interface Registration { event: HookEvent; command: Command; matcher?: RegExp }
interface ProcessResult { stdout: string; stderr: string; code: number }
const OUTPUT_LIMIT = 1024 * 1024;
const TOOL_NAMES: Record<string, string> = {
  bash: "Bash", read: "Read", write: "Write", edit: "Edit", grep: "Grep", glob: "Glob", task: "Task",
};

function object(value: unknown, label: string): ObjectValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as ObjectValue;
}
function keys(value: ObjectValue, allowed: string[], label: string): void {
  const extra = Object.keys(value).filter(key => !allowed.includes(key));
  if (extra.length) throw new Error(`${label}: unsupported fields ${extra.join(", ")}`);
}
function text(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  return value;
}
function timeout(event: HookEvent, command: Command): number {
  return (command.timeout ?? (event === "SessionEnd" ? 1.5 : 29)) * 1000;
}

export function parseDescriptor(value: unknown): Registration[] {
  const document = object(value, "hook descriptor");
  const hooks = object(document.hooks, "hooks");
  const registrations: Registration[] = [];
  for (const [name, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) continue;
    for (const rawEntry of entries) {
      if (!rawEntry || typeof rawEntry !== "object" || !Array.isArray(rawEntry.hooks)) continue;
      const owned = rawEntry.hooks.filter((raw: unknown) => raw !== null && typeof raw === "object" && Object.hasOwn(raw, "apm"));
      if (!owned.length) continue;
      if (!Object.hasOwn(EVENTS, name)) throw new Error(`Unsupported omp hook event: ${name}`);
      const event = name as HookEvent;
      const entry = object(rawEntry, event);
      keys(entry, ["matcher", "hooks"], event);
      const matcherText = entry.matcher === undefined ? "" : text(entry.matcher, "matcher");
      if (matcherText && !["PreToolUse", "PostToolUse", "PostToolUseFailure"].includes(event)) {
        throw new Error(`${event} matcher has no native equivalent`);
      }
      if (/mcp__.*__/.test(matcherText)) throw new Error("Foreign server-qualified MCP matchers cannot represent native single-separator tool names");
      const matcher = !matcherText || matcherText === "*" ? undefined : new RegExp(matcherText);
      for (const raw of owned) {
        const command = object(raw, "command hook");
        keys(command, ["type", "command", "timeout", "shell", "env", "statusMessage", "apm"], "command hook");
        if (command.type !== "command" || !text(command.command, "command").trim()) {
          throw new Error("Only nonempty declared command hooks are supported");
        }
        const max = event === "SessionEnd" ? 1.5 : 29;
        if (command.timeout !== undefined && (typeof command.timeout !== "number" || !Number.isFinite(command.timeout) || command.timeout <= 0 || command.timeout > max)) {
          throw new Error(`${event} timeout must be >0 and <=${max} seconds`);
        }
        if (command.shell !== undefined && !text(command.shell, "shell").trim()) throw new Error("shell must name an executable");
        if (command.statusMessage !== undefined) text(command.statusMessage, "statusMessage");
        if (command.env !== undefined) {
          for (const [key, val] of Object.entries(object(command.env, "env"))) {
            if (!key || key.includes("=") || key.includes("\0") || text(val, `env.${key}`).includes("\0")) throw new Error("Invalid hook environment");
          }
        }
        const apm = object(command.apm, "apm metadata");
        keys(apm, ["owner", "root", "dataDir"], "apm metadata");
        if (!text(apm.owner, "apm.owner").trim()) throw new Error("Missing hook owner");
        for (const key of ["root", "dataDir"]) if (!isAbsolute(text(apm[key], `apm.${key}`))) throw new Error(`apm.${key} must be absolute`);
        registrations.push({ event, command: command as unknown as Command, matcher });
      }
    }
  }
  return registrations;
}

/** JSON travels only over stdin, never through shell interpolation. */
export function executeCommand(command: Command, payload: ObjectValue, cwd: string, timeoutMs: number, signal?: AbortSignal): Promise<ProcessResult> {
  if (signal?.aborted) return Promise.reject(new Error("Hook cancelled"));
  if (process.platform === "win32") return Promise.reject(new Error("APM command hooks require POSIX process-group cleanup"));
  const { promise, resolve: resolveResult, reject } = Promise.withResolvers<ProcessResult>();
  const child = spawn(command.shell ?? "/bin/sh", ["-c", command.command], {
    cwd,
    env: {
      ...process.env, ...command.env,
      CLAUDE_PLUGIN_ROOT: command.apm.root, PLUGIN_ROOT: command.apm.root,
      CLAUDE_PLUGIN_DATA: command.apm.dataDir, APM_HOOK_DATA_DIR: command.apm.dataDir,
      CLAUDE_PROJECT_DIR: cwd,
    },
    detached: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  const stdoutDecoder = new StringDecoder("utf8");
  const stderrDecoder = new StringDecoder("utf8");
  let bytes = 0;
  let failure: Error | undefined;
  const kill = () => {
    if (!child.pid) return;
    try { process.kill(-child.pid, "SIGKILL"); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") failure ??= error as Error;
    }
  };
  const fail = (error: Error) => { failure ??= error; kill(); };
  const abort = () => fail(new Error("Hook cancelled"));
  const timer = setTimeout(() => fail(new Error(`Hook timed out after ${timeoutMs}ms`)), timeoutMs);
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
  const collect = (chunk: Buffer, target: "stdout" | "stderr") => {
    bytes += chunk.length;
    if (bytes > OUTPUT_LIMIT) { fail(new Error(`Hook output exceeds ${OUTPUT_LIMIT} bytes`)); return; }
    if (target === "stdout") stdout += stdoutDecoder.write(chunk); else stderr += stderrDecoder.write(chunk);
  };
  child.stdout.on("data", chunk => collect(chunk, "stdout"));
  child.stderr.on("data", chunk => collect(chunk, "stderr"));
  child.stdin.on("error", error => {
    // A hook may intentionally exit without consuming stdin.
    if ((error as NodeJS.ErrnoException).code !== "EPIPE") fail(error);
  });
  child.on("error", error => { failure ??= error; });
  child.on("exit", kill); // Also terminate descendants that retained stdout/stderr.
  child.on("close", (code, exitSignal) => {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
    if (failure) reject(failure);
    else if (code === null) reject(new Error(`Hook terminated by ${exitSignal}`));
    else resolveResult({ stdout: stdout + stdoutDecoder.end(), stderr: stderr + stderrDecoder.end(), code });
  });
  try { child.stdin.end(`${JSON.stringify(payload)}\n`); }
  catch (error) { fail(error as Error); }
  return promise;
}

async function foreignInput(tool: string, input: ObjectValue, cwd: string): Promise<ObjectValue> {
  if (tool === "task") throw new Error("Native batched task input cannot faithfully map to foreign Task prompt/subagent_type; use a native extension for this tool");
  if (tool === "bash" && typeof input.timeout === "number") return { ...input, timeout: input.timeout * 1000 };
  if (tool === "read" && typeof input.path === "string") return projectReadPath(input.path, cwd);
  if (tool === "write" && typeof input.path === "string") {
    const { path, ...rest } = input;
    return { ...rest, file_path: path };
  }
  if (tool === "edit") {
    // Native hashline/patch modes can hide several targets and move destinations
    // inside input/edits. A derived singular path is not sufficient evidence.
    const allowed = ["path", "old_string", "new_string", "replace_all"];
    if (Object.keys(input).some(key => !allowed.includes(key)) || typeof input.path !== "string" || !input.path.trim() || typeof input.old_string !== "string" || typeof input.new_string !== "string" || (input.replace_all !== undefined && typeof input.replace_all !== "boolean")) {
      throw new Error("Edit input cannot faithfully map to one foreign Edit; only native single-file replace mode is supported");
    }
    if (/^[~@:]|^[a-z][a-z0-9+.-]*:\/\//i.test(input.path)) throw new Error("Edit input cannot faithfully map native resource/path aliases to file_path");
    const { path, ...replacement } = input;
    return { ...replacement, file_path: path };
  }
  return input;
}
function readPathFailure(path: string): never {
  throw new Error(`Read path ${JSON.stringify(path)} uses a native resource or selector that cannot faithfully map to file_path/offset/limit`);
}
function readSelector(selector: string, path: string): { offset?: number; limit?: number } {
  if (selector.toLowerCase() === "raw") return {};
  const raw = /(^raw:|:raw$)/i.test(selector);
  const range = selector.replace(/^raw:|:raw$/gi, "");
  const match = /^L?(\d+)(?:(-|\.\.|\+)L?(\d*)?)?$/.exec(range);
  if (!match) return readPathFailure(path);
  const offset = Number(match[1]);
  const operator = match[2];
  const end = match[3];
  if (!Number.isSafeInteger(offset) || offset < 1) return readPathFailure(path);
  if (operator === "+" || end) {
    const number = Number(end);
    const limit = operator === "+" ? number : number - offset + 1;
    if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(offset + limit - 1)) return readPathFailure(path);
    return { offset, limit };
  }
  return raw && !operator ? { offset, limit: 1 } : { offset };
}
async function projectReadPath(path: string, cwd: string): Promise<ObjectValue> {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(path) || /^www\.|^[^/]+:\d+\//i.test(path) || /^[~@]/.test(path) || path.includes("?") || path.includes(";")) return readPathFailure(path);
  let separator = path.lastIndexOf(":");
  if (separator <= 0) return { file_path: path };
  // Native read lets an existing literal colon filename win over selector syntax.
  try {
    await lstat(resolve(cwd, path));
    return { file_path: path };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTDIR" && code !== "ENAMETOOLONG") return readPathFailure(path);
  }
  let selector = path.slice(separator + 1);
  const previous = path.lastIndexOf(":", separator - 1);
  if (previous > 0 && (selector.toLowerCase() === "raw" || path.slice(previous + 1, separator).toLowerCase() === "raw")) {
    selector = path.slice(previous + 1);
    separator = previous;
  }
  const filePath = path.slice(0, separator);
  if (filePath.includes(":") || /\.(?:db|sqlite3?|zip|tar|gz|bz2|xz|7z|rar|jar|whl|pdf|png|jpe?g|gif|webp|svgz?|mp4|mkv|mov|webm|avi|mp3|wav|wasm|exe|dll|so)$/i.test(filePath)) return readPathFailure(path);
  // offset/limit describe requested lines; native non-raw output can add context.
  return { file_path: filePath, ...readSelector(selector, path) };
}
function nativeReadPath(input: ObjectValue, nativeInput?: ObjectValue, original?: ObjectValue): string {
  keys(input, ["file_path", "offset", "limit"], "Read updatedInput");
  const filePath = text(input.file_path, "file_path");
  if (filePath.includes("?") || filePath.includes(";") || (filePath.includes(":") && filePath !== original?.file_path)) return readPathFailure(filePath);
  if (input.offset !== undefined && (typeof input.offset !== "number" || !Number.isSafeInteger(input.offset) || input.offset < 1)) throw new Error("Read updatedInput offset must be a positive integer");
  if (input.limit !== undefined && (typeof input.limit !== "number" || !Number.isSafeInteger(input.limit) || input.limit < 1)) throw new Error("Read updatedInput limit must be a positive integer");
  // A path-only rewrite of the full received input preserves the original native
  // selector and its raw/context formatting rather than widening or changing it.
  if (original && input.offset === original.offset && input.limit === original.limit && typeof original.file_path === "string" && typeof nativeInput?.path === "string") {
    return filePath + nativeInput.path.slice(original.file_path.length);
  }
  if (input.offset === undefined && input.limit === undefined) return filePath;
  const offset = (input.offset as number | undefined) ?? 1;
  if (input.limit === undefined) return `${filePath}:raw:${offset}-`;
  if (!Number.isSafeInteger(offset + (input.limit as number) - 1)) throw new Error("Read updatedInput range exceeds safe integer bounds");
  return `${filePath}:raw:${offset}+${input.limit}`;
}
function updatedInput(tool: string, value: unknown, nativeInput?: ObjectValue, original?: ObjectValue): ObjectValue {
  const input = { ...object(value, "updatedInput") };
  if (tool === "edit" || tool === "task") throw new Error(`updatedInput for ${tool} cannot safely represent native hashline/batched inputs`);
  if (tool === "read") {
    if (input.path !== undefined) throw new Error("Read updatedInput must use foreign file_path, offset and limit fields");
    return { path: nativeReadPath(input, nativeInput, original) };
  }
  if (tool === "write") {
    if (input.file_path !== undefined) {
      if (input.path !== undefined && input.path !== input.file_path) throw new Error("Conflicting path and file_path");
      input.path = text(input.file_path, "file_path");
      delete input.file_path;
    }
    keys(input, ["path", "content"], "Write updatedInput");
  }
  if (tool === "bash") {
    keys(input, ["command", "timeout", "cwd", "name", "ready", "async", "pty"], "Bash updatedInput");
    if (input.timeout !== undefined) {
      if (typeof input.timeout !== "number" || !Number.isFinite(input.timeout) || input.timeout <= 0) throw new Error("Bash updatedInput timeout must be positive milliseconds");
      input.timeout /= 1000;
    }
  }
  if (tool === "grep") keys(input, ["pattern", "path", "case", "gitignore", "skip"], "Grep updatedInput");
  if (tool === "glob") keys(input, ["path", "hidden", "gitignore", "limit"], "Glob updatedInput");
  return input;
}
async function payloadFor(event: HookEvent, native: ObjectValue, ctx: ExtensionContext): Promise<ObjectValue> {
  const payload: ObjectValue = {
    hook_event_name: event, cwd: ctx.cwd,
    session_id: ctx.sessionManager.getSessionId(),
    transcript_path: ctx.sessionManager.getSessionFile(),
  };
  if (typeof native.toolName === "string") {
    payload.tool_name = TOOL_NAMES[native.toolName] ?? native.toolName;
    payload.tool_use_id = native.toolCallId;
    payload.tool_input = await foreignInput(native.toolName, object(native.input, "tool input"), ctx.cwd);
    if (event !== "PreToolUse") {
      payload.tool_response = { content: native.content, details: native.details, isError: native.isError };
      if (native.isError) payload.error = (native.content as { text?: string }[]).map(part => part.text ?? "").join("\n");
    }
  }
  if (event === "Stop") {
    payload.stop_hook_active = native.stop_hook_active;
    const last = native.last_assistant_message;
    if (typeof last === "string") payload.last_assistant_message = last;
    else if (last !== undefined && last !== null) {
      const message = object(last, "last_assistant_message");
      if (typeof message.content === "string") payload.last_assistant_message = message.content;
      else if (Array.isArray(message.content)) {
        payload.last_assistant_message = message.content
          .filter(part => part !== null && typeof part === "object" && part.type === "text")
          .map(part => text(part.text, "assistant text content")).join("\n");
      } else throw new Error("last_assistant_message must contain native text content");
    }
    payload.turn_id = native.turn_id;
  }
  if (event === "PreCompact") payload.custom_instructions = native.customInstructions;
  // Native session/compaction events do not identify foreign source/reason/trigger.
  return payload;
}

interface Translation { result?: ObjectValue; context?: string; message?: string }
function denial(event: HookEvent, reason: string): Translation {
  if (event === "PreToolUse") return { result: { block: true, reason } };
  if (event === "PreCompact") return { result: { cancel: true }, message: reason };
  if (event === "Stop") return { result: { decision: "block", reason } };
  if (event === "PostToolUse" || event === "PostToolUseFailure") return { result: { additionalContext: reason } };
  throw new Error(`${event} cannot represent a blocking hook result`);
}
export function translateOutput(event: HookEvent, native: ObjectValue, output: ProcessResult, originalInput?: ObjectValue): Translation {
  if (output.code === 2) return denial(event, output.stderr.trim() || output.stdout.trim() || `${event} hook blocked`);
  if (output.code !== 0) throw new Error(`Hook exited ${output.code}: ${output.stderr.trim()}`);
  const stdout = output.stdout.trim();
  if (!stdout) return {};
  if (!stdout.startsWith("{") && !stdout.startsWith("[")) {
    if (event === "SessionStart") return { context: stdout };
    throw new Error(`${event} requires JSON output; plain text context is only supported for SessionStart`);
  }
  const value = object(JSON.parse(stdout), "hook output");
  const topFields = ["hookSpecificOutput", "decision", "reason", "systemMessage", "suppressOutput", "continue"];
  if (event === "Stop") topFields.push("additionalContext");
  keys(value, topFields, `${event} output`);
  if (value.continue !== undefined && value.continue !== true) throw new Error("Foreign continue:false or non-boolean continue cannot represent a native session halt");
  if (value.suppressOutput !== undefined && typeof value.suppressOutput !== "boolean") throw new Error("suppressOutput must be boolean");
  if (value.systemMessage !== undefined) text(value.systemMessage, "systemMessage");
  if (value.reason !== undefined) text(value.reason, "reason");
  if (value.additionalContext !== undefined) text(value.additionalContext, "additionalContext");
  const specific = value.hookSpecificOutput === undefined ? {} : object(value.hookSpecificOutput, "hookSpecificOutput");
  if (specific.hookEventName !== undefined && specific.hookEventName !== event) throw new Error("hookEventName does not match invoked event");
  const fields = ["hookEventName"];
  if (["PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionStart", "Stop", "PostCompact"].includes(event)) fields.push("additionalContext");
  if (event === "PreToolUse") fields.push("permissionDecision", "permissionDecisionReason", "updatedInput");
  if (event === "PostToolUse") fields.push("updatedMCPToolOutput");
  keys(specific, fields, `${event} hookSpecificOutput`);
  if (specific.additionalContext !== undefined) text(specific.additionalContext, "additionalContext");
  if (specific.permissionDecisionReason !== undefined) text(specific.permissionDecisionReason, "permissionDecisionReason");
  if (specific.permissionDecision !== undefined && !["allow", "deny"].includes(String(specific.permissionDecision))) throw new Error("Only allow/deny permission decisions are representable; ask is unsupported");
  if (value.decision !== undefined && value.decision !== "block") throw new Error("Only decision:block is supported");
  if (value.reason !== undefined && value.decision !== "block") throw new Error("reason requires decision:block");
  if (event === "Stop" && value.decision !== "block" && (value.additionalContext !== undefined || specific.additionalContext !== undefined)) {
    throw new Error("Stop context requires decision:block; foreign continue is not a native continuation request");
  }
  if (value.decision === "block" || specific.permissionDecision === "deny") {
    const result = denial(event, String(specific.permissionDecisionReason ?? value.reason ?? `${event} hook blocked`));
    if (event === "Stop" && result.result) {
      const context = [value.additionalContext, specific.additionalContext].filter(part => typeof part === "string" && part.trim()).join("\n\n");
      if (context) result.result.additionalContext = context;
    }
    result.message ??= value.systemMessage as string | undefined;
    return result;
  }
  const result: ObjectValue = {};
  let context = specific.additionalContext as string | undefined;
  if (event === "PreToolUse" && specific.updatedInput !== undefined) result.input = updatedInput(String(native.toolName), specific.updatedInput, object(native.input, "tool input"), originalInput);
  if (specific.updatedMCPToolOutput !== undefined) {
    if (!String(native.toolName).startsWith("mcp__")) throw new Error("updatedMCPToolOutput is only supported for MCP tools");
    result.content = [{ type: "text", text: typeof specific.updatedMCPToolOutput === "string" ? specific.updatedMCPToolOutput : JSON.stringify(specific.updatedMCPToolOutput) }];
  }
  if (["PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop"].includes(event)) {
    if (context) result.additionalContext = context;
    context = undefined;
  }
  return { result: Object.keys(result).length ? result : undefined, context, message: value.systemMessage as string | undefined };
}

export function registerHooks(pi: ExtensionAPI, descriptor: unknown): void {
  const registrations = parseDescriptor(descriptor);
  const active = new Set<AbortController>();
  let sessionContext: string[] = [];
  // Install cleanup before package handlers: shutdown must kill earlier commands first.
  pi.on("session_shutdown", () => { for (const controller of active) controller.abort(); });
  pi.on("before_agent_start", () => {
    const context = sessionContext.join("\n\n");
    sessionContext = [];
    if (context) return { message: { customType: "apm-hooks", content: context, display: false } };
  });
  for (const [index, registration] of registrations.entries()) {
    const { event, command, matcher } = registration;
    // Each shell command has its own native handler and native timeout budget.
    const handler = async (native: ObjectValue, ctx: ExtensionContext): Promise<ObjectValue | undefined> => {
      if (matcher && (!matcher.test(String(native.toolName)) && !matcher.test(TOOL_NAMES[String(native.toolName)] ?? String(native.toolName)))) return;
      if (event === "PostToolUse" && native.isError) return;
      if (event === "PostToolUseFailure" && !native.isError) return;
      const controller = new AbortController();
      active.add(controller);
      const signal = native.signal instanceof AbortSignal ? AbortSignal.any([native.signal, controller.signal]) : controller.signal;
      try {
        if (command.statusMessage !== undefined) ctx.ui.setStatus(`apm-hook-${index}`, command.statusMessage);
        const payload = await payloadFor(event, native, ctx);
        const output = await executeCommand(command, payload, ctx.cwd, timeout(event, command), signal);
        const translated = translateOutput(event, native, output, payload.tool_input as ObjectValue | undefined);
        if (translated.message) ctx.ui.notify(translated.message, "warning");
        if (translated.context) sessionContext.push(translated.context);
        return translated.result;
      } catch (error) {
        const message = `APM hook ${command.apm.owner} (${event}): ${error instanceof Error ? error.message : String(error)}`;
        // Native compact/stop exceptions fail open. Return their actual gates.
        if (event === "PreCompact" || event === "Stop") {
          ctx.ui.notify(message, "error");
          return denial(event, message).result;
        }
        throw new Error(message);
      } finally {
        active.delete(controller);
        if (command.statusMessage !== undefined) ctx.ui.setStatus(`apm-hook-${index}`, undefined);
      }
    };
    // The runtime descriptor determines the overload; both event and return shape are validated above.
    const register = pi.on as unknown as (name: string, callback: typeof handler) => void;
    register(EVENTS[event], handler);
  }
}

export default async function apmHooks(pi: ExtensionAPI): Promise<void> {
  const descriptor = resolve(dirname(fileURLToPath(import.meta.url)), "../../hooks.json");
  registerHooks(pi, JSON.parse(await readFile(descriptor, "utf8")));
}
