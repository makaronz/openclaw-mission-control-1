/**
 * Auto transport — tries HTTP first, falls back to CLI.
 *
 * Probes /tools/invoke (not just "/") so non-200 root responses don't
 * incorrectly demote transport to CLI on VPS/reverse-proxy setups.
 *
 * Circuit breaker: when the gateway returns scope/auth errors (403, 401,
 * "missing scope", "forbidden"), HTTP is permanently disabled for the
 * lifetime of this process. These errors indicate a fundamental
 * configuration mismatch that won't resolve on its own.
 */

import type { OpenClawClient, TransportMode } from "../openclaw-client";
import type { RunCliResult } from "../openclaw-cli";
import { CliTransport } from "./cli-transport";
import { HttpTransport } from "./http-transport";

function errorToMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

/** Patterns that indicate a permanent scope/auth mismatch — no point retrying HTTP. */
const PERMANENT_FAILURE_PATTERNS = [
  "missing scope",
  "forbidden",
  "unauthorized",
  "returned 403",
  "returned 401",
];

/** Patterns that indicate a specific tool is unavailable — not worth retrying via HTTP. */
const TOOL_UNAVAILABLE_PATTERNS = [
  "tool not available",
  "returned 404",
];

function isPermanentHttpFailure(reason: string): boolean {
  const lower = reason.toLowerCase();
  return PERMANENT_FAILURE_PATTERNS.some((p) => lower.includes(p));
}

function isPermanentHttpStatus(status: number): boolean {
  return status === 401 || status === 403;
}

export class AutoTransport implements OpenClawClient {
  private cli = new CliTransport();
  private http = new HttpTransport();
  private preferHttp = false;
  private lastProbe = 0;
  private probing: Promise<void> | null = null;
  // Re-probe quickly after a fallback (3s) so HTTP is rediscovered fast.
  // Use a longer interval (60s) when the transport is stable.
  private readonly probeIntervalStableMs = 60_000;
  private readonly probeIntervalRecoveryMs = 3_000;
  private readonly probeTimeoutMs = 2_000;
  private inRecovery = false;

  /** Circuit breaker: once true, HTTP is permanently disabled. */
  private permanentCliMode = false;
  private consecutiveHttpFailures = 0;

  /**
   * Cache of tools that returned 404 ("Tool not available") via HTTP.
   * These skip HTTP entirely and go straight to CLI, avoiding wasted
   * round-trips and CLI queue pressure from fallback pile-ups.
   * Entries expire after 60s so new gateway deploys are picked up.
   */
  private unavailableTools = new Map<string, number>();
  private readonly toolUnavailableTtlMs = 60_000;

  /** CLI concurrency limiter — prevents subprocess storms during gateway restarts. */
  private activeCli = 0;
  private readonly maxCli = 6;

  /** Check if a tool is known to be unavailable via HTTP (cached 404). */
  private isToolUnavailable(tool: string): boolean {
    const ts = this.unavailableTools.get(tool);
    if (!ts) return false;
    if (Date.now() - ts > this.toolUnavailableTtlMs) {
      this.unavailableTools.delete(tool);
      return false;
    }
    return true;
  }

  /** Mark a tool as unavailable via HTTP after a 404. */
  private markToolUnavailable(reason: string): void {
    const lower = reason.toLowerCase();
    if (TOOL_UNAVAILABLE_PATTERNS.some((p) => lower.includes(p))) {
      // Extract tool name from error like "Gateway /tools/invoke exec returned 404"
      const match = reason.match(/\/tools\/invoke\s+(\S+)/);
      if (match) {
        this.unavailableTools.set(match[1], Date.now());
      }
    }
  }

  /** Extract the tool name from CLI args (e.g., ["skills", "list"] → "exec"). */
  private toolForArgs(_args: string[]): string {
    // All CLI commands go through the "exec" tool on the HTTP transport
    return "exec";
  }

  getTransport(): TransportMode {
    return "auto";
  }

  async resolveTransport(): Promise<TransportMode> {
    if (this.permanentCliMode) return "cli";
    await this.probe();
    return this.preferHttp ? "http" : "cli";
  }

  private shouldUseHttpForStatus(status: number): boolean {
    // 404 means "/tools/invoke" is missing; 401/403 means auth rejects requests.
    // In both cases, command invocation over HTTP won't work.
    if (status === 404 || status === 401 || status === 403) return false;
    // Any non-5xx implies the Gateway is reachable and potentially usable.
    return status < 500;
  }

  private markHttpFailed(reason: string): void {
    // Track tool-specific unavailability (e.g., "exec" returning 404).
    // This prevents repeated HTTP attempts for tools the gateway doesn't support.
    this.markToolUnavailable(reason);

    const wasHttp = this.preferHttp;
    this.preferHttp = false;
    this.consecutiveHttpFailures++;

    // Scope/auth errors are permanent — stop probing.
    if (isPermanentHttpFailure(reason)) {
      this.permanentCliMode = true;
      this.inRecovery = false;
      console.warn(
        `[AutoTransport] Permanent CLI mode: ${reason}. HTTP transport disabled for this process.`,
      );
      return;
    }

    this.inRecovery = true;
    // Force a quick re-probe on the next request.
    this.lastProbe = Date.now() - this.probeIntervalRecoveryMs;
    if (wasHttp) {
      console.warn(`[AutoTransport] HTTP failed, falling back to CLI: ${reason}`);
    }
  }

  /** Probe Gateway availability and cache the result. */
  private async probe(): Promise<void> {
    // Circuit breaker: don't probe if permanently in CLI mode.
    if (this.permanentCliMode) return;

    const interval = this.inRecovery
      ? this.probeIntervalRecoveryMs
      : this.probeIntervalStableMs;
    if (Date.now() - this.lastProbe < interval) return;
    // Deduplicate concurrent probes.
    if (this.probing) return this.probing;
    this.probing = (async () => {
      const hadHttp = this.preferHttp;
      try {
        // Probe with a real POST to catch scope errors (HEAD bypasses auth).
        const res = await this.http.gatewayFetch("/tools/invoke", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tool: "sessions_list", input: {} }),
          signal: AbortSignal.timeout(this.probeTimeoutMs),
        });

        // Check for permanent auth/scope failures on probe.
        if (isPermanentHttpStatus(res.status)) {
          const body = await res.text().catch(() => "");
          this.markHttpFailed(
            `HTTP ${res.status} during probe${body ? `: ${body.slice(0, 200)}` : ""}`,
          );
          return;
        }

        const allowHttp = this.shouldUseHttpForStatus(res.status);
        this.preferHttp = allowHttp;
        this.inRecovery = !allowHttp;

        if (allowHttp) {
          this.consecutiveHttpFailures = 0;
        }

        if (allowHttp && !hadHttp) {
          console.info("[AutoTransport] HTTP transport restored.");
        }
        if (!allowHttp && hadHttp) {
          console.warn(
            `[AutoTransport] Probe switched to CLI fallback (HTTP ${res.status}).`,
          );
        }
      } catch (err) {
        this.markHttpFailed(errorToMessage(err));
      } finally {
        this.lastProbe = Date.now();
        this.probing = null;
      }
    })();
    return this.probing;
  }

  private async pick(): Promise<OpenClawClient> {
    if (this.permanentCliMode) return this.cli;
    await this.probe();
    return this.preferHttp ? this.http : this.cli;
  }

  /**
   * Execute with automatic fallback on HTTP failure.
   * Skips HTTP entirely for tools known to be unavailable (cached 404).
   */
  private async withFallback<T>(
    fn: (client: OpenClawClient) => Promise<T>,
    tool?: string,
  ): Promise<T> {
    // If this tool is known to be unavailable via HTTP, skip straight to CLI.
    if (tool && this.isToolUnavailable(tool)) {
      return fn(this.cli);
    }
    const primary = await this.pick();
    try {
      return await fn(primary);
    } catch (err) {
      if (primary === this.http) {
        this.markHttpFailed(errorToMessage(err));
        // CLI fallback — the underlying CLI semaphore handles queuing.
        // Only hard-reject if we're way over capacity to prevent OOM.
        if (this.activeCli >= this.maxCli) {
          throw new Error("Gateway busy — too many pending CLI operations");
        }
        this.activeCli++;
        try {
          return await fn(this.cli);
        } finally {
          this.activeCli--;
        }
      }
      throw err;
    }
  }

  // ── OpenClawClient interface ──────────────────────

  runJson<T>(args: string[], timeout?: number): Promise<T> {
    return this.withFallback((c) => c.runJson<T>(args, timeout), this.toolForArgs(args));
  }

  run(args: string[], timeout?: number, stdin?: string): Promise<string> {
    return this.withFallback((c) => c.run(args, timeout, stdin), this.toolForArgs(args));
  }

  async runCapture(args: string[], timeout?: number): Promise<RunCliResult> {
    const tool = this.toolForArgs(args);

    // If tool is known-unavailable via HTTP, or we're in permanent CLI mode, skip HTTP.
    if (this.permanentCliMode || this.isToolUnavailable(tool)) {
      return this.cli.runCapture(args, timeout);
    }
    await this.probe();
    if (this.preferHttp) {
      const result = await this.http.runCapture(args, timeout);
      if (result.code !== 0 && result.stderr?.includes("/tools/invoke")) {
        this.markHttpFailed(result.stderr || `openclaw ${args.join(" ")} failed over HTTP`);
        return this.cli.runCapture(args, timeout);
      }
      return result;
    }
    // CLI-only path — let the CLI semaphore handle queuing.
    return this.cli.runCapture(args, timeout);
  }

  async gatewayRpc<T>(
    method: string,
    params?: Record<string, unknown>,
    timeout?: number,
  ): Promise<T> {
    // gatewayRpc uses WebSocket/HTTP RPC — CLI fallback does not help here
    // (the CLI would spawn a new gateway process or timeout). Fail fast and let
    // callers serve stale cache instead of spawning an expensive subprocess.
    // Always try HTTP (WebSocket) RPC regardless of /tools/invoke probe state;
    // the WebSocket RPC path is independent of HTTP REST tool invocation.
    try {
      return await this.http.gatewayRpc<T>(method, params, timeout);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new Error(`Gateway RPC unavailable for ${method}: ${reason}`);
    }
  }

  readFile(path: string): Promise<string> {
    return this.withFallback((c) => c.readFile(path));
  }

  writeFile(path: string, content: string): Promise<void> {
    return this.withFallback((c) => c.writeFile(path, content));
  }

  readdir(path: string): Promise<string[]> {
    return this.withFallback((c) => c.readdir(path));
  }

  async gatewayFetch(path: string, init?: RequestInit): Promise<Response> {
    return this.withFallback((c) => c.gatewayFetch(path, init));
  }
}
