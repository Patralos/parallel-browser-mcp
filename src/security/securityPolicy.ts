import { isAbsolute, relative, resolve } from 'node:path';
import { realpathSync } from 'node:fs';

/**
 * Server-level security policy: which origins a browser session may reach, and which local
 * directories `browser_upload_file` may read from.
 *
 * This is configured once, by the operator, at server start (`security` block of
 * BROWSER_MCP_CONFIG / BROWSER_MCP_CONFIG_PATH, or the BROWSER_MCP_* env vars). A calling
 * agent cannot widen it, the same way it cannot change `launchOptions`.
 *
 * `allowedOrigins` / `blockedOrigins` deliberately mirror `@playwright/mcp`'s
 * `--allowed-origins` / `--blocked-origins` vocabulary and matching rules.
 */

/** Thrown when a tool argument violates the policy. Surfaced verbatim to the calling agent. */
export class SecurityPolicyError extends Error {}

/**
 * Schemes that are always refused, regardless of configuration.
 *
 * `file:` is the important one: a `file://` navigation reads local disk and never crosses the
 * HTTP proxy, so an after-the-fact proxy-history audit is blind to it. The rest are Chromium's
 * privileged internal surfaces; `view-source:` is listed because `view-source:file:///...`
 * would otherwise slip a naive `file:`-only check.
 *
 * Operators may add to this list but cannot remove from it.
 */
export const ALWAYS_BLOCKED_SCHEMES = [
  'file:',
  'filesystem:',
  'chrome:',
  'chrome-untrusted:',
  'chrome-extension:',
  'devtools:',
  'view-source:',
] as const;

/** Schemes an `allowedOrigins` entry can meaningfully constrain. */
const NETWORK_SCHEMES = new Set(['http:', 'https:', 'ws:', 'wss:']);

const DEFAULT_PORTS: Record<string, string> = {
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
};

/**
 * `about:blank` is the page every session starts on and the page we reset to after a blocked
 * navigation; `about:srcdoc` is the URL of every `<iframe srcdoc>`. Any other `about:` URL is
 * refused, because Chromium redirects several of them (e.g. `about:version`) into `chrome://`.
 */
const ALLOWED_ABOUT_URLS = new Set(['about:blank', 'about:srcdoc']);

export interface SecurityPolicyInput {
  allowedOrigins: string[];
  blockedOrigins: string[];
  blockedSchemes: string[];
  allowedUploadDirectories: string[];
}

export type PolicyDecision = { allowed: true } | { allowed: false; reason: string };

interface OriginEntry {
  /** Original text, for error messages. */
  readonly raw: string;
  /** e.g. `https:`, or null when the entry did not pin a scheme. */
  readonly scheme: string | null;
  /** Lower-cased host, `*` for any host, or `*.suffix` for subdomains of `suffix`. */
  readonly host: string;
  /** Port number as a string, `*` for any port, or null for "the scheme's default port". */
  readonly port: string | null;
}

/**
 * Parses one `allowedOrigins` / `blockedOrigins` entry.
 *
 * Accepted forms: `host`, `host:port`, `scheme://host`, `scheme://host:port`.
 * `host` may be `*` (any host) or `*.example.com` (any subdomain of `example.com`, but NOT
 * `example.com` itself -- list the apex separately). `port` may be `*` (any port).
 *
 * An entry with no port matches only the default port for the URL's scheme (80 for
 * http/ws, 443 for https/wss), which is how `@playwright/mcp` behaves. A target on a
 * non-standard port must be listed with its port, or with `:*`.
 *
 * Throws on anything it cannot parse, so a typo in the scope allowlist fails at server start
 * rather than silently never matching.
 */
export const parseOriginEntry = (raw: string): OriginEntry => {
  const trimmed = raw.trim().toLowerCase();

  if (trimmed === '') {
    throw new SecurityPolicyError('Origin entry is empty.');
  }

  let scheme: string | null = null;
  let rest = trimmed;
  const schemeSeparator = rest.indexOf('://');

  if (schemeSeparator !== -1) {
    scheme = `${rest.slice(0, schemeSeparator)}:`;
    rest = rest.slice(schemeSeparator + 3);
  }

  // Tolerate (and ignore) a trailing path/query/fragment: origins have no path component,
  // but operators paste full URLs. Everything after the authority is dropped.
  const pathStart = rest.search(/[/?#]/);

  if (pathStart !== -1) {
    rest = rest.slice(0, pathStart);
  }

  if (rest.includes('@')) {
    throw new SecurityPolicyError(
      `Invalid origin entry "${raw}": userinfo ("user@host") is not part of an origin.`,
    );
  }

  let host = rest;
  let port: string | null = null;

  if (rest.startsWith('[')) {
    // IPv6 literal, e.g. [::1] or [::1]:8080. WHATWG URL keeps the brackets in `hostname`.
    const closingBracket = rest.indexOf(']');

    if (closingBracket === -1) {
      throw new SecurityPolicyError(`Invalid origin entry "${raw}": unterminated IPv6 literal.`);
    }

    host = rest.slice(0, closingBracket + 1);
    const remainder = rest.slice(closingBracket + 1);

    if (remainder.startsWith(':')) {
      port = remainder.slice(1);
    } else if (remainder !== '') {
      throw new SecurityPolicyError(`Invalid origin entry "${raw}": unexpected "${remainder}".`);
    }
  } else {
    const lastColon = rest.lastIndexOf(':');

    if (lastColon !== -1) {
      host = rest.slice(0, lastColon);
      port = rest.slice(lastColon + 1);
    }
  }

  if (host === '') {
    throw new SecurityPolicyError(`Invalid origin entry "${raw}": missing host.`);
  }

  if (port !== null && port !== '*' && !/^\d{1,5}$/.test(port)) {
    throw new SecurityPolicyError(`Invalid origin entry "${raw}": port must be a number or "*".`);
  }

  if (host !== '*' && !host.startsWith('*.') && host.includes('*')) {
    throw new SecurityPolicyError(
      `Invalid origin entry "${raw}": "*" is only allowed as the whole host or as a leading "*." label.`,
    );
  }

  return { raw, scheme, host, port };
};

const hostMatches = (entryHost: string, urlHostname: string): boolean => {
  if (entryHost === '*') {
    return true;
  }

  if (entryHost.startsWith('*.')) {
    // Subdomains only; the apex must be listed separately.
    return urlHostname.endsWith(entryHost.slice(1)) && urlHostname.length > entryHost.length - 1;
  }

  return entryHost === urlHostname;
};

const portMatches = (entryPort: string | null, url: URL): boolean => {
  const effectivePort = url.port === '' ? (DEFAULT_PORTS[url.protocol] ?? '') : url.port;

  if (entryPort === '*') {
    return true;
  }

  if (entryPort === null) {
    // No port in the entry means "the default port for this scheme" -- so an explicit,
    // non-default port never matches an entry that did not name it.
    return url.port === '';
  }

  return entryPort === effectivePort;
};

const entryMatches = (entry: OriginEntry, url: URL): boolean => {
  if (entry.scheme !== null && entry.scheme !== url.protocol) {
    return false;
  }

  return hostMatches(entry.host, url.hostname) && portMatches(entry.port, url);
};

/** Resolves an allowed-upload directory once, at startup, so symlinks in it are collapsed. */
const resolveAllowedDirectory = (raw: string): string => {
  const absolute = resolve(raw);

  try {
    return realpathSync(absolute);
  } catch {
    throw new SecurityPolicyError(
      `security.allowedUploadDirectories entry "${raw}" does not exist (resolved to "${absolute}").`,
    );
  }
};

export class SecurityPolicy {
  private readonly allowedOrigins: OriginEntry[];
  private readonly blockedOrigins: OriginEntry[];
  private readonly blockedSchemes: Set<string>;
  private readonly allowedUploadDirectories: string[];

  constructor(input: SecurityPolicyInput) {
    this.allowedOrigins = input.allowedOrigins.map(parseOriginEntry);
    this.blockedOrigins = input.blockedOrigins.map(parseOriginEntry);
    this.blockedSchemes = new Set<string>(ALWAYS_BLOCKED_SCHEMES);

    for (const scheme of input.blockedSchemes) {
      const normalized = scheme.trim().toLowerCase();
      this.blockedSchemes.add(normalized.endsWith(':') ? normalized : `${normalized}:`);
    }

    this.allowedUploadDirectories = input.allowedUploadDirectories.map(resolveAllowedDirectory);
  }

  /** True when an origin allowlist is in force (i.e. the server is NOT permissive by default). */
  get hasOriginAllowlist(): boolean {
    return this.allowedOrigins.length > 0;
  }

  /** True when uploads are confined to a directory allowlist. */
  get hasUploadAllowlist(): boolean {
    return this.allowedUploadDirectories.length > 0;
  }

  /** Operator-facing summary. Contains no secrets; safe to log and to show a calling agent. */
  describe(): {
    allowedOrigins: string[];
    blockedOrigins: string[];
    blockedSchemes: string[];
    allowedUploadDirectories: string[];
  } {
    return {
      allowedOrigins: this.allowedOrigins.map((entry) => entry.raw),
      blockedOrigins: this.blockedOrigins.map((entry) => entry.raw),
      blockedSchemes: [...this.blockedSchemes].sort(),
      allowedUploadDirectories: [...this.allowedUploadDirectories],
    };
  }

  /**
   * The single decision function. Every enforcement layer -- the `context.route` handler, the
   * WebSocket route, the post-navigation guard and the `browser_navigate` argument check --
   * calls this and nothing else, so they cannot drift apart.
   */
  evaluateUrl(rawUrl: string): PolicyDecision {
    let url: URL;

    try {
      url = new URL(rawUrl);
    } catch {
      return { allowed: false, reason: `unparseable URL "${rawUrl}"` };
    }

    if (url.protocol === 'about:') {
      return ALLOWED_ABOUT_URLS.has(url.href)
        ? { allowed: true }
        : { allowed: false, reason: `"${url.href}" is not an allowed about: URL` };
    }

    if (this.blockedSchemes.has(url.protocol)) {
      return {
        allowed: false,
        reason: `scheme "${url.protocol}" is blocked (blockedSchemes)`,
      };
    }

    if (!NETWORK_SCHEMES.has(url.protocol)) {
      // data:, blob: and friends. They carry no origin an allowlist entry could match, so
      // when an allowlist is configured we fail closed rather than wave them through.
      if (this.hasOriginAllowlist) {
        return {
          allowed: false,
          reason: `scheme "${url.protocol}" cannot be matched against allowedOrigins`,
        };
      }

      return { allowed: true };
    }

    const blocked = this.blockedOrigins.find((entry) => entryMatches(entry, url));

    if (blocked !== undefined) {
      return {
        allowed: false,
        reason: `origin "${url.origin}" matches blockedOrigins entry "${blocked.raw}"`,
      };
    }

    if (!this.hasOriginAllowlist) {
      // Documented default: with no allowedOrigins configured the server is permissive.
      return { allowed: true };
    }

    if (this.allowedOrigins.some((entry) => entryMatches(entry, url))) {
      return { allowed: true };
    }

    return {
      allowed: false,
      reason: `origin "${url.origin}" is not in allowedOrigins`,
    };
  }

  /**
   * Outermost, least-trusted layer: the `browser_navigate` argument check.
   *
   * This exists to give the agent a clear, immediate error and to stop `file://` (which is not
   * an HTTP request and therefore never reaches the `context.route` handler). It is NOT the
   * control -- `browser_evaluate` can navigate without ever calling this function.
   */
  assertNavigationAllowed(rawUrl: string): void {
    const decision = this.evaluateUrl(rawUrl);

    if (!decision.allowed) {
      throw new SecurityPolicyError(`Blocked by security policy: ${decision.reason}.`);
    }
  }

  /**
   * Resolves upload paths against the directory allowlist.
   *
   * `resolve()` collapses `..`, then `realpathSync()` collapses symlinks, junctions and 8.3
   * short names -- so the containment check runs on the true target, not on the string the
   * caller supplied. A path check that can be defeated by `../` is decoration.
   */
  resolveUploadPaths(rawPaths: string[]): string[] {
    if (!this.hasUploadAllowlist) {
      // Documented default: with no allowedUploadDirectories configured, uploads are
      // unrestricted (the upstream behaviour).
      return rawPaths;
    }

    return rawPaths.map((rawPath) => this.resolveUploadPath(rawPath));
  }

  private resolveUploadPath(rawPath: string): string {
    const absolute = resolve(rawPath);
    let realPath: string;

    try {
      realPath = realpathSync(absolute);
    } catch {
      throw new SecurityPolicyError(
        `Blocked by security policy: upload path "${rawPath}" does not exist or is not readable.`,
      );
    }

    const contained = this.allowedUploadDirectories.some((directory) => {
      const relativePath = relative(directory, realPath);

      // '' means the path IS the directory; a leading '..' means it escapes it; an absolute
      // result means a different drive/root entirely.
      return (
        relativePath !== '' &&
        !relativePath.startsWith('..') &&
        !isAbsolute(relativePath)
      );
    });

    if (!contained) {
      throw new SecurityPolicyError(
        `Blocked by security policy: upload path "${rawPath}" resolves to "${realPath}", ` +
          `which is outside allowedUploadDirectories (${this.allowedUploadDirectories.join(', ')}).`,
      );
    }

    return realPath;
  }
}

export interface BlockedRequest {
  url: string;
  reason: string;
  layer: 'route' | 'websocket' | 'navigation-guard';
  at: string;
}

/**
 * Per-session record of what the policy stopped.
 *
 * A silently dropped request looks exactly like a broken target, so every block is recorded
 * here, reported back on the tool call that caused it, and logged to stderr.
 */
export class BlockedRequestLog {
  private static readonly MAX_RETAINED = 200;

  private readonly entries: BlockedRequest[] = [];
  private totalCount = 0;

  get total(): number {
    return this.totalCount;
  }

  record(blocked: BlockedRequest): void {
    this.totalCount += 1;
    this.entries.push(blocked);

    if (this.entries.length > BlockedRequestLog.MAX_RETAINED) {
      this.entries.shift();
    }
  }

  /** The blocks recorded since `total` was `since`, newest last, bounded by what we retained. */
  since(since: number): BlockedRequest[] {
    const count = Math.min(this.totalCount - since, this.entries.length);

    return count > 0 ? this.entries.slice(this.entries.length - count) : [];
  }
}
