import { randomUUID } from 'node:crypto';
import type { BrowserProvider } from '../providers/BrowserProvider.js';
import { applySecurityPolicyToContext } from '../security/applySecurityPolicy.js';
import { redactSecrets } from '../security/redactSecrets.js';
import { BlockedRequestLog, type SecurityPolicy } from '../security/securityPolicy.js';
import type { ProviderName } from '../types/providerConfig.js';
import type { SessionRecord, SessionSummary, StartSessionInput } from '../types/session.js';

export class SessionRegistryError extends Error {}

export interface SessionRegistryOptions {
  defaultProvider: ProviderName;
  securityPolicy: SecurityPolicy;
  /**
   * Providers `start_session` may launch. NOT permissive by default -- a session request for a
   * provider outside this set is refused before the provider SDK is ever invoked (so before any
   * third-party network call). This is server config, not a tool argument: nothing in the tool
   * layer can widen it.
   */
  allowedProviders: ReadonlySet<ProviderName>;
  /**
   * Whether `closeAllSessions` may be called with no `ownerId` (closing every session on the
   * server, including other callers'). Off by default.
   */
  allowUnscopedCloseAll: boolean;
}

export class SessionRegistry {
  private readonly sessions = new Map<number, SessionRecord>();
  private nextSessionId = 1;

  constructor(
    private readonly providers: Map<ProviderName, BrowserProvider>,
    private readonly options: SessionRegistryOptions,
  ) {}

  async startSession(input: StartSessionInput): Promise<SessionSummary> {
    const providerName = input.provider ?? this.options.defaultProvider;

    // Checked before touching `this.providers` at all, so a disallowed provider's SDK client is
    // never constructed or invoked -- this must fail before any third-party network call, not
    // merely before the session is handed back.
    if (!this.options.allowedProviders.has(providerName)) {
      const allowed = [...this.options.allowedProviders];

      throw new SessionRegistryError(
        `Provider "${providerName}" is not permitted by this server's configuration. ` +
          `Requested: "${providerName}". Permitted: ${allowed.length > 0 ? allowed.join(', ') : '(none)'}. ` +
          'This is a server-level allowlist (security.allowedProviders); it cannot be widened by a tool call.',
      );
    }

    const provider = this.providers.get(providerName);

    if (provider === undefined) {
      throw new SessionRegistryError(`Unsupported provider "${providerName}".`);
    }

    const startedSession = await provider.startSession({
      sessionName: input.sessionName ?? null,
    });
    const now = new Date().toISOString();
    const id = this.nextSessionId;

    this.nextSessionId += 1;

    // Every session gets an owner, whether the caller asked for one or not. When the caller
    // supplies `ownerId`, sessions started under the same id can be managed as a group. When
    // they don't, the server assigns a random, unguessable one -- this is what makes ownership a
    // real control rather than a courtesy: an agent that never claimed an id (or never saw one
    // it didn't start) has no way to guess another session's owner and close it.
    const ownerId = input.ownerId ?? `auto-${randomUUID()}`;

    // Install the origin restriction on the context before the session is handed out. Every
    // provider returns a BrowserContext, so this one place covers all four of them, and it runs
    // before any tool can drive the session.
    const blockedRequests = new BlockedRequestLog();

    try {
      await applySecurityPolicyToContext(startedSession.context, this.options.securityPolicy, {
        sessionLabel: `session=${id}`,
        log: blockedRequests,
      });
    } catch (error) {
      // Fail closed: an unguarded session must never be returned to a caller.
      await provider.closeSession(startedSession).catch(() => undefined);

      const reason = error instanceof Error ? error.message : 'Unknown error';

      throw new SessionRegistryError(
        `Refusing to start session ${id}: could not install the security policy (${reason}).`,
      );
    }

    const record: SessionRecord = {
      ...startedSession,
      id,
      provider: providerName,
      sessionName: input.sessionName ?? null,
      createdAt: now,
      lastUsedAt: now,
      blockedRequests,
      ownerId,
    };

    this.sessions.set(id, record);

    // ownerId is revealed here, and only here -- see the field comment on SessionRecord.
    return this.toSummary(record, { includeOwnerId: true });
  }

  getSessions(): SessionSummary[] {
    return [...this.sessions.values()].map((session) => this.toSummary(session));
  }

  getSessionOrThrow(id: number): SessionRecord {
    const session = this.sessions.get(id);

    if (session === undefined) {
      throw new SessionRegistryError(
        `Unknown session ${id}. Start a session first or call get_sessions.`,
      );
    }

    session.lastUsedAt = new Date().toISOString();

    return session;
  }

  /**
   * `callerOwnerId` must match the session's `ownerId` exactly -- including when both are
   * `undefined`, which never happens, since every session is assigned an owner at start (see
   * `startSession`). Omitting `ownerId` is therefore never treated as "any owner is fine"; it is
   * simply never going to equal a real owner id, so it is always refused. That is deliberate:
   * this check must fail closed, not open, when the caller doesn't supply proof of ownership.
   */
  async closeSession(id: number, callerOwnerId?: string): Promise<void> {
    const session = this.getSessionOrThrow(id);

    if (session.ownerId !== callerOwnerId) {
      throw new SessionRegistryError(
        `Session ${id} is owned by a different caller; refusing to close it. ` +
          'Pass the ownerId that was returned when this session was started.',
      );
    }

    await this.forceCloseSession(id);
  }

  /**
   * With `callerOwnerId`, closes only that caller's own sessions -- always allowed, and the
   * self-service cleanup path a well-behaved subagent should use. Without it, this would close
   * every session on the server, including other callers'; that is gated behind
   * `security.allowUnscopedCloseAll` (off by default) rather than available unconditionally, so
   * one subagent calling this tool without arguments cannot take down everyone else's browsers.
   */
  async closeAllSessions(callerOwnerId?: string): Promise<number> {
    if (callerOwnerId !== undefined) {
      const ids = [...this.sessions.values()]
        .filter((session) => session.ownerId === callerOwnerId)
        .map((session) => session.id);

      await Promise.all(ids.map(async (id) => this.forceCloseSession(id)));

      return ids.length;
    }

    if (!this.options.allowUnscopedCloseAll) {
      throw new SessionRegistryError(
        'close_all_sessions with no ownerId would close every session on this server, including ' +
          'sessions started by other callers, and is disabled by default. Pass your own ownerId ' +
          'to close only your own sessions, or ask the operator to set security.allowUnscopedCloseAll ' +
          'to enable the unscoped form.',
      );
    }

    const ids = [...this.sessions.keys()];

    await Promise.all(ids.map(async (id) => this.forceCloseSession(id)));

    return ids.length;
  }

  /** Actually tears a session down. No ownership check -- callers above are responsible for it. */
  private async forceCloseSession(id: number): Promise<void> {
    const session = this.sessions.get(id);

    if (session === undefined) {
      return;
    }

    const provider = this.providers.get(session.provider);

    if (provider === undefined) {
      throw new SessionRegistryError(`Missing provider "${session.provider}" for session ${id}.`);
    }

    await provider.closeSession(session);
    this.sessions.delete(id);
  }

  private toSummary(
    session: SessionRecord,
    options: { includeOwnerId?: boolean } = {},
  ): SessionSummary {
    return {
      id: session.id,
      provider: session.provider,
      providerSessionId: session.providerSessionId,
      sessionName: session.sessionName,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      metadata: session.metadata,
      // Redacted at this single boundary, so both the start_session response and the
      // get_sessions listing are covered without redacting (and risking corrupting) the live
      // config the provider actually uses to drive the browser.
      resolvedProviderConfig: redactSecrets(session.resolvedProviderConfig),
      ...(options.includeOwnerId ? { ownerId: session.ownerId } : {}),
    };
  }
}
