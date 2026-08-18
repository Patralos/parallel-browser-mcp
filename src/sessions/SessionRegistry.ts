import type { BrowserProvider } from '../providers/BrowserProvider.js';
import { applySecurityPolicyToContext } from '../security/applySecurityPolicy.js';
import { BlockedRequestLog, type SecurityPolicy } from '../security/securityPolicy.js';
import type { ProviderName } from '../types/providerConfig.js';
import type { SessionRecord, SessionSummary, StartSessionInput } from '../types/session.js';

export class SessionRegistryError extends Error {}

export class SessionRegistry {
  private readonly sessions = new Map<number, SessionRecord>();
  private nextSessionId = 1;

  constructor(
    private readonly providers: Map<ProviderName, BrowserProvider>,
    private readonly defaultProvider: ProviderName,
    private readonly securityPolicy: SecurityPolicy,
  ) {}

  async startSession(input: StartSessionInput): Promise<SessionSummary> {
    const providerName = input.provider ?? this.defaultProvider;
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

    // Install the origin restriction on the context before the session is handed out. Every
    // provider returns a BrowserContext, so this one place covers all four of them, and it runs
    // before any tool can drive the session.
    const blockedRequests = new BlockedRequestLog();

    try {
      await applySecurityPolicyToContext(startedSession.context, this.securityPolicy, {
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
    };

    this.sessions.set(id, record);

    return this.toSummary(record);
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

  async closeSession(id: number): Promise<void> {
    const session = this.getSessionOrThrow(id);
    const provider = this.providers.get(session.provider);

    if (provider === undefined) {
      throw new SessionRegistryError(`Missing provider "${session.provider}" for session ${id}.`);
    }

    await provider.closeSession(session);
    this.sessions.delete(id);
  }

  async closeAllSessions(): Promise<number> {
    const ids = [...this.sessions.keys()];

    await Promise.all(ids.map(async (id) => this.closeSession(id)));

    return ids.length;
  }

  private toSummary(session: SessionRecord): SessionSummary {
    return {
      id: session.id,
      provider: session.provider,
      providerSessionId: session.providerSessionId,
      sessionName: session.sessionName,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
      metadata: session.metadata,
      resolvedProviderConfig: session.resolvedProviderConfig,
    };
  }
}
