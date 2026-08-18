import type { Browser, BrowserContext, Page } from 'playwright-core';
import { describe, expect, it, vi } from 'vitest';
import { BrowserProvider, type ProviderStartSessionParams } from '../providers/BrowserProvider.js';
import { SecurityPolicy } from '../security/securityPolicy.js';
import { SessionRegistry } from './SessionRegistry.js';
import type { StartedBrowserSession } from '../types/session.js';

const testPolicy = (): SecurityPolicy =>
  new SecurityPolicy({
    allowedOrigins: [],
    blockedOrigins: [],
    blockedSchemes: [],
    allowedUploadDirectories: [],
  });

/** Minimal BrowserContext stand-in: just the surface applySecurityPolicyToContext touches. */
const createFakeContext = (): BrowserContext =>
  ({
    close: vi.fn(),
    route: vi.fn(async () => undefined),
    routeWebSocket: vi.fn(async () => undefined),
    addInitScript: vi.fn(async () => undefined),
    on: vi.fn(),
    pages: vi.fn(() => []),
  }) as unknown as BrowserContext;

const createStartedSession = (
  context: BrowserContext = createFakeContext(),
): StartedBrowserSession => ({
  browser: { close: vi.fn() } as unknown as Browser,
  context,
  page: { close: vi.fn() } as unknown as Page,
  providerSessionId: 'remote-1',
  metadata: { test: true },
  resolvedProviderConfig: {
    launchOptions: {},
    contextOptions: {},
    storageStatePath: null,
    executablePath: null,
    channel: null,
    useCloakBrowser: false,
  },
});

class TestProvider extends BrowserProvider {
  constructor() {
    super('playwright');
  }

  readonly startSessionMock = vi.fn(
    async (_params: ProviderStartSessionParams) => createStartedSession(),
  );
  readonly closeSessionMock = vi.fn(async (_session: StartedBrowserSession) => undefined);

  async startSession(params: ProviderStartSessionParams): Promise<StartedBrowserSession> {
    return this.startSessionMock(params);
  }

  async closeSession(session: StartedBrowserSession): Promise<void> {
    await this.closeSessionMock(session);
  }
}

describe('SessionRegistry', () => {
  it('allocates sequential numeric IDs', async () => {
    const provider = new TestProvider();
    const registry = new SessionRegistry(new Map([['playwright', provider]]), 'playwright', testPolicy());

    const first = await registry.startSession({});
    const second = await registry.startSession({});

    expect(first.id).toBe(1);
    expect(second.id).toBe(2);
  });

  it('closes a session and removes it from the registry', async () => {
    const provider = new TestProvider();
    const registry = new SessionRegistry(new Map([['playwright', provider]]), 'playwright', testPolicy());
    const session = await registry.startSession({});

    await registry.closeSession(session.id);

    expect(provider.closeSessionMock).toHaveBeenCalledTimes(1);
    expect(registry.getSessions()).toHaveLength(0);
  });

  it('installs the security policy on the context before handing the session out', async () => {
    const context = createFakeContext();
    const provider = new TestProvider();
    provider.startSessionMock.mockImplementationOnce(async () => createStartedSession(context));
    const registry = new SessionRegistry(
      new Map([['playwright', provider]]),
      'playwright',
      testPolicy(),
    );

    await registry.startSession({});

    // Registered on the context (not the page), so pages opened later inherit it.
    expect(context.route).toHaveBeenCalledTimes(1);
    expect(context.routeWebSocket).toHaveBeenCalledTimes(1);
    expect(context.on).toHaveBeenCalledWith('page', expect.any(Function));
  });

  it('fails closed when the security policy cannot be installed', async () => {
    const context = createFakeContext();
    (context.route as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('route refused'));
    const provider = new TestProvider();
    provider.startSessionMock.mockImplementationOnce(async () => createStartedSession(context));
    const registry = new SessionRegistry(
      new Map([['playwright', provider]]),
      'playwright',
      testPolicy(),
    );

    await expect(registry.startSession({})).rejects.toThrow(/could not install the security policy/);

    // The half-built, unguarded session must not survive or be reachable.
    expect(provider.closeSessionMock).toHaveBeenCalledTimes(1);
    expect(registry.getSessions()).toHaveLength(0);
  });

  it('closes all sessions idempotently', async () => {
    const provider = new TestProvider();
    const registry = new SessionRegistry(new Map([['playwright', provider]]), 'playwright', testPolicy());
    await registry.startSession({});
    await registry.startSession({});

    const closedCount = await registry.closeAllSessions();
    const closedAgain = await registry.closeAllSessions();

    expect(closedCount).toBe(2);
    expect(closedAgain).toBe(0);
  });
});
