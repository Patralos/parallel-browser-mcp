import type { Browser, BrowserContext, Page } from 'playwright-core';
import { describe, expect, it, vi } from 'vitest';
import { BrowserProvider, type ProviderStartSessionParams } from '../providers/BrowserProvider.js';
import { SecurityPolicy } from '../security/securityPolicy.js';
import { SessionRegistry, type SessionRegistryOptions } from './SessionRegistry.js';
import type { StartedBrowserSession } from '../types/session.js';

const testPolicy = (): SecurityPolicy =>
  new SecurityPolicy({
    allowedOrigins: [],
    blockedOrigins: [],
    blockedSchemes: [],
    allowedUploadDirectories: [],
  });

/** Matches loadServerConfig's actual default: playwright only, unscoped close-all disabled. */
const testOptions = (overrides: Partial<SessionRegistryOptions> = {}): SessionRegistryOptions => ({
  defaultProvider: 'playwright',
  securityPolicy: testPolicy(),
  allowedProviders: new Set(['playwright']),
  allowUnscopedCloseAll: false,
  ...overrides,
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
    const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());

    const first = await registry.startSession({});
    const second = await registry.startSession({});

    expect(first.id).toBe(1);
    expect(second.id).toBe(2);
  });

  it('installs the security policy on the context before handing the session out', async () => {
    const context = createFakeContext();
    const provider = new TestProvider();
    provider.startSessionMock.mockImplementationOnce(async () => createStartedSession(context));
    const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());

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
    const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());

    await expect(registry.startSession({})).rejects.toThrow(/could not install the security policy/);

    // The half-built, unguarded session must not survive or be reachable.
    expect(provider.closeSessionMock).toHaveBeenCalledTimes(1);
    expect(registry.getSessions()).toHaveLength(0);
  });

  describe('provider allowlist', () => {
    it('refuses a provider that is not on the allowlist, naming what was requested and permitted', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(
        new Map([['playwright', provider]]),
        testOptions({ allowedProviders: new Set(['playwright']) }),
      );

      await expect(registry.startSession({ provider: 'browserbase' })).rejects.toThrow(
        /Provider "browserbase" is not permitted.*Permitted: playwright/s,
      );

      // Refused before the provider SDK is ever invoked -- no third-party call was attempted.
      expect(provider.startSessionMock).not.toHaveBeenCalled();
    });

    it('allows a provider that is on the allowlist', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(
        new Map([['playwright', provider]]),
        testOptions({ allowedProviders: new Set(['playwright', 'browserbase']) }),
      );

      await expect(registry.startSession({ provider: 'playwright' })).resolves.toMatchObject({
        provider: 'playwright',
      });
    });

    it('applies the allowlist to the default provider too, not just an explicit one', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(
        new Map([['playwright', provider]]),
        testOptions({ defaultProvider: 'playwright', allowedProviders: new Set() }),
      );

      await expect(registry.startSession({})).rejects.toThrow(/not permitted/);
    });
  });

  describe('resolvedProviderConfig redaction', () => {
    it('redacts secrets in the config returned by startSession and getSessions', async () => {
      const provider = new TestProvider();
      provider.startSessionMock.mockImplementationOnce(async () => ({
        ...createStartedSession(),
        resolvedProviderConfig: {
          launchOptions: {
            proxy: { server: 'http://127.0.0.1:9081', username: 'burpuser', password: 'S3cretProxyPw' },
          },
          contextOptions: {},
          storageStatePath: null,
          executablePath: null,
          channel: null,
          useCloakBrowser: false,
        },
      }));
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());

      const started = await registry.startSession({});
      const config = started.resolvedProviderConfig as unknown as {
        launchOptions: { proxy: { server: string; username: string; password: string } };
      };

      expect(config.launchOptions.proxy.password).toBe('***redacted***');
      expect(config.launchOptions.proxy.username).toBe('burpuser');

      const listed = registry.getSessions()[0]?.resolvedProviderConfig as unknown as typeof config;

      expect(listed.launchOptions.proxy.password).toBe('***redacted***');
    });
  });

  describe('ownership', () => {
    it('returns an ownerId from startSession even when the caller did not supply one', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());

      const session = await registry.startSession({});

      expect(session.ownerId).toBeDefined();
      expect(typeof session.ownerId).toBe('string');
    });

    it('uses the caller-supplied ownerId when given', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());

      const session = await registry.startSession({ ownerId: 'agent-a' });

      expect(session.ownerId).toBe('agent-a');
    });

    it('does not include ownerId in a getSessions listing', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());

      await registry.startSession({ ownerId: 'agent-a' });

      expect(registry.getSessions()[0]?.ownerId).toBeUndefined();
    });

    it('closes a session for its own owner', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());
      const session = await registry.startSession({ ownerId: 'agent-a' });

      await registry.closeSession(session.id, 'agent-a');

      expect(provider.closeSessionMock).toHaveBeenCalledTimes(1);
      expect(registry.getSessions()).toHaveLength(0);
    });

    it('refuses to close a session owned by a different caller', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());
      const session = await registry.startSession({ ownerId: 'agent-a' });

      await expect(registry.closeSession(session.id, 'agent-b')).rejects.toThrow(
        /owned by a different caller/,
      );
      // Also refused with no ownerId at all -- omitting it is not "any owner is fine".
      await expect(registry.closeSession(session.id)).rejects.toThrow(/owned by a different caller/);

      expect(provider.closeSessionMock).not.toHaveBeenCalled();
      expect(registry.getSessions()).toHaveLength(1);
    });

    it('refuses to close a session started with a server-generated owner unless that owner is supplied', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());
      const session = await registry.startSession({}); // no ownerId supplied

      await expect(registry.closeSession(session.id)).rejects.toThrow(/owned by a different caller/);
      await expect(registry.closeSession(session.id, 'guessed-owner')).rejects.toThrow(
        /owned by a different caller/,
      );

      await expect(registry.closeSession(session.id, session.ownerId)).resolves.toBeUndefined();
    });

    it('closeAllSessions with an ownerId closes only that owner\'s sessions, leaving others running', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());
      await registry.startSession({ ownerId: 'agent-a' });
      await registry.startSession({ ownerId: 'agent-a' });
      const bSession = await registry.startSession({ ownerId: 'agent-b' });

      const closedCount = await registry.closeAllSessions('agent-a');

      expect(closedCount).toBe(2);
      expect(registry.getSessions()).toHaveLength(1);
      // The survivor's ID belongs to agent-b -- agent-a's call did not touch it.
      await expect(registry.closeSession(bSession.id, 'agent-b')).resolves.toBeUndefined();
    });

    it('refuses an unscoped closeAllSessions (no ownerId) by default', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());
      await registry.startSession({ ownerId: 'agent-a' });
      await registry.startSession({ ownerId: 'agent-b' });

      await expect(registry.closeAllSessions()).rejects.toThrow(/allowUnscopedCloseAll/);
      expect(registry.getSessions()).toHaveLength(2);
    });

    it('allows an unscoped closeAllSessions when the operator has enabled it', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(
        new Map([['playwright', provider]]),
        testOptions({ allowUnscopedCloseAll: true }),
      );
      await registry.startSession({ ownerId: 'agent-a' });
      await registry.startSession({ ownerId: 'agent-b' });

      const closedCount = await registry.closeAllSessions();

      expect(closedCount).toBe(2);
      expect(registry.getSessions()).toHaveLength(0);
    });

    it('closeAllSessions with an ownerId that owns nothing closes nothing, without error', async () => {
      const provider = new TestProvider();
      const registry = new SessionRegistry(new Map([['playwright', provider]]), testOptions());
      await registry.startSession({ ownerId: 'agent-a' });

      const closedCount = await registry.closeAllSessions('agent-nobody');

      expect(closedCount).toBe(0);
      expect(registry.getSessions()).toHaveLength(1);
    });
  });
});
