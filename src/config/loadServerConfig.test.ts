import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadServerConfig } from './loadServerConfig.js';

const ORIGINAL_ENV = { ...process.env };

describe('loadServerConfig', () => {
  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    vi.restoreAllMocks();
  });

  it('prefers explicit MCP config over env defaults', () => {
    process.env.BROWSERBASE_PROJECT_ID = 'env-project';
    process.env.BROWSER_MCP_CONFIG = JSON.stringify({
      defaultProvider: 'browserbase',
      providers: {
        browserbase: {
          projectId: 'config-project',
          keepAlive: true,
        },
      },
    });

    const config = loadServerConfig();

    expect(config.defaultProvider).toBe('browserbase');
    expect(config.providers.browserbase.projectId).toBe('config-project');
    expect(config.providers.browserbase.keepAlive).toBe(true);
  });

  it('falls back to env defaults when config override is absent', () => {
    delete process.env.BROWSER_MCP_CONFIG;
    process.env.BROWSERBASE_PROJECT_ID = 'env-project';
    process.env.BROWSERBASE_KEEP_ALIVE = 'true';

    const config = loadServerConfig();

    expect(config.defaultProvider).toBe('playwright');
    expect(config.providers.browserbase.projectId).toBe('env-project');
    expect(config.providers.browserbase.keepAlive).toBe(true);
  });

  it('throws a clear error for invalid JSON config', () => {
    process.env.BROWSER_MCP_CONFIG = '{bad json}';

    expect(() => loadServerConfig()).toThrow(/Invalid browser MCP config/);
  });

  it('defaults the security block to empty (permissive), which is the documented default', () => {
    delete process.env.BROWSER_MCP_CONFIG;
    delete process.env.BROWSER_MCP_ALLOWED_ORIGINS;
    delete process.env.BROWSER_MCP_ALLOWED_UPLOAD_DIRS;
    delete process.env.BROWSER_MCP_ALLOWED_PROVIDERS;
    delete process.env.BROWSER_MCP_ALLOW_UNSCOPED_CLOSE_ALL;

    expect(loadServerConfig().security).toEqual({
      allowedOrigins: [],
      blockedOrigins: [],
      blockedSchemes: [],
      allowedUploadDirectories: [],
      // NOT permissive, unlike the origin/upload fields above -- see serverConfig.ts.
      allowedProviders: ['playwright'],
      allowUnscopedCloseAll: false,
    });
  });

  it('defaults allowedProviders to playwright-only, not permissive', () => {
    delete process.env.BROWSER_MCP_CONFIG;
    delete process.env.BROWSER_MCP_ALLOWED_PROVIDERS;

    expect(loadServerConfig().security.allowedProviders).toEqual(['playwright']);
  });

  it('reads allowedProviders from config and from the ;-separated env var', () => {
    process.env.BROWSER_MCP_CONFIG = JSON.stringify({
      security: { allowedProviders: ['playwright', 'browserbase'] },
    });

    expect(loadServerConfig().security.allowedProviders).toEqual(['playwright', 'browserbase']);

    delete process.env.BROWSER_MCP_CONFIG;
    process.env.BROWSER_MCP_ALLOWED_PROVIDERS = ' playwright ; anchor ;';

    expect(loadServerConfig().security.allowedProviders).toEqual(['playwright', 'anchor']);
  });

  it('rejects an unknown provider name in the BROWSER_MCP_ALLOWED_PROVIDERS env var', () => {
    delete process.env.BROWSER_MCP_CONFIG;
    process.env.BROWSER_MCP_ALLOWED_PROVIDERS = 'playwright;not-a-real-provider';

    expect(() => loadServerConfig()).toThrow(/Invalid entry "not-a-real-provider"/);
  });

  it('rejects an unknown provider name in security.allowedProviders (JSON config)', () => {
    process.env.BROWSER_MCP_CONFIG = JSON.stringify({
      security: { allowedProviders: ['not-a-real-provider'] },
    });

    expect(() => loadServerConfig()).toThrow(/Invalid browser MCP config/);
  });

  it('defaults allowUnscopedCloseAll to false and respects env / config overrides', () => {
    delete process.env.BROWSER_MCP_CONFIG;
    delete process.env.BROWSER_MCP_ALLOW_UNSCOPED_CLOSE_ALL;

    expect(loadServerConfig().security.allowUnscopedCloseAll).toBe(false);

    process.env.BROWSER_MCP_ALLOW_UNSCOPED_CLOSE_ALL = 'true';
    expect(loadServerConfig().security.allowUnscopedCloseAll).toBe(true);

    delete process.env.BROWSER_MCP_ALLOW_UNSCOPED_CLOSE_ALL;
    process.env.BROWSER_MCP_CONFIG = JSON.stringify({
      security: { allowUnscopedCloseAll: true },
    });
    expect(loadServerConfig().security.allowUnscopedCloseAll).toBe(true);
  });

  it('reads the security block from config, and from ;-separated env vars', () => {
    process.env.BROWSER_MCP_CONFIG = JSON.stringify({
      security: { allowedOrigins: ['app.example.com', '127.0.0.1:8080'] },
    });

    expect(loadServerConfig().security.allowedOrigins).toEqual([
      'app.example.com',
      '127.0.0.1:8080',
    ]);

    delete process.env.BROWSER_MCP_CONFIG;
    process.env.BROWSER_MCP_ALLOWED_ORIGINS = ' app.example.com ; *.api.example.com ;';
    process.env.BROWSER_MCP_BLOCKED_ORIGINS = 'admin.example.com';
    process.env.BROWSER_MCP_ALLOWED_UPLOAD_DIRS = '/srv/uploads';

    const fromEnv = loadServerConfig().security;

    expect(fromEnv.allowedOrigins).toEqual(['app.example.com', '*.api.example.com']);
    expect(fromEnv.blockedOrigins).toEqual(['admin.example.com']);
    expect(fromEnv.allowedUploadDirectories).toEqual(['/srv/uploads']);
  });

  it('rejects an unknown key inside the security block', () => {
    process.env.BROWSER_MCP_CONFIG = JSON.stringify({
      security: { allowedOrigin: ['typo.example.com'] },
    });

    expect(() => loadServerConfig()).toThrow(/Invalid browser MCP config/);
  });

  it('defaults useCloakBrowser to false and respects env / config overrides', () => {
    delete process.env.BROWSER_MCP_CONFIG;
    delete process.env.PLAYWRIGHT_USE_CLOAKBROWSER;

    expect(loadServerConfig().providers.playwright.useCloakBrowser).toBe(false);

    process.env.PLAYWRIGHT_USE_CLOAKBROWSER = 'true';
    expect(loadServerConfig().providers.playwright.useCloakBrowser).toBe(true);

    delete process.env.PLAYWRIGHT_USE_CLOAKBROWSER;
    process.env.BROWSER_MCP_CONFIG = JSON.stringify({
      providers: { playwright: { useCloakBrowser: true } },
    });
    expect(loadServerConfig().providers.playwright.useCloakBrowser).toBe(true);
  });
});
