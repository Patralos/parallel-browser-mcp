import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { providerNames, type ProviderName } from '../types/providerConfig.js';
import {
  type ResolvedServerConfig,
  type ServerConfig,
  serverConfigSchema,
} from './serverConfig.js';

const parseBoolean = (value: string | undefined): boolean | undefined => {
  if (value === undefined) {
    return undefined;
  }

  if (value === 'true') {
    return true;
  }

  if (value === 'false') {
    return false;
  }

  return undefined;
};

/**
 * Splits a `;`-separated env-var list, matching `@playwright/mcp`'s `--allowed-origins` format.
 * Returns undefined (not []) when unset, so an explicit empty string can still mean "no entries".
 */
const parseList = (value: string | undefined): string[] | undefined => {
  if (value === undefined) {
    return undefined;
  }

  return value
    .split(';')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');
};

/**
 * `security.allowedProviders` from JSON config is already validated by
 * `providerNameSchema` inside `serverConfigSchema.parse`. The `;`-separated env var bypasses
 * zod entirely (same as every other `BROWSER_MCP_*` list), so it gets its own check here --
 * a typo'd provider name must fail loudly at start-up, not silently never match (and therefore
 * silently allow nothing).
 */
const parseProviderList = (raw: string[] | undefined): ProviderName[] | undefined => {
  if (raw === undefined) {
    return undefined;
  }

  return raw.map((entry) => {
    if (!(providerNames as readonly string[]).includes(entry)) {
      throw new Error(
        `Invalid entry "${entry}" in BROWSER_MCP_ALLOWED_PROVIDERS: must be one of ${providerNames.join(', ')}.`,
      );
    }

    return entry as ProviderName;
  });
};

const parseJsonConfig = (rawValue: string, source: string): ServerConfig => {
  try {
    return serverConfigSchema.parse(JSON.parse(rawValue));
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'Unknown error';
    throw new Error(`Invalid browser MCP config from ${source}: ${reason}`);
  }
};

const loadConfigOverride = (): ServerConfig => {
  if (process.env.BROWSER_MCP_CONFIG !== undefined) {
    return parseJsonConfig(process.env.BROWSER_MCP_CONFIG, 'BROWSER_MCP_CONFIG');
  }

  if (process.env.BROWSER_MCP_CONFIG_PATH !== undefined) {
    const filePath = resolve(process.cwd(), process.env.BROWSER_MCP_CONFIG_PATH);
    const rawValue = readFileSync(filePath, 'utf8');

    return parseJsonConfig(rawValue, `BROWSER_MCP_CONFIG_PATH (${filePath})`);
  }

  return serverConfigSchema.parse({});
};

export const loadServerConfig = (): ResolvedServerConfig => {
  const override = loadConfigOverride();
  const browserbaseConfig = override.providers.browserbase ?? {};
  const anchorConfig = override.providers.anchor ?? {};
  const playwrightConfig = override.providers.playwright ?? {};
  const cloudflareConfig = override.providers.cloudflare ?? {};

  const securityConfig = override.security ?? {};

  return {
    defaultProvider: override.defaultProvider ?? 'playwright',
    security: {
      allowedOrigins:
        securityConfig.allowedOrigins ??
        parseList(process.env.BROWSER_MCP_ALLOWED_ORIGINS) ??
        [],
      blockedOrigins:
        securityConfig.blockedOrigins ??
        parseList(process.env.BROWSER_MCP_BLOCKED_ORIGINS) ??
        [],
      blockedSchemes:
        securityConfig.blockedSchemes ??
        parseList(process.env.BROWSER_MCP_BLOCKED_SCHEMES) ??
        [],
      allowedUploadDirectories:
        securityConfig.allowedUploadDirectories ??
        parseList(process.env.BROWSER_MCP_ALLOWED_UPLOAD_DIRS) ??
        [],
      // NOT permissive-by-default, unlike the fields above: an unset allowlist here means
      // "playwright only", not "every provider". See securityConfigSchema for why.
      allowedProviders:
        securityConfig.allowedProviders ??
        parseProviderList(parseList(process.env.BROWSER_MCP_ALLOWED_PROVIDERS)) ??
        ['playwright'],
      allowUnscopedCloseAll:
        securityConfig.allowUnscopedCloseAll ??
        parseBoolean(process.env.BROWSER_MCP_ALLOW_UNSCOPED_CLOSE_ALL) ??
        false,
    },
    providers: {
      browserbase: {
        apiKey: process.env.BROWSERBASE_API_KEY ?? null,
        projectId: browserbaseConfig.projectId ?? process.env.BROWSERBASE_PROJECT_ID ?? null,
        proxy:
          browserbaseConfig.proxy ??
          parseBoolean(process.env.BROWSERBASE_PROXY) ??
          null,
        keepAlive:
          browserbaseConfig.keepAlive ??
          parseBoolean(process.env.BROWSERBASE_KEEP_ALIVE) ??
          false,
        contextId: browserbaseConfig.contextId ?? process.env.BROWSERBASE_CONTEXT_ID ?? null,
        persist:
          browserbaseConfig.persist ??
          parseBoolean(process.env.BROWSERBASE_PERSIST) ??
          true,
        sessionOptions: browserbaseConfig.sessionOptions ?? {},
      },
      anchor: {
        apiKey: process.env.ANCHOR_API_KEY ?? null,
        recording:
          anchorConfig.recording ??
          parseBoolean(process.env.ANCHOR_RECORDING) ??
          null,
        proxy: anchorConfig.proxy ?? null,
        timeout: anchorConfig.timeout ?? null,
        sessionOptions: anchorConfig.sessionOptions ?? {},
      },
      playwright: {
        launchOptions: playwrightConfig.launchOptions ?? {},
        contextOptions: playwrightConfig.contextOptions ?? {},
        storageStatePath:
          playwrightConfig.storageStatePath ?? process.env.PLAYWRIGHT_STORAGE_STATE_PATH ?? null,
        executablePath:
          playwrightConfig.executablePath ?? process.env.PLAYWRIGHT_EXECUTABLE_PATH ?? null,
        channel: playwrightConfig.channel ?? process.env.PLAYWRIGHT_CHANNEL ?? null,
        useCloakBrowser:
          playwrightConfig.useCloakBrowser ??
          parseBoolean(process.env.PLAYWRIGHT_USE_CLOAKBROWSER) ??
          false,
      },
      cloudflare: {
        apiKey: process.env.CLOUDFLARE_API_TOKEN ?? null,
        accountId: cloudflareConfig.accountId ?? process.env.CLOUDFLARE_ACCOUNT_ID ?? null,
        keepAlive: cloudflareConfig.keepAlive ?? null,
      },
    },
  };
};
