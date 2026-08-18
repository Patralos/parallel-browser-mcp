import { z } from 'zod';
import {
  anchorProviderConfigSchema,
  browserbaseProviderConfigSchema,
  cloudflareProviderConfigSchema,
  playwrightProviderConfigSchema,
  providerNameSchema,
} from '../types/providerConfig.js';

/**
 * Server-level security controls. Operator-set at start-up, never a tool argument, so a calling
 * agent cannot widen its own scope. `allowedOrigins` / `blockedOrigins` mirror `@playwright/mcp`.
 */
export const securityConfigSchema = z
  .object({
    allowedOrigins: z.array(z.string().min(1)).optional(),
    blockedOrigins: z.array(z.string().min(1)).optional(),
    blockedSchemes: z.array(z.string().min(1)).optional(),
    allowedUploadDirectories: z.array(z.string().min(1)).optional(),
  })
  .strict();

export const serverConfigSchema = z
  .object({
    defaultProvider: providerNameSchema.nullable().optional(),
    security: securityConfigSchema.default({}),
    providers: z
      .object({
        browserbase: browserbaseProviderConfigSchema.optional(),
        anchor: anchorProviderConfigSchema.optional(),
        playwright: playwrightProviderConfigSchema.optional(),
        cloudflare: cloudflareProviderConfigSchema.optional(),
      })
      .default({}),
  })
  .strict();

export type ServerConfig = z.infer<typeof serverConfigSchema>;

export interface ResolvedBrowserbaseProviderConfig {
  apiKey: string | null;
  projectId: string | null;
  proxy: boolean | Record<string, unknown> | null;
  keepAlive: boolean;
  contextId: string | null;
  persist: boolean;
  sessionOptions: Record<string, unknown>;
}

export interface ResolvedAnchorProviderConfig {
  apiKey: string | null;
  recording: boolean | null;
  proxy: Record<string, unknown> | null;
  timeout: {
    maxDuration?: number;
    idleTimeout?: number;
  } | null;
  sessionOptions: Record<string, unknown>;
}

export interface ResolvedPlaywrightProviderConfig {
  launchOptions: Record<string, unknown>;
  contextOptions: Record<string, unknown>;
  storageStatePath: string | null;
  executablePath: string | null;
  channel: string | null;
  useCloakBrowser: boolean;
}

export interface ResolvedCloudflareProviderConfig {
  apiKey: string | null;
  accountId: string | null;
  keepAlive: number | null;
}

export interface ResolvedSecurityConfig {
  /** Empty means no allowlist: every origin is permitted (documented permissive default). */
  allowedOrigins: string[];
  blockedOrigins: string[];
  /** Added to ALWAYS_BLOCKED_SCHEMES; the built-in entries cannot be removed. */
  blockedSchemes: string[];
  /** Empty means `browser_upload_file` is unrestricted (documented permissive default). */
  allowedUploadDirectories: string[];
}

export interface ResolvedServerConfig {
  defaultProvider: 'browserbase' | 'anchor' | 'playwright' | 'cloudflare';
  security: ResolvedSecurityConfig;
  providers: {
    browserbase: ResolvedBrowserbaseProviderConfig;
    anchor: ResolvedAnchorProviderConfig;
    playwright: ResolvedPlaywrightProviderConfig;
    cloudflare: ResolvedCloudflareProviderConfig;
  };
}
