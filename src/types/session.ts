import type { Browser, BrowserContext, Page } from 'playwright-core';
import type { BlockedRequestLog } from '../security/securityPolicy.js';
import type {
  ProviderName,
} from './providerConfig.js';
import type {
  ResolvedAnchorProviderConfig,
  ResolvedBrowserbaseProviderConfig,
  ResolvedCloudflareProviderConfig,
  ResolvedPlaywrightProviderConfig,
} from '../config/serverConfig.js';

export interface StartSessionInput {
  provider?: ProviderName;
  sessionName?: string;
  /**
   * Caller-chosen owner identifier. Sessions started under the same `ownerId` can later be
   * closed (individually or via `close_all_sessions`) by supplying that same `ownerId` again.
   * If omitted, the server assigns a private, unguessable one and returns it -- see
   * `SessionRegistry.startSession`.
   */
  ownerId?: string;
}

export interface StartedBrowserSession {
  browser: Browser;
  context: BrowserContext;
  page: Page;
  providerSessionId: string | null;
  metadata: Record<string, unknown>;
  resolvedProviderConfig:
    | ResolvedBrowserbaseProviderConfig
    | ResolvedAnchorProviderConfig
    | ResolvedPlaywrightProviderConfig
    | ResolvedCloudflareProviderConfig;
}

export interface SessionRecord extends StartedBrowserSession {
  id: number;
  provider: ProviderName;
  sessionName: string | null;
  createdAt: string;
  lastUsedAt: string;
  /** What the security policy stopped in this session, so tool calls can report it. */
  blockedRequests: BlockedRequestLog;
  /**
   * Who may close this session. Always set -- either the caller's own `ownerId`, or a
   * server-generated one when the caller didn't supply one. Never echoed back except on the
   * `start_session` call that set it, so a `get_sessions` listing cannot be used to harvest
   * another caller's ownership token.
   */
  ownerId: string;
}

export interface SessionSummary {
  id: number;
  provider: ProviderName;
  providerSessionId: string | null;
  sessionName: string | null;
  createdAt: string;
  lastUsedAt: string;
  metadata: Record<string, unknown>;
  resolvedProviderConfig:
    | ResolvedBrowserbaseProviderConfig
    | ResolvedAnchorProviderConfig
    | ResolvedPlaywrightProviderConfig
    | ResolvedCloudflareProviderConfig;
  /** Present only on the `start_session` response that created this session. See `ownerId` above. */
  ownerId?: string;
}

export interface SessionToolContext {
  sessionId: number;
}
