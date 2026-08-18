import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ResolvedServerConfig } from '../config/serverConfig.js';
import { createProviders } from '../providers/createProvider.js';
import { SecurityPolicy } from '../security/securityPolicy.js';
import { SessionRegistry } from '../sessions/SessionRegistry.js';
import { registerBrowserTools } from '../tools/browser/registerBrowserTools.js';
import { registerSessionTools } from '../tools/session/registerSessionTools.js';

export interface BrowserMcpServer {
  server: McpServer;
  registry: SessionRegistry;
}

/**
 * Tells the calling agent where its boundary is, up front, so a blocked request is understood
 * rather than mistaken for a broken target. Also logged to stderr for the operator.
 */
const describePolicy = (policy: SecurityPolicy): string => {
  const summary = policy.describe();
  const lines: string[] = [];

  lines.push(
    summary.allowedOrigins.length > 0
      ? `Origin allowlist ACTIVE: only ${summary.allowedOrigins.join(', ')} are reachable; every other origin is blocked in the browser layer.`
      : 'Origin allowlist NOT configured: all origins are reachable (permissive default).',
  );

  if (summary.blockedOrigins.length > 0) {
    lines.push(`Blocked origins: ${summary.blockedOrigins.join(', ')}.`);
  }

  lines.push(`Always-blocked URL schemes: ${summary.blockedSchemes.join(', ')}.`);
  lines.push(
    summary.allowedUploadDirectories.length > 0
      ? `browser_upload_file is restricted to: ${summary.allowedUploadDirectories.join(', ')}.`
      : 'browser_upload_file is NOT restricted to a directory allowlist (permissive default).',
  );

  return lines.join(' ');
};

/**
 * Unlike `describePolicy` above, there is no "permissive default" branch here -- the provider
 * allowlist is never unset, so this always names a concrete (possibly single-provider) list.
 */
const describeProviderPolicy = (config: ResolvedServerConfig): string => {
  const allowed = config.security.allowedProviders;
  const allowedText = allowed.length > 0 ? allowed.join(', ') : '(none)';
  const closeAllText = config.security.allowUnscopedCloseAll
    ? 'close_all_sessions may close every session on the server (security.allowUnscopedCloseAll is true).'
    : 'close_all_sessions without an ownerId is refused (security.allowUnscopedCloseAll is false, the default).';

  return `Providers this server will launch: ${allowedText}. ${closeAllText}`;
};

export const createServer = (config: ResolvedServerConfig): BrowserMcpServer => {
  // Throws on an unparseable origin entry or a missing upload directory, so a typo in the
  // scope allowlist fails at start-up instead of silently never matching.
  const securityPolicy = new SecurityPolicy(config.security);
  const policyDescription = describePolicy(securityPolicy);
  const providerPolicyDescription = describeProviderPolicy(config);

  console.error(`[security-policy] ${policyDescription}`);
  console.error(`[security-policy] ${providerPolicyDescription}`);

  const allowedProviders = new Set(config.security.allowedProviders);

  // Fail fast: a defaultProvider outside the allowlist would mean every start_session call that
  // omits `provider` fails, which is a confusing way to discover a config mistake. Catch it here,
  // at start-up, the same way SecurityPolicy fails fast on a malformed origin entry.
  if (!allowedProviders.has(config.defaultProvider)) {
    throw new Error(
      `Configured defaultProvider "${config.defaultProvider}" is not in security.allowedProviders ` +
        `(${[...allowedProviders].join(', ') || '(none)'}). Add it to the allowlist or change defaultProvider.`,
    );
  }

  const providers = createProviders(config);
  const registry = new SessionRegistry(providers, {
    defaultProvider: config.defaultProvider,
    securityPolicy,
    allowedProviders,
    allowUnscopedCloseAll: config.security.allowUnscopedCloseAll,
  });
  const server = new McpServer(
    {
      name: 'browser-mcp',
      version: '0.1.0',
    },
    {
      capabilities: {
        logging: {},
      },
      instructions:
        'Use start_session first to create a numeric browser session. Pass that sessionId to all browser_* tools. ' +
        'start_session returns an ownerId -- keep it, you need it to close_session or close_all_sessions ' +
        'your own sessions later; a session owned by a different caller cannot be closed. ' +
        `${policyDescription} ${providerPolicyDescription}`,
    },
  );

  registerSessionTools(server, registry);
  registerBrowserTools(server, registry, securityPolicy);

  return {
    server,
    registry,
  };
};
