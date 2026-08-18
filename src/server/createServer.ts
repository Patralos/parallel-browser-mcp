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

export const createServer = (config: ResolvedServerConfig): BrowserMcpServer => {
  // Throws on an unparseable origin entry or a missing upload directory, so a typo in the
  // scope allowlist fails at start-up instead of silently never matching.
  const securityPolicy = new SecurityPolicy(config.security);
  const policyDescription = describePolicy(securityPolicy);

  console.error(`[security-policy] ${policyDescription}`);

  const providers = createProviders(config);
  const registry = new SessionRegistry(providers, config.defaultProvider, securityPolicy);
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
        policyDescription,
    },
  );

  registerSessionTools(server, registry);
  registerBrowserTools(server, registry, securityPolicy);

  return {
    server,
    registry,
  };
};
