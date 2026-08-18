import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SessionRegistry, SessionRegistryError } from '../../sessions/SessionRegistry.js';
import {
  closeAllSessionsSchema,
  closeSessionSchema,
  startSessionSchema,
} from '../../types/toolArgs.js';
import { jsonResult, textResult } from '../../utils/mcp.js';

const getErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message;
  }

  return 'Unknown error';
};

export const registerSessionTools = (server: McpServer, registry: SessionRegistry): void => {
  server.registerTool(
    'start_session',
    {
      title: 'Start Session',
      description:
        'Start a browser session using the configured provider. Returns an ownerId: pass the ' +
        'same value on future start_session calls to group sessions under it, and keep it -- ' +
        'closing this session later (via close_session or close_all_sessions) requires it, and a ' +
        'different caller cannot close this session without it.',
      inputSchema: startSessionSchema,
    },
    async (args) => {
      try {
        const session = await registry.startSession(args);

        return jsonResult(session);
      } catch (error) {
        return textResult(getErrorMessage(error), true);
      }
    },
  );

  server.registerTool(
    'close_session',
    {
      title: 'Close Session',
      description:
        'Close a browser session by numeric session ID. Requires the ownerId returned by the ' +
        'start_session call that created it -- closing a session you do not own is refused.',
      inputSchema: closeSessionSchema,
    },
    async ({ sessionId, ownerId }) => {
      try {
        await registry.closeSession(sessionId, ownerId);

        return jsonResult({
          sessionId,
          closed: true,
        });
      } catch (error) {
        return textResult(getErrorMessage(error), true);
      }
    },
  );

  server.registerTool(
    'close_all_sessions',
    {
      title: 'Close All Sessions',
      description:
        'Close sessions. Pass ownerId to close only the sessions you own (always allowed). ' +
        "Omit it to close every session on the server, including other callers' -- refused unless " +
        'the operator has enabled security.allowUnscopedCloseAll.',
      inputSchema: closeAllSessionsSchema,
    },
    async ({ ownerId }) => {
      try {
        const closedCount = await registry.closeAllSessions(ownerId);

        return jsonResult({
          closedCount,
        });
      } catch (error) {
        return textResult(getErrorMessage(error), true);
      }
    },
  );

  server.registerTool(
    'get_sessions',
    {
      title: 'Get Sessions',
      description: 'List all active browser sessions.',
    },
    async () => {
      try {
        return jsonResult({
          sessions: registry.getSessions(),
        });
      } catch (error) {
        return textResult(getErrorMessage(error), true);
      }
    },
  );
};
