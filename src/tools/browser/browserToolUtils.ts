import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { SecurityPolicyError, type BlockedRequest } from '../../security/securityPolicy.js';
import type { SessionRecord } from '../../types/session.js';
import { textResult } from '../../utils/mcp.js';
import { SessionRegistry, SessionRegistryError } from '../../sessions/SessionRegistry.js';

type SessionArgs = {
  sessionId: number;
};

type BrowserToolExecutor<TArgs extends SessionArgs> = (
  session: SessionRecord,
  args: TArgs,
) => Promise<CallToolResult>;

/** Cap on how many individual blocks a single tool result lists before summarising. */
const MAX_REPORTED_BLOCKS = 10;

const getErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message;
  }

  return 'Unknown error';
};

/**
 * Appends a notice naming every origin the security policy blocked during this call.
 *
 * A silently dropped request is indistinguishable from a broken target, so the agent that
 * caused the block is told about it on the very call that caused it -- whether that call
 * otherwise succeeded (e.g. a `fetch` from `browser_evaluate` that the page swallowed) or
 * failed (e.g. a navigation that aborted with net::ERR_BLOCKED_BY_CLIENT).
 */
const appendBlockedRequestNotice = (
  result: CallToolResult,
  blocked: BlockedRequest[],
): CallToolResult => {
  const shown = blocked.slice(0, MAX_REPORTED_BLOCKS);
  const lines = shown.map((entry) => `  - [${entry.layer}] ${entry.url} -- ${entry.reason}`);

  if (blocked.length > shown.length) {
    lines.push(`  - ...and ${blocked.length - shown.length} more.`);
  }

  return {
    ...result,
    content: [
      ...result.content,
      {
        type: 'text',
        text:
          `SECURITY POLICY BLOCKED ${blocked.length} request(s) during this call:\n` +
          `${lines.join('\n')}\n` +
          'These origins are outside the configured scope for this server. ' +
          'Widen the operator-set allowlist if they are genuinely in scope; do not retry.',
      },
    ],
  };
};

export const withSession = <TArgs extends SessionArgs>(
  registry: SessionRegistry,
  executor: BrowserToolExecutor<TArgs>,
) => {
  return async (args: TArgs): Promise<CallToolResult> => {
    let session: SessionRecord | undefined;
    let blockedBefore = 0;
    let result: CallToolResult;

    try {
      session = registry.getSessionOrThrow(args.sessionId);
      blockedBefore = session.blockedRequests.total;
      result = await executor(session, args);
    } catch (error) {
      result =
        error instanceof SessionRegistryError || error instanceof SecurityPolicyError
          ? textResult(error.message, true)
          : textResult(`Tool failed: ${getErrorMessage(error)}`, true);
    }

    if (session !== undefined) {
      const blocked = session.blockedRequests.since(blockedBefore);

      if (blocked.length > 0) {
        return appendBlockedRequestNotice(result, blocked);
      }
    }

    return result;
  };
};
