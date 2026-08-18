import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { describe, expect, it, vi } from 'vitest';
import { registerSessionTools } from './registerSessionTools.js';

class FakeServer {
  readonly tools = new Map<string, (args: unknown) => Promise<unknown>>();

  registerTool(name: string, _config: unknown, handler: (args: unknown) => Promise<unknown>): void {
    this.tools.set(name, handler);
  }
}

describe('registerSessionTools', () => {
  it('starts and lists sessions via the registry', async () => {
    const fakeServer = new FakeServer();
    const registry = {
      startSession: vi.fn(async () => ({ id: 1, provider: 'playwright' })),
      closeSession: vi.fn(async () => undefined),
      closeAllSessions: vi.fn(async () => 1),
      getSessions: vi.fn(() => [{ id: 1, provider: 'playwright' }]),
    };

    registerSessionTools(fakeServer as unknown as McpServer, registry as never);

    const startSession = fakeServer.tools.get('start_session');
    const getSessions = fakeServer.tools.get('get_sessions');
    const startResult = (await startSession?.({
      provider: 'playwright',
    })) as { content: Array<{ text?: string }> };
    const listResult = (await getSessions?.({})) as { content: Array<{ text?: string }> };

    expect(startResult.content[0]?.text).toContain('"id": 1');
    expect(listResult.content[0]?.text).toContain('"playwright"');
  });

  it('forwards ownerId to the registry on close_session and close_all_sessions', async () => {
    const fakeServer = new FakeServer();
    const registry = {
      startSession: vi.fn(async () => ({ id: 1, provider: 'playwright', ownerId: 'agent-a' })),
      closeSession: vi.fn(async () => undefined),
      closeAllSessions: vi.fn(async () => 1),
      getSessions: vi.fn(() => []),
    };

    registerSessionTools(fakeServer as unknown as McpServer, registry as never);

    await fakeServer.tools.get('close_session')?.({ sessionId: 1, ownerId: 'agent-a' });
    expect(registry.closeSession).toHaveBeenCalledWith(1, 'agent-a');

    await fakeServer.tools.get('close_session')?.({ sessionId: 1 });
    expect(registry.closeSession).toHaveBeenCalledWith(1, undefined);

    await fakeServer.tools.get('close_all_sessions')?.({ ownerId: 'agent-a' });
    expect(registry.closeAllSessions).toHaveBeenCalledWith('agent-a');

    await fakeServer.tools.get('close_all_sessions')?.({});
    expect(registry.closeAllSessions).toHaveBeenCalledWith(undefined);
  });

  it('surfaces a SessionRegistry ownership refusal as a tool error, not a thrown exception', async () => {
    const fakeServer = new FakeServer();
    const registry = {
      startSession: vi.fn(async () => ({ id: 1, provider: 'playwright', ownerId: 'agent-a' })),
      closeSession: vi.fn(async () => {
        throw new Error('Session 1 is owned by a different caller; refusing to close it.');
      }),
      closeAllSessions: vi.fn(async () => 0),
      getSessions: vi.fn(() => []),
    };

    registerSessionTools(fakeServer as unknown as McpServer, registry as never);

    const result = (await fakeServer.tools.get('close_session')?.({
      sessionId: 1,
      ownerId: 'agent-b',
    })) as { isError?: boolean; content: Array<{ text?: string }> };

    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain('owned by a different caller');
  });
});
