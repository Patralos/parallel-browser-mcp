import type { BrowserContext } from 'playwright-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { applySecurityPolicyToContext } from './applySecurityPolicy.js';
import { BlockedRequestLog, SecurityPolicy } from './securityPolicy.js';

/**
 * These tests exercise the enforcement layer itself: the handler registered on
 * `BrowserContext.route`. That handler only ever sees a URL -- it has no idea whether the
 * request came from `browser_navigate`, from `location.href` set by `browser_evaluate`, from an
 * injected `<iframe>`, or from a subresource. That initiator-blindness IS the control, and it is
 * what an argument check on `browser_navigate` cannot give you.
 *
 * `src/smoke/securityPolicySmoke.ts` proves the same thing end-to-end against a real Chromium.
 */

type RouteHandler = (route: FakeRoute) => Promise<void>;
type WebSocketHandler = (route: FakeWebSocketRoute) => void;
type FrameHandler = (frame: FakeFrame) => void;

class FakeRoute {
  readonly continued = vi.fn(async () => undefined);
  readonly aborted = vi.fn(async (_errorCode?: string) => undefined);

  constructor(private readonly requestUrl: string) {}

  request(): { url: () => string } {
    return { url: () => this.requestUrl };
  }

  async continue(): Promise<void> {
    await this.continued();
  }

  async abort(errorCode?: string): Promise<void> {
    await this.aborted(errorCode);
  }
}

class FakeWebSocketRoute {
  readonly connected = vi.fn();
  readonly closed = vi.fn();

  constructor(private readonly socketUrl: string) {}

  url(): string {
    return this.socketUrl;
  }

  connectToServer(): void {
    this.connected();
  }

  close(options?: { code?: number; reason?: string }): void {
    this.closed(options);
  }
}

class FakeFrame {
  readonly goto = vi.fn(async () => null);

  constructor(private readonly frameUrl: string) {}

  url(): string {
    return this.frameUrl;
  }
}

class FakePage {
  frameNavigatedHandler: FrameHandler | null = null;

  on(event: string, handler: FrameHandler): void {
    if (event === 'framenavigated') {
      this.frameNavigatedHandler = handler;
    }
  }
}

class FakeContext {
  routeHandler: RouteHandler | null = null;
  webSocketHandler: WebSocketHandler | null = null;
  readonly initScripts: unknown[] = [];
  readonly page = new FakePage();

  async addInitScript(script: unknown): Promise<void> {
    this.initScripts.push(script);
  }

  async route(_url: unknown, handler: RouteHandler): Promise<void> {
    this.routeHandler = handler;
  }

  async routeWebSocket(_url: unknown, handler: WebSocketHandler): Promise<void> {
    this.webSocketHandler = handler;
  }

  on(_event: string, _handler: unknown): void {
    // New pages inherit the guard; the initial page is covered by pages() below.
  }

  pages(): FakePage[] {
    return [this.page];
  }
}

const scopedPolicy = (): SecurityPolicy =>
  new SecurityPolicy({
    allowedOrigins: ['127.0.0.1:8899'],
    blockedOrigins: [],
    blockedSchemes: [],
    allowedUploadDirectories: [],
  });

describe('applySecurityPolicyToContext', () => {
  let context: FakeContext;
  let log: BlockedRequestLog;

  beforeEach(async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    context = new FakeContext();
    log = new BlockedRequestLog();

    await applySecurityPolicyToContext(context as unknown as BrowserContext, scopedPolicy(), {
      sessionLabel: 'session=1',
      log,
    });
  });

  it('continues a request to an allowed origin', async () => {
    const route = new FakeRoute('http://127.0.0.1:8899/login');

    await context.routeHandler?.(route);

    expect(route.continued).toHaveBeenCalledTimes(1);
    expect(route.aborted).not.toHaveBeenCalled();
    expect(log.total).toBe(0);
  });

  it('aborts a request to a disallowed origin and records it', async () => {
    const route = new FakeRoute('http://127.0.0.1:8900/secret');

    await context.routeHandler?.(route);

    expect(route.continued).not.toHaveBeenCalled();
    expect(route.aborted).toHaveBeenCalledWith('blockedbyclient');
    expect(log.total).toBe(1);
    expect(log.since(0)[0]?.reason).toContain('http://127.0.0.1:8900');
  });

  it('blocks a disallowed origin identically no matter what initiated the request', async () => {
    // The handler receives only a URL. A fetch/XHR/iframe/location.href issued from inside
    // browser_evaluate arrives here exactly like a browser_navigate would -- which is why
    // enforcing at this layer cannot be routed around by running JavaScript in the page.
    const initiators = [
      'http://127.0.0.1:8900/from-navigate',
      'http://127.0.0.1:8900/from-fetch',
      'http://127.0.0.1:8900/from-iframe',
      'http://127.0.0.1:8900/from-window-open',
      'http://127.0.0.1:8900/favicon.ico',
    ];

    for (const url of initiators) {
      const route = new FakeRoute(url);

      await context.routeHandler?.(route);

      expect(route.aborted, url).toHaveBeenCalledWith('blockedbyclient');
      expect(route.continued, url).not.toHaveBeenCalled();
    }

    expect(log.total).toBe(initiators.length);
  });

  it('connects an allowed WebSocket and refuses a disallowed one', async () => {
    const allowed = new FakeWebSocketRoute('ws://127.0.0.1:8899/socket');
    const blocked = new FakeWebSocketRoute('ws://127.0.0.1:8900/socket');

    context.webSocketHandler?.(allowed);
    context.webSocketHandler?.(blocked);

    expect(allowed.connected).toHaveBeenCalledTimes(1);
    expect(allowed.closed).not.toHaveBeenCalled();
    // Never calling connectToServer() means no socket to the blocked origin is opened at all.
    expect(blocked.connected).not.toHaveBeenCalled();
    expect(blocked.closed).toHaveBeenCalledTimes(1);
    expect(log.total).toBe(1);
  });

  it('records and resets a frame that reached a disallowed URL without an HTTP request', async () => {
    const frame = new FakeFrame('file:///C:/Users/Patrick/cert.pem');

    context.page.frameNavigatedHandler?.(frame);

    expect(log.total).toBe(1);
    expect(log.since(0)[0]?.layer).toBe('navigation-guard');
    expect(frame.goto).toHaveBeenCalledWith('about:blank');
  });

  it('neuters WebRTC only when a scope has been declared', async () => {
    // WebRTC egresses over raw UDP, which context.route() cannot see, so it is removed from the
    // JS realm instead -- but only once the operator has declared a scope, since it changes
    // behaviour for targets that legitimately use WebRTC.
    expect(context.initScripts).toHaveLength(1);

    const permissiveContext = new FakeContext();

    await applySecurityPolicyToContext(
      permissiveContext as unknown as BrowserContext,
      new SecurityPolicy({
        allowedOrigins: [],
        blockedOrigins: [],
        blockedSchemes: [],
        allowedUploadDirectories: [],
      }),
      { sessionLabel: 'session=2', log: new BlockedRequestLog() },
    );

    expect(permissiveContext.initScripts).toHaveLength(0);
  });

  it('ignores about:blank and Chromium error pages in the navigation guard', () => {
    const blank = new FakeFrame('about:blank');
    const errorPage = new FakeFrame('chrome-error://chromewebdata/');

    context.page.frameNavigatedHandler?.(blank);
    context.page.frameNavigatedHandler?.(errorPage);

    expect(log.total).toBe(0);
    expect(blank.goto).not.toHaveBeenCalled();
    expect(errorPage.goto).not.toHaveBeenCalled();
  });
});
