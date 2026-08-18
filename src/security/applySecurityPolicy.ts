import type { BrowserContext, Frame, Page } from 'playwright-core';
import {
  type BlockedRequest,
  type BlockedRequestLog,
  type SecurityPolicy,
} from './securityPolicy.js';

/**
 * Installs the origin restriction in the browser layer.
 *
 * WHY HERE AND NOT IN THE TOOL ARGUMENTS
 * --------------------------------------
 * Validating the `url` argument of `browser_navigate` is trivially bypassed: `browser_evaluate`
 * runs arbitrary JavaScript in the page, which can set `location.href`, call `fetch`, inject an
 * `<iframe>`, or `window.open`. None of those go anywhere near a tool argument. An argument
 * check alone would be a documented control that does not control anything.
 *
 * `context.route()` sits below all of that: it is Chromium's network interception, so every HTTP
 * request the context makes passes through it no matter what triggered it -- top-level
 * navigation, subresource, XHR/fetch, iframe, popup, prefetch, beacon, or a redirect hop. It is
 * registered on the *context*, so pages opened later (e.g. by `window.open`) inherit it.
 *
 * `context.routeWebSocket()` covers the one network path `route()` does not see.
 *
 * The post-navigation guard is a detective control for the paths neither can intercept, notably
 * `file://` -- which is not an HTTP request at all.
 *
 * WebRTC is the one channel none of these reach: `RTCPeerConnection` sends STUN/ICE over raw UDP,
 * below Chromium's network stack, so it is an egress path to an arbitrary host:port that is
 * invisible both to `context.route()` and to an HTTP proxy audit. Measured, not assumed -- see
 * HARDENING-2.md. It is neutered in the JS realm instead, and only when a scope has been declared.
 */

const nowIso = (): string => new Date().toISOString();

/** Chromium's own error page. Not a destination anyone can navigate to; never a violation. */
const isBrowserErrorPage = (url: string): boolean => url.startsWith('chrome-error:');

export interface SecurityPolicySink {
  sessionLabel: string;
  log: BlockedRequestLog;
}

const recordBlock = (sink: SecurityPolicySink, blocked: BlockedRequest): void => {
  sink.log.record(blocked);
  // stderr, not stdout: stdout is the MCP stdio transport.
  console.error(
    `[security-policy] BLOCKED (${blocked.layer}) ${sink.sessionLabel} ${blocked.url} -- ${blocked.reason}`,
  );
};

export const applySecurityPolicyToContext = async (
  context: BrowserContext,
  policy: SecurityPolicy,
  sink: SecurityPolicySink,
): Promise<void> => {
  // Layer 1 -- every HTTP(S) request in the context, whatever initiated it.
  await context.route(
    () => true,
    async (route) => {
      const url = route.request().url();
      const decision = policy.evaluateUrl(url);

      try {
        if (decision.allowed) {
          await route.continue();

          return;
        }

        recordBlock(sink, { url, reason: decision.reason, layer: 'route', at: nowIso() });
        await route.abort('blockedbyclient');
      } catch {
        // The request was already handled, or the page went away mid-flight. Nothing to do:
        // an unhandled route cannot let the request through, it just stalls.
      }
    },
  );

  // Layer 1b -- WebSocket handshakes, which `context.route()` does not intercept.
  await context.routeWebSocket(
    () => true,
    (webSocketRoute) => {
      const url = webSocketRoute.url();
      const decision = policy.evaluateUrl(url);

      if (decision.allowed) {
        webSocketRoute.connectToServer();

        return;
      }

      recordBlock(sink, { url, reason: decision.reason, layer: 'websocket', at: nowIso() });
      // Not calling connectToServer() means no connection to the origin is ever opened.
      webSocketRoute.close({ code: 1008, reason: 'Blocked by security policy' });
    },
  );

  // Layer 1c -- WebRTC. `context.route()` cannot see raw UDP, so the API is removed from every
  // realm instead. Playwright re-runs this on every new document, including `about:blank`
  // iframes, so page script cannot recover the constructor from a fresh frame (verified).
  //
  // Honest limitation: this is a JavaScript-realm control, not a network control. It is applied
  // only when an origin allowlist exists, because it does change behaviour for any target that
  // legitimately uses WebRTC. Network-level UDP egress control belongs on the host firewall.
  if (policy.hasOriginAllowlist) {
    await context.addInitScript(() => {
      const disabled = ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel'];

      for (const name of disabled) {
        Object.defineProperty(window, name, {
          configurable: false,
          get() {
            throw new Error('WebRTC is disabled by the browser-mcp security policy');
          },
        });
      }
    });
  }

  // Layer 2 -- post-navigation guard. Catches anything that reached a disallowed URL without
  // producing an interceptable request (a `file://` navigation is the case that matters).
  // Best effort and after the fact: it makes the violation visible and resets the frame, but it
  // cannot un-load content the page already had. `browser_navigate`'s argument check and the
  // always-on scheme denylist are what actually stop `file://` before it loads.
  const guardFrame = (frame: Frame): void => {
    const url = frame.url();

    if (url === '' || isBrowserErrorPage(url)) {
      return;
    }

    const decision = policy.evaluateUrl(url);

    if (decision.allowed) {
      return;
    }

    recordBlock(sink, {
      url,
      reason: `${decision.reason} (reached without an interceptable request; frame reset to about:blank)`,
      layer: 'navigation-guard',
      at: nowIso(),
    });

    void frame.goto('about:blank').catch(() => undefined);
  };

  const guardPage = (page: Page): void => {
    page.on('framenavigated', guardFrame);
  };

  context.on('page', guardPage);

  for (const page of context.pages()) {
    guardPage(page);
  }
};
