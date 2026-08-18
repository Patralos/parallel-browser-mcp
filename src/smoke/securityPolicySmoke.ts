/**
 * Empirical proof of the origin restriction, against a real Chromium and a real MCP stdio client.
 *
 * Unit tests prove the decision function and the handler wiring. This proves the whole path:
 * a real `parallel-browser-mcp` process, driven over stdio exactly the way a subagent drives it,
 * against two local HTTP servers -- one in scope, one out of scope.
 *
 * The decisive evidence is server-side: the out-of-scope server counts every request that
 * reaches it. If it stays at zero across every bypass attempt, nothing got through.
 *
 * Localhost only. Run with: npm run smoke:security
 */

import { createHash, randomUUID } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { createServer as createHttpServer, type IncomingMessage, type Server } from 'node:http';
import type { Duplex } from 'node:stream';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const IN_SCOPE_PORT = 18899;
const OUT_OF_SCOPE_PORT = 18900;
const OUT_OF_SCOPE_UDP_PORT = 18901;
const IN_SCOPE_ORIGIN = `http://127.0.0.1:${IN_SCOPE_PORT}`;
const OUT_OF_SCOPE_ORIGIN = `http://127.0.0.1:${OUT_OF_SCOPE_PORT}`;

interface TargetServer {
  server: Server;
  hits: string[];
  upgrades: string[];
}

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const startTargetServer = (port: number, label: string): Promise<TargetServer> => {
  const hits: string[] = [];
  const upgrades: string[] = [];

  const server = createHttpServer((request, response) => {
    hits.push(`${request.method} ${request.url}`);

    const url = request.url ?? '/';

    if (url === '/sw.js') {
      response.writeHead(200, {
        'content-type': 'application/javascript',
        'service-worker-allowed': '/',
      });
      response.end(
        `self.addEventListener('install', (event) => {\n` +
          `  event.waitUntil(fetch('${OUT_OF_SCOPE_ORIGIN}/via-service-worker')\n` +
          `    .then(() => self.__ok = true).catch(() => self.__ok = false));\n` +
          `});\n`,
      );

      return;
    }

    if (url.startsWith('/upload')) {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<!doctype html><title>upload</title><input type="file" id="picker">');

      return;
    }

    response.writeHead(200, { 'content-type': 'text/html' });
    response.end(`<!doctype html><title>${label}</title><h1>${label}</h1>`);
  });

  // Minimal WebSocket handshake: enough for the browser to consider the socket open.
  server.on('upgrade', (request: IncomingMessage, socket: Duplex) => {
    upgrades.push(`UPGRADE ${request.url}`);

    const key = request.headers['sec-websocket-key'] ?? '';
    const accept = createHash('sha1')
      .update(`${key}${WS_GUID}`)
      .digest('base64');

    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
  });

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({ server, hits, upgrades }));
  });
};

const toText = (result: unknown): string => {
  const content = (result as { content?: Array<{ type: string; text?: string }> }).content ?? [];

  return content
    .filter((part) => part.type === 'text')
    .map((part) => part.text ?? '')
    .join('\n');
};

let passed = 0;
let failed = 0;
const failures: string[] = [];

const check = (name: string, condition: boolean, detail: string): void => {
  if (condition) {
    passed += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failed += 1;
    failures.push(name);
    console.log(`  FAIL  ${name}`);
  }

  console.log(`        ${detail.replace(/\s+/g, ' ').slice(0, 300)}`);
};

const note = (name: string, detail: string): void => {
  console.log(`  NOTE  ${name}`);
  console.log(`        ${detail.replace(/\s+/g, ' ').slice(0, 300)}`);
};

const main = async (): Promise<void> => {
  const workspace = mkdtempSync(join(tmpdir(), 'pbmcp-policy-smoke-'));
  const uploadsDir = join(workspace, 'uploads');
  const secretsDir = join(workspace, 'secrets');

  mkdirSync(uploadsDir, { recursive: true });
  mkdirSync(secretsDir, { recursive: true });

  const allowedUpload = join(uploadsDir, 'in-scope-payload.txt');
  const secretFile = join(secretsDir, 'cert.pem');
  const secretMarker = `SMOKE-SECRET-${randomUUID()}`;

  writeFileSync(allowedUpload, 'payload that is fine to upload');
  writeFileSync(secretFile, `-----BEGIN CERTIFICATE-----\n${secretMarker}\n`);

  // Raw-UDP listener: the destination a WebRTC STUN probe would reach if nothing stopped it.
  const udpPackets: string[] = [];
  const udpListener = createSocket('udp4');

  udpListener.on('message', (message) => udpPackets.push(`${message.length}B`));
  await new Promise<void>((resolve) => udpListener.bind(OUT_OF_SCOPE_UDP_PORT, '127.0.0.1', resolve));

  const inScope = await startTargetServer(IN_SCOPE_PORT, 'in-scope');
  const outOfScope = await startTargetServer(OUT_OF_SCOPE_PORT, 'OUT-OF-SCOPE');

  console.log(`in-scope server      ${IN_SCOPE_ORIGIN}`);
  console.log(`out-of-scope server  ${OUT_OF_SCOPE_ORIGIN}`);
  console.log(`secret file          ${secretFile}`);
  console.log(`upload allowlist     ${uploadsDir}`);
  console.log('');

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      fileURLToPath(new URL('../../node_modules/tsx/dist/cli.mjs', import.meta.url)),
      fileURLToPath(new URL('../index.ts', import.meta.url)),
    ],
    env: {
      ...(process.env as Record<string, string>),
      BROWSER_MCP_CONFIG: JSON.stringify({
        defaultProvider: 'playwright',
        security: {
          allowedOrigins: [`127.0.0.1:${IN_SCOPE_PORT}`],
          allowedUploadDirectories: [uploadsDir],
        },
        providers: {
          playwright: { launchOptions: { headless: true } },
        },
      }),
    },
    stderr: 'inherit',
  });

  const client = new Client({ name: 'security-policy-smoke', version: '1.0.0' });

  await client.connect(transport);

  const call = async (name: string, args: Record<string, unknown>): Promise<string> =>
    toText(await client.callTool({ name, arguments: args }));

  const startResult = await call('start_session', { sessionName: 'policy-smoke' });
  const sessionId = (JSON.parse(startResult) as { id: number }).id;

  console.log(`MCP session id ${sessionId}\n`);

  try {
    // ---------------------------------------------------------------- allowed origin
    console.log('== origin allowlist ==');
    const allowedNav = await call('browser_navigate', {
      sessionId,
      url: `${IN_SCOPE_ORIGIN}/`,
    });

    check(
      'in-scope origin is reachable',
      allowedNav.includes('"status": 200') && inScope.hits.length > 0,
      allowedNav,
    );

    // ------------------------------------------------- disallowed origin, via navigate
    const blockedNav = await call('browser_navigate', {
      sessionId,
      url: `${OUT_OF_SCOPE_ORIGIN}/`,
    });

    check(
      'out-of-scope origin blocked via browser_navigate',
      blockedNav.includes('Blocked by security policy') &&
        blockedNav.includes(OUT_OF_SCOPE_ORIGIN) &&
        outOfScope.hits.length === 0,
      `${blockedNav} | out-of-scope hits: ${outOfScope.hits.length}`,
    );

    // ================================================================================
    // THE TEST THAT MATTERS: the same origin, reached from JavaScript instead of from a
    // tool argument. An argument check cannot see any of these.
    // ================================================================================
    console.log('\n== browser_evaluate bypass attempts (the decisive test) ==');

    const fetchAttempt = await call('browser_evaluate', {
      sessionId,
      script: `return fetch('${OUT_OF_SCOPE_ORIGIN}/via-fetch')
        .then(r => 'FETCH REACHED IT: ' + r.status)
        .catch(e => 'fetch rejected: ' + e.message);`,
    });

    check(
      'browser_evaluate fetch() to out-of-scope origin is blocked',
      !fetchAttempt.includes('FETCH REACHED IT') && outOfScope.hits.length === 0,
      `${fetchAttempt} | out-of-scope hits: ${outOfScope.hits.length}`,
    );

    check(
      'the block is reported back to the calling agent, naming the origin',
      fetchAttempt.includes('SECURITY POLICY BLOCKED') &&
        fetchAttempt.includes(`${OUT_OF_SCOPE_ORIGIN}/via-fetch`),
      fetchAttempt,
    );

    await call('browser_evaluate', {
      sessionId,
      script: `location.href = '${OUT_OF_SCOPE_ORIGIN}/via-location';`,
    });
    await call('browser_wait_for_timeout', { sessionId, milliseconds: 700 });
    const afterLocation = await call('browser_evaluate', {
      sessionId,
      script: 'return location.href;',
    });

    check(
      'browser_evaluate location.href to out-of-scope origin is blocked',
      !afterLocation.includes(`${OUT_OF_SCOPE_ORIGIN}/via-location`) &&
        outOfScope.hits.length === 0,
      `location is now ${afterLocation} | out-of-scope hits: ${outOfScope.hits.length}`,
    );

    await call('browser_navigate', { sessionId, url: `${IN_SCOPE_ORIGIN}/` });

    const iframeAttempt = await call('browser_evaluate', {
      sessionId,
      script: `return new Promise((resolve) => {
        const frame = document.createElement('iframe');
        frame.onload = () => resolve('iframe onload fired');
        frame.onerror = () => resolve('iframe onerror fired');
        frame.src = '${OUT_OF_SCOPE_ORIGIN}/via-iframe';
        document.body.appendChild(frame);
        setTimeout(() => resolve('iframe timed out'), 1500);
      });`,
    });

    check(
      'browser_evaluate <iframe> to out-of-scope origin is blocked',
      outOfScope.hits.length === 0,
      `${iframeAttempt} | out-of-scope hits: ${outOfScope.hits.length}`,
    );

    const windowOpenAttempt = await call('browser_evaluate', {
      sessionId,
      script: `window.open('${OUT_OF_SCOPE_ORIGIN}/via-window-open'); return 'opened';`,
    });

    await call('browser_wait_for_timeout', { sessionId, milliseconds: 700 });

    check(
      'browser_evaluate window.open() to out-of-scope origin is blocked (new pages inherit the route)',
      outOfScope.hits.length === 0,
      `${windowOpenAttempt} | out-of-scope hits: ${outOfScope.hits.length}`,
    );

    const xhrAttempt = await call('browser_evaluate', {
      sessionId,
      script: `return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.onload = () => resolve('XHR REACHED IT: ' + xhr.status);
        xhr.onerror = () => resolve('xhr error');
        xhr.open('GET', '${OUT_OF_SCOPE_ORIGIN}/via-xhr');
        xhr.send();
        setTimeout(() => resolve('xhr timed out'), 1500);
      });`,
    });

    check(
      'browser_evaluate XMLHttpRequest to out-of-scope origin is blocked',
      !xhrAttempt.includes('XHR REACHED IT') && outOfScope.hits.length === 0,
      `${xhrAttempt} | out-of-scope hits: ${outOfScope.hits.length}`,
    );

    const beaconAttempt = await call('browser_evaluate', {
      sessionId,
      script: `return String(navigator.sendBeacon('${OUT_OF_SCOPE_ORIGIN}/via-beacon', 'x'));`,
    });

    await call('browser_wait_for_timeout', { sessionId, milliseconds: 500 });

    check(
      'browser_evaluate navigator.sendBeacon to out-of-scope origin is blocked',
      outOfScope.hits.length === 0,
      `sendBeacon returned ${beaconAttempt} | out-of-scope hits: ${outOfScope.hits.length}`,
    );

    // ---------------------------------------------------------------- WebSocket
    console.log('\n== WebSocket (context.route does not cover these; routeWebSocket does) ==');

    const wsBlocked = await call('browser_evaluate', {
      sessionId,
      script: `return new Promise((resolve) => {
        const socket = new WebSocket('ws://127.0.0.1:${OUT_OF_SCOPE_PORT}/ws');
        socket.onopen = () => resolve('WS OPENED');
        socket.onerror = () => resolve('ws error');
        socket.onclose = (e) => resolve('ws closed code=' + e.code);
        setTimeout(() => resolve('ws timed out'), 2000);
      });`,
    });

    check(
      'WebSocket to out-of-scope origin never reaches the server',
      !wsBlocked.includes('WS OPENED') && outOfScope.upgrades.length === 0,
      `${wsBlocked} | out-of-scope upgrades: ${outOfScope.upgrades.length}`,
    );

    const wsAllowed = await call('browser_evaluate', {
      sessionId,
      script: `return new Promise((resolve) => {
        const socket = new WebSocket('ws://127.0.0.1:${IN_SCOPE_PORT}/ws');
        socket.onopen = () => resolve('ws opened');
        socket.onerror = () => resolve('ws error');
        socket.onclose = (e) => resolve('ws closed code=' + e.code);
        setTimeout(() => resolve('ws timed out'), 2000);
      });`,
    });

    check(
      'WebSocket to the in-scope origin still works',
      wsAllowed.includes('ws opened') && inScope.upgrades.length > 0,
      `${wsAllowed} | in-scope upgrades: ${inScope.upgrades.length}`,
    );

    // ---------------------------------------------------------------- WebRTC / raw UDP
    console.log('\n== WebRTC (raw UDP: below context.route(), and invisible to an HTTP proxy) ==');

    const webrtcAttempt = await call('browser_evaluate', {
      sessionId,
      script: `return (async () => {
        try {
          const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:127.0.0.1:${OUT_OF_SCOPE_UDP_PORT}' }] });
          pc.createDataChannel('x');
          await pc.setLocalDescription(await pc.createOffer());
          await new Promise(r => setTimeout(r, 2000));
          return 'REACHED: iceGatheringState=' + pc.iceGatheringState;
        } catch (e) { return 'blocked: ' + e.message; }
      })();`,
    });

    check(
      'WebRTC cannot send UDP to an out-of-scope host:port',
      !webrtcAttempt.includes('REACHED') && udpPackets.length === 0,
      `${webrtcAttempt} | UDP packets at 127.0.0.1:${OUT_OF_SCOPE_UDP_PORT}: ${udpPackets.length}`,
    );

    // ---------------------------------------------------------------- file://
    console.log('\n== file:// (the read the evaluation demonstrated) ==');

    const fileUrl = pathToFileURL(secretFile).href;
    const fileNav = await call('browser_navigate', { sessionId, url: fileUrl });

    check(
      'browser_navigate to file:// is blocked',
      fileNav.includes('Blocked by security policy') && fileNav.includes('file:'),
      fileNav,
    );

    await call('browser_navigate', { sessionId, url: `${IN_SCOPE_ORIGIN}/` });

    const fileRead = await call('browser_evaluate', {
      sessionId,
      script: `return fetch('${fileUrl}').then(r => r.text()).catch(e => 'fetch rejected: ' + e.message);`,
    });

    check(
      'browser_evaluate fetch(file://) does not return the secret',
      !fileRead.includes(secretMarker),
      fileRead,
    );

    await call('browser_evaluate', { sessionId, script: `location.href = '${fileUrl}';` });
    await call('browser_wait_for_timeout', { sessionId, milliseconds: 900 });
    const afterFileNav = await call('browser_evaluate', {
      sessionId,
      script: 'return document.documentElement.outerHTML.slice(0, 400) + " @ " + location.href;',
    });

    check(
      'browser_evaluate location.href = file:// does not expose the secret',
      !afterFileNav.includes(secretMarker),
      afterFileNav,
    );

    // ---------------------------------------------------------------- uploads
    console.log('\n== browser_upload_file directory allowlist ==');

    await call('browser_navigate', { sessionId, url: `${IN_SCOPE_ORIGIN}/upload` });

    const allowedUploadResult = await call('browser_upload_file', {
      sessionId,
      selector: '#picker',
      filePaths: [allowedUpload],
    });

    check(
      'a file inside the upload allowlist is accepted',
      !allowedUploadResult.includes('Blocked by security policy'),
      allowedUploadResult,
    );

    const outsideUploadResult = await call('browser_upload_file', {
      sessionId,
      selector: '#picker',
      filePaths: [secretFile],
    });

    check(
      'a file outside the upload allowlist is rejected',
      outsideUploadResult.includes('Blocked by security policy') &&
        outsideUploadResult.includes('outside allowedUploadDirectories'),
      outsideUploadResult,
    );

    // Built by concatenation so the literal '..' survives into the tool argument.
    const traversalPath = `${uploadsDir}${sep}..${sep}secrets${sep}cert.pem`;
    const traversalResult = await call('browser_upload_file', {
      sessionId,
      selector: '#picker',
      filePaths: [traversalPath],
    });

    check(
      'a ".." traversal out of the upload allowlist is rejected',
      traversalResult.includes('Blocked by security policy'),
      `${traversalPath} -> ${traversalResult}`,
    );

    // ---------------------------------------------------------------- service worker
    console.log('\n== service worker (known gap check) ==');

    const swHitsBefore = outOfScope.hits.length;
    const swResult = await call('browser_evaluate', {
      sessionId,
      script: `return navigator.serviceWorker.register('/sw.js')
        .then(() => 'registered')
        .catch(e => 'register failed: ' + e.message);`,
    });

    await call('browser_wait_for_timeout', { sessionId, milliseconds: 2000 });

    const swLeaked = outOfScope.hits.length > swHitsBefore;

    note(
      'service-worker-initiated fetch to an out-of-scope origin',
      swLeaked
        ? `LEAKED: the out-of-scope server saw ${outOfScope.hits.length - swHitsBefore} ` +
            `service-worker request(s). context.route() does not intercept these. ` +
            `Mitigate with contextOptions.serviceWorkers = "block".`
        : `no leak: register said "${swResult.trim()}" and the out-of-scope server saw 0 ` +
            `additional requests.`,
    );

    // ---------------------------------------------------------------- final tally
    console.log('\n== server-side ledger (the decisive evidence) ==');
    console.log(`  in-scope server     received ${inScope.hits.length} request(s): ${inScope.hits.slice(0, 8).join(', ')}`);
    console.log(`  OUT-OF-SCOPE server received ${outOfScope.hits.length} request(s): ${outOfScope.hits.join(', ') || '(none)'}`);
    console.log(`  OUT-OF-SCOPE server received ${outOfScope.upgrades.length} websocket upgrade(s)`);
    console.log(`  OUT-OF-SCOPE UDP port received ${udpPackets.length} datagram(s)`);
  } finally {
    await call('close_all_sessions', {}).catch(() => undefined);
    await client.close().catch(() => undefined);
    inScope.server.close();
    outOfScope.server.close();
    udpListener.close();
    rmSync(workspace, { recursive: true, force: true });
  }

  console.log(`\n${passed} passed, ${failed} failed`);

  if (failed > 0) {
    console.log(`failing checks: ${failures.join('; ')}`);
    process.exit(1);
  }
};

main().catch((error) => {
  console.error('Security policy smoke failed:', error);
  process.exit(1);
});
