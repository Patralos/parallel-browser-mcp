import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  BlockedRequestLog,
  SecurityPolicy,
  SecurityPolicyError,
  parseOriginEntry,
} from './securityPolicy.js';

const policy = (input: Partial<ConstructorParameters<typeof SecurityPolicy>[0]>): SecurityPolicy =>
  new SecurityPolicy({
    allowedOrigins: [],
    blockedOrigins: [],
    blockedSchemes: [],
    allowedUploadDirectories: [],
    ...input,
  });

describe('SecurityPolicy.evaluateUrl - origin allowlist', () => {
  it('allows an origin that is on the allowlist', () => {
    const subject = policy({ allowedOrigins: ['127.0.0.1:8899'] });

    expect(subject.evaluateUrl('http://127.0.0.1:8899/login')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('http://127.0.0.1:8899/deep/path?q=1#f')).toEqual({ allowed: true });
  });

  it('blocks an origin that is not on the allowlist, naming it', () => {
    const subject = policy({ allowedOrigins: ['127.0.0.1:8899'] });
    const decision = subject.evaluateUrl('http://127.0.0.1:8900/secret');

    expect(decision.allowed).toBe(false);
    expect(decision.allowed === false && decision.reason).toContain('http://127.0.0.1:8900');
    expect(decision.allowed === false && decision.reason).toContain('not in allowedOrigins');
  });

  it('is permissive when no allowlist is configured (documented default)', () => {
    const subject = policy({});

    expect(subject.hasOriginAllowlist).toBe(false);
    expect(subject.evaluateUrl('https://anything.example.com/')).toEqual({ allowed: true });
  });

  it('lets blockedOrigins override an otherwise permissive server', () => {
    const subject = policy({ blockedOrigins: ['evil.example.com'] });

    expect(subject.evaluateUrl('https://ok.example.com/')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('https://evil.example.com/')).toMatchObject({ allowed: false });
  });

  it('lets blockedOrigins win over allowedOrigins', () => {
    const subject = policy({
      allowedOrigins: ['*.example.com'],
      blockedOrigins: ['admin.example.com'],
    });

    expect(subject.evaluateUrl('https://app.example.com/')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('https://admin.example.com/')).toMatchObject({ allowed: false });
  });

  it('treats an entry without a port as the scheme default port only', () => {
    const subject = policy({ allowedOrigins: ['example.com'] });

    expect(subject.evaluateUrl('https://example.com/')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('http://example.com/')).toEqual({ allowed: true });
    // A non-default port was never named, so it is out of scope.
    expect(subject.evaluateUrl('https://example.com:8443/')).toMatchObject({ allowed: false });
  });

  it('supports an explicit any-port wildcard', () => {
    const subject = policy({ allowedOrigins: ['example.com:*'] });

    expect(subject.evaluateUrl('https://example.com:8443/')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('https://example.com/')).toEqual({ allowed: true });
  });

  it('matches subdomains with *. but not the apex, and not a lookalike suffix', () => {
    const subject = policy({ allowedOrigins: ['*.example.com'] });

    expect(subject.evaluateUrl('https://app.example.com/')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('https://a.b.example.com/')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('https://example.com/')).toMatchObject({ allowed: false });
    expect(subject.evaluateUrl('https://notexample.com/')).toMatchObject({ allowed: false });
    expect(subject.evaluateUrl('https://example.com.evil.net/')).toMatchObject({ allowed: false });
  });

  it('honours a scheme pinned on the entry', () => {
    const subject = policy({ allowedOrigins: ['https://example.com'] });

    expect(subject.evaluateUrl('https://example.com/')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('http://example.com/')).toMatchObject({ allowed: false });
  });

  it('matches IPv6 literals with a port', () => {
    const subject = policy({ allowedOrigins: ['[::1]:8899'] });

    expect(subject.evaluateUrl('http://[::1]:8899/')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('http://[::1]:9000/')).toMatchObject({ allowed: false });
  });

  it('applies to ws:// as well as http(s)://', () => {
    const subject = policy({ allowedOrigins: ['127.0.0.1:8899'] });

    expect(subject.evaluateUrl('ws://127.0.0.1:8899/socket')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('ws://127.0.0.1:8900/socket')).toMatchObject({ allowed: false });
  });

  it('blocks a URL it cannot parse rather than waving it through', () => {
    expect(policy({}).evaluateUrl('http://[not a url')).toMatchObject({ allowed: false });
  });
});

describe('SecurityPolicy.evaluateUrl - scheme denylist', () => {
  it('blocks file:// even with no allowlist configured', () => {
    const decision = policy({}).evaluateUrl('file:///C:/Users/Patrick/cert.pem');

    expect(decision.allowed).toBe(false);
    expect(decision.allowed === false && decision.reason).toContain('file:');
  });

  it('blocks the other privileged schemes', () => {
    const subject = policy({});

    for (const url of [
      'filesystem:file:///persistent/x',
      'chrome://net-internals/',
      'chrome-untrusted://x/',
      'chrome-extension://abcdef/background.js',
      'devtools://devtools/bundled/x.html',
      'view-source:file:///C:/Users/Patrick/cert.pem',
    ]) {
      expect(subject.evaluateUrl(url), url).toMatchObject({ allowed: false });
    }
  });

  it('cannot have the built-in schemes configured away, only added to', () => {
    // Passing an empty blockedSchemes must not re-enable file://.
    expect(policy({ blockedSchemes: [] }).evaluateUrl('file:///etc/passwd')).toMatchObject({
      allowed: false,
    });

    const withExtra = policy({ blockedSchemes: ['data'] });

    expect(withExtra.evaluateUrl('data:text/html,<h1>x</h1>')).toMatchObject({ allowed: false });
    expect(withExtra.evaluateUrl('file:///etc/passwd')).toMatchObject({ allowed: false });
  });

  it('permits about:blank and about:srcdoc but no other about: URL', () => {
    const subject = policy({});

    expect(subject.evaluateUrl('about:blank')).toEqual({ allowed: true });
    expect(subject.evaluateUrl('about:srcdoc')).toEqual({ allowed: true });
    // Chromium redirects about:version into chrome://version.
    expect(subject.evaluateUrl('about:version')).toMatchObject({ allowed: false });
  });

  it('fails closed for origin-less schemes once an allowlist exists', () => {
    const permissive = policy({});
    const restricted = policy({ allowedOrigins: ['127.0.0.1:8899'] });

    expect(permissive.evaluateUrl('data:text/html,<h1>x</h1>')).toEqual({ allowed: true });
    expect(restricted.evaluateUrl('data:text/html,<h1>x</h1>')).toMatchObject({ allowed: false });
  });
});

describe('SecurityPolicy.assertNavigationAllowed', () => {
  it('throws a SecurityPolicyError naming the blocked origin', () => {
    const subject = policy({ allowedOrigins: ['127.0.0.1:8899'] });

    expect(() => subject.assertNavigationAllowed('http://127.0.0.1:8899/ok')).not.toThrow();
    expect(() => subject.assertNavigationAllowed('http://127.0.0.1:8900/no')).toThrow(
      SecurityPolicyError,
    );
    expect(() => subject.assertNavigationAllowed('http://127.0.0.1:8900/no')).toThrow(
      /http:\/\/127\.0\.0\.1:8900/,
    );
    expect(() => subject.assertNavigationAllowed('file:///C:/secret.txt')).toThrow(/file:/);
  });
});

describe('parseOriginEntry', () => {
  it('rejects malformed entries at configuration time, not silently', () => {
    expect(() => parseOriginEntry('')).toThrow(SecurityPolicyError);
    expect(() => parseOriginEntry('example.com:notaport')).toThrow(/port must be a number/);
    expect(() => parseOriginEntry('ex*ample.com')).toThrow(/only allowed as the whole host/);
    expect(() => parseOriginEntry('user@example.com')).toThrow(/userinfo/);
    expect(() => parseOriginEntry('[::1')).toThrow(/unterminated IPv6/);
  });

  it('tolerates a pasted full URL by dropping the path', () => {
    expect(parseOriginEntry('https://example.com:8443/app/login?a=1')).toMatchObject({
      scheme: 'https:',
      host: 'example.com',
      port: '8443',
    });
  });
});

describe('SecurityPolicy.resolveUploadPaths', () => {
  const root = mkdtempSync(join(tmpdir(), 'pbmcp-upload-'));
  const allowedDir = join(root, 'allowed');
  const secretDir = join(root, 'secret');
  const allowedFile = join(allowedDir, 'payload.txt');
  const nestedFile = join(allowedDir, 'nested', 'payload.txt');
  const secretFile = join(secretDir, 'cert.pem');

  mkdirSync(join(allowedDir, 'nested'), { recursive: true });
  mkdirSync(secretDir, { recursive: true });
  writeFileSync(allowedFile, 'payload');
  writeFileSync(nestedFile, 'payload');
  writeFileSync(secretFile, 'PRIVATE KEY');

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  const restricted = (): SecurityPolicy => policy({ allowedUploadDirectories: [allowedDir] });

  it('accepts a file inside an allowed directory, including nested', () => {
    expect(restricted().resolveUploadPaths([allowedFile, nestedFile])).toHaveLength(2);
  });

  it('rejects a file outside every allowed directory', () => {
    expect(() => restricted().resolveUploadPaths([secretFile])).toThrow(SecurityPolicyError);
    expect(() => restricted().resolveUploadPaths([secretFile])).toThrow(
      /outside allowedUploadDirectories/,
    );
  });

  it('rejects ".." traversal out of an allowed directory', () => {
    // Built by concatenation, not join(), so the literal '..' survives into the argument --
    // this is the string an attacker actually sends.
    const traversal = `${allowedDir}${sep}..${sep}secret${sep}cert.pem`;

    // The raw string starts with the allowed directory; only resolving it reveals the escape.
    expect(traversal.startsWith(allowedDir)).toBe(true);
    expect(() => restricted().resolveUploadPaths([traversal])).toThrow(
      /outside allowedUploadDirectories/,
    );
  });

  it('rejects a sibling directory whose name merely starts with the allowed one', () => {
    const sibling = join(root, 'allowed-elsewhere');

    mkdirSync(sibling, { recursive: true });
    writeFileSync(join(sibling, 'x.txt'), 'x');

    expect(() => restricted().resolveUploadPaths([join(sibling, 'x.txt')])).toThrow(
      /outside allowedUploadDirectories/,
    );
  });

  it('rejects a symlink inside the allowed directory that points outside it', () => {
    const link = join(allowedDir, 'link-to-secret.pem');

    try {
      symlinkSync(secretFile, link, 'file');
    } catch {
      // Creating symlinks needs elevation or Developer Mode on Windows. The realpath()
      // behaviour is identical to the ".." case above, which does run everywhere.
      return;
    }

    expect(() => restricted().resolveUploadPaths([link])).toThrow(
      /outside allowedUploadDirectories/,
    );
  });

  it('rejects a path that does not exist rather than passing it through', () => {
    expect(() => restricted().resolveUploadPaths([join(allowedDir, 'missing.txt')])).toThrow(
      /does not exist or is not readable/,
    );
  });

  it('refuses to start with an allowed directory that does not exist', () => {
    expect(() => policy({ allowedUploadDirectories: [join(root, 'nope')] })).toThrow(
      /does not exist/,
    );
  });

  it('is permissive when no upload allowlist is configured (documented default)', () => {
    const subject = policy({});

    expect(subject.hasUploadAllowlist).toBe(false);
    expect(subject.resolveUploadPaths([secretFile])).toEqual([secretFile]);
  });
});

describe('BlockedRequestLog', () => {
  it('reports only the blocks recorded since a given point', () => {
    const log = new BlockedRequestLog();
    const entry = (url: string) =>
      ({ url, reason: 'r', layer: 'route', at: 'now' }) as const;

    log.record(entry('http://a/'));
    const mark = log.total;
    log.record(entry('http://b/'));
    log.record(entry('http://c/'));

    expect(log.total).toBe(3);
    expect(log.since(mark).map((blocked) => blocked.url)).toEqual(['http://b/', 'http://c/']);
    expect(log.since(log.total)).toEqual([]);
  });

  it('bounds retention but keeps counting', () => {
    const log = new BlockedRequestLog();

    for (let index = 0; index < 250; index += 1) {
      log.record({ url: `http://a/${index}`, reason: 'r', layer: 'route', at: 'now' });
    }

    expect(log.total).toBe(250);
    expect(log.since(0)).toHaveLength(200);
  });
});
