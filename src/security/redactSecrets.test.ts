import { describe, expect, it } from 'vitest';
import { isSecretKey, redactSecrets } from './redactSecrets.js';

describe('redactSecrets', () => {
  it('redacts an exact-name secret key at the top level', () => {
    expect(redactSecrets({ apiKey: 'sk-live-abc123' })).toEqual({ apiKey: '***redacted***' });
  });

  it('redacts by key semantics, not an exact-name list -- proxyPassword is not "password"', () => {
    // This is the case the brief calls out by name: a list that only knew about `password`
    // would still leak `proxyPassword`.
    const input = {
      launchOptions: {
        proxy: {
          server: 'http://127.0.0.1:9081',
          username: 'burpuser',
          proxyPassword: 'S3cretProxyPw',
        },
      },
    };

    expect(redactSecrets(input)).toEqual({
      launchOptions: {
        proxy: {
          server: 'http://127.0.0.1:9081',
          username: 'burpuser',
          proxyPassword: '***redacted***',
        },
      },
    });
  });

  it('reproduces the evaluator-reported leak: launchOptions.proxy.password', () => {
    const input = {
      launchOptions: {
        headless: true,
        proxy: {
          server: 'http://127.0.0.1:9081',
          bypass: '',
          username: 'burpuser',
          password: 'S3cretProxyPw',
        },
      },
      contextOptions: { ignoreHTTPSErrors: true },
    };

    const redacted = redactSecrets(input) as typeof input;

    expect(redacted.launchOptions.proxy.password).toBe('***redacted***');
    expect(redacted.launchOptions.proxy.username).toBe('burpuser');
    expect(redacted.launchOptions.headless).toBe(true);
    expect(redacted.contextOptions).toEqual({ ignoreHTTPSErrors: true });
  });

  it('redacts at arbitrary depth, including inside arrays', () => {
    const input = {
      sessionOptions: {
        auth: [{ kind: 'bearer', token: 'eyJabc' }, { kind: 'none' }],
      },
    };

    expect(redactSecrets(input)).toEqual({
      sessionOptions: {
        auth: [{ kind: 'bearer', token: '***redacted***' }, { kind: 'none' }],
      },
    });
  });

  it('matches regardless of separator style and casing', () => {
    const input = {
      Api_Key: 'a',
      'client-secret': 'b',
      ACCESSTOKEN: 'c',
      private_key: 'd',
    };

    expect(redactSecrets(input)).toEqual({
      Api_Key: '***redacted***',
      'client-secret': '***redacted***',
      ACCESSTOKEN: '***redacted***',
      private_key: '***redacted***',
    });
  });

  it('leaves null and undefined secret values as-is, so absence stays visible', () => {
    expect(redactSecrets({ apiKey: null })).toEqual({ apiKey: null });
    expect(redactSecrets({ apiKey: undefined })).toEqual({ apiKey: undefined });
  });

  it('does not touch non-secret keys or primitive/array values', () => {
    const input = { headless: true, args: ['--no-sandbox'], contextId: 'ctx_123' };

    expect(redactSecrets(input)).toEqual(input);
  });

  it('handles primitives, null and arrays passed at the top level', () => {
    expect(redactSecrets(null)).toBeNull();
    expect(redactSecrets(42)).toBe(42);
    expect(redactSecrets('plain string')).toBe('plain string');
    expect(redactSecrets([{ password: 'x' }, { ok: true }])).toEqual([
      { password: '***redacted***' },
      { ok: true },
    ]);
  });

  describe('isSecretKey', () => {
    it('matches known secret-shaped fragments', () => {
      for (const key of [
        'password',
        'proxyPassword',
        'apiKey',
        'api_key',
        'token',
        'accessToken',
        'secret',
        'clientSecret',
        'privateKey',
        'credential',
      ]) {
        expect(isSecretKey(key)).toBe(true);
      }
    });

    it('does not flag ordinary configuration keys', () => {
      for (const key of ['headless', 'contextId', 'keepAlive', 'username', 'server', 'bypass']) {
        expect(isSecretKey(key)).toBe(false);
      }
    });
  });
});
