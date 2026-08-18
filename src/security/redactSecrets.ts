/**
 * Redacts secret-shaped values out of anything that is about to leave the server in a tool
 * result -- most importantly `resolvedProviderConfig`, which is built from operator config
 * (`launchOptions`, `contextOptions`, `sessionOptions`, `proxy`) that is an arbitrary passthrough
 * record (`z.record(z.unknown())`). An operator can put a secret under any key, at any depth
 * (`launchOptions.proxy.password`, a nested `sessionOptions.auth.token`, etc.), so this walks the
 * whole structure and matches on *key semantics*, not a fixed list of exact field names -- a list
 * that only knew about `password` would still leak `proxyPassword`.
 *
 * This is deliberately generic rather than provider-specific: a new provider, or an operator
 * putting an unanticipated field into one of the passthrough records, is still covered without a
 * code change here.
 */

const REDACTED = '***redacted***';

/**
 * Substrings that mark a key as secret-shaped, matched against the key with separators and
 * casing stripped (so `proxy_password`, `ProxyPassword` and `proxy-password` all match the same
 * way `proxyPassword` does). Deliberately broad: a false positive redacts a harmless field, which
 * is a usability annoyance; a false negative leaks a credential, which is the failure this exists
 * to prevent. When in doubt, redact.
 */
const SECRET_KEY_FRAGMENTS = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'apikey',
  'accesskey',
  'accesstoken',
  'privatekey',
  'clientsecret',
  'credential',
  'authorization',
  'sessionkey',
] as const;

const normalizeKey = (key: string): string => key.toLowerCase().replace(/[^a-z0-9]/g, '');

export const isSecretKey = (key: string): boolean => {
  const normalized = normalizeKey(key);

  return SECRET_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment));
};

/**
 * Recursively redacts secret-shaped values, at any nesting depth, inside plain objects and
 * arrays.
 *
 * `null` / `undefined` values are left as-is even under a secret-shaped key, so the caller can
 * still distinguish "this is configured" (`"***redacted***"`) from "this is not set" (`null`) --
 * an agent deciding whether e.g. a proxy password is present needs that distinction, and hiding
 * it behind the same marker either way would make the response less useful without adding any
 * safety (there is nothing to leak from `null`).
 */
export const redactSecrets = <T>(value: T): T => redactValue(value) as T;

const redactValue = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(redactValue);
  }

  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {};

    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      if (isSecretKey(key)) {
        result[key] = entry === null || entry === undefined ? entry : REDACTED;
      } else {
        result[key] = redactValue(entry);
      }
    }

    return result;
  }

  return value;
};
