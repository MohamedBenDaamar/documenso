import crypto from 'node:crypto';

import {
  OAUTH_ACCESS_TOKEN_PREFIX,
  OAUTH_API_PROCEDURE_SCOPES,
  OAUTH_DEFAULT_SCOPES,
  OAUTH_MAX_REDIRECT_URI_LENGTH,
  OAUTH_SCOPES,
  type OAuthScope,
} from '../../constants/oauth';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', 'localhost']);

/** Schemes that can run code or read local data if a browser is sent to them. */
const FORBIDDEN_REDIRECT_SCHEMES = new Set(['javascript:', 'data:', 'file:', 'vbscript:', 'blob:', 'about:', 'ftp:']);

/**
 * Keeps the scopes this server knows and drops the rest, as RFC 6749 section 3.3 allows.
 *
 * Hosts often ask for OpenID scopes such as `openid` or `offline_access`. Refusing them would
 * break the connection for no security gain, since the granted scopes are returned with the token.
 */
export const parseOAuthScopes = (scope: string | null | undefined): OAuthScope[] => {
  const requested = new Set((scope ?? '').split(' ').filter(Boolean));

  const scopes = OAUTH_SCOPES.filter((known) => requested.has(known));

  return scopes.length > 0 ? scopes : [...OAUTH_DEFAULT_SCOPES];
};

export const formatOAuthScopes = (scopes: readonly string[]) => scopes.join(' ');

const isLoopbackUrl = (url: URL) => url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);

/**
 * Redirect URIs accepted at registration:
 *
 * - `https:` URLs.
 * - `http:` only on loopback hosts, for native apps (RFC 8252 section 7.3).
 * - Private-use schemes such as `cursor://`, for native apps (RFC 8252 section 7.1).
 *
 * Fragments are refused (RFC 6749 section 3.1.2), as are schemes that could run code in the browser.
 */
export const isValidOAuthRedirectUri = (value: unknown): value is string => {
  if (typeof value !== 'string' || value.length === 0 || value.length > OAUTH_MAX_REDIRECT_URI_LENGTH) {
    return false;
  }

  let url: URL;

  try {
    url = new URL(value);
  } catch {
    return false;
  }

  if (url.hash || value.includes('#')) {
    return false;
  }

  if (url.username || url.password) {
    return false;
  }

  if (url.protocol === 'https:') {
    return url.hostname.length > 0;
  }

  if (url.protocol === 'http:') {
    return isLoopbackUrl(url);
  }

  if (FORBIDDEN_REDIRECT_SCHEMES.has(url.protocol) || url.protocol === 'ws:' || url.protocol === 'wss:') {
    return false;
  }

  return /^[a-z][a-z0-9+.-]*:$/.test(url.protocol);
};

/**
 * Whether the redirect URI sent to `/authorize` matches one the client registered.
 *
 * Matching is exact, except that loopback redirect URIs may use any port, because native apps
 * pick a free port at runtime (RFC 8252 section 7.3).
 */
export const matchesRegisteredRedirectUri = (requested: string, registered: readonly string[]) => {
  if (registered.includes(requested)) {
    return true;
  }

  let requestedUrl: URL;

  try {
    requestedUrl = new URL(requested);
  } catch {
    return false;
  }

  if (!isLoopbackUrl(requestedUrl)) {
    return false;
  }

  return registered.some((candidate) => {
    try {
      const candidateUrl = new URL(candidate);

      return (
        isLoopbackUrl(candidateUrl) &&
        candidateUrl.hostname === requestedUrl.hostname &&
        candidateUrl.pathname === requestedUrl.pathname &&
        candidateUrl.search === requestedUrl.search
      );
    } catch {
      return false;
    }
  });
};

const timingSafeEqualStrings = (a: string, b: string) => {
  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);

  return bufferA.length === bufferB.length && crypto.timingSafeEqual(bufferA, bufferB);
};

/** RFC 7636: a verifier is 43 to 128 characters from the unreserved set. */
export const isValidPkceVerifier = (verifier: unknown): verifier is string =>
  typeof verifier === 'string' && /^[A-Za-z0-9._~-]{43,128}$/.test(verifier);

/** An S256 challenge is an unpadded base64url SHA-256 digest: exactly 43 characters. */
export const isValidPkceChallenge = (challenge: unknown): challenge is string =>
  typeof challenge === 'string' && /^[A-Za-z0-9_-]{43}$/.test(challenge);

export const verifyPkceS256 = (verifier: string, challenge: string) => {
  if (!isValidPkceVerifier(verifier)) {
    return false;
  }

  const computed = crypto.createHash('sha256').update(verifier).digest('base64url');

  return timingSafeEqualStrings(computed, challenge);
};

export const isOAuthAccessToken = (token: string) => token.startsWith(OAUTH_ACCESS_TOKEN_PREFIX);

/**
 * The scope an OAuth access token needs to call an API v2 procedure, or `null` when OAuth
 * tokens may not call it at all.
 */
export const getRequiredOAuthScope = (procedurePath: string): OAuthScope | null =>
  Object.hasOwn(OAUTH_API_PROCEDURE_SCOPES, procedurePath) ? OAUTH_API_PROCEDURE_SCOPES[procedurePath] : null;

/**
 * Canonical form of an RFC 8707 resource indicator, so that `https://host/mcp` and
 * `https://HOST/mcp` compare equal. Returns `null` for anything that is not an absolute URL
 * without a fragment.
 */
export const normalizeOAuthResource = (value: string | null | undefined): string | null => {
  if (!value) {
    return null;
  }

  try {
    const url = new URL(value);

    if (url.hash || (url.protocol !== 'https:' && !isLoopbackUrl(url))) {
      return null;
    }

    return url.href.replace(/\/$/, '');
  } catch {
    return null;
  }
};

/** Appends query parameters to a registered redirect URI without dropping any it already has. */
export const buildOAuthRedirectUrl = (redirectUri: string, params: Record<string, string | null | undefined>) => {
  const url = new URL(redirectUri);

  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
};
