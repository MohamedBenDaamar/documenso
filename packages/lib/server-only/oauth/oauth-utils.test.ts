import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  buildOAuthRedirectUrl,
  getRequiredOAuthScope,
  isValidOAuthRedirectUri,
  isValidPkceChallenge,
  matchesRegisteredRedirectUri,
  normalizeOAuthResource,
  parseOAuthScopes,
  verifyPkceS256,
} from './oauth-utils';

const challengeFor = (verifier: string) => crypto.createHash('sha256').update(verifier).digest('base64url');

describe('parseOAuthScopes', () => {
  it('keeps known scopes in canonical order', () => {
    expect(parseOAuthScopes('envelopes:send envelopes:read')).toEqual(['envelopes:read', 'envelopes:send']);
  });

  it('drops unknown scopes such as openid', () => {
    expect(parseOAuthScopes('openid offline_access envelopes:write')).toEqual(['envelopes:write']);
  });

  it('falls back to read-only when nothing known is requested', () => {
    expect(parseOAuthScopes(undefined)).toEqual(['envelopes:read']);
    expect(parseOAuthScopes('openid profile')).toEqual(['envelopes:read']);
  });
});

describe('isValidOAuthRedirectUri', () => {
  it.each([
    'https://claude.ai/api/mcp/auth_callback',
    'https://chatgpt.com/connector_platform_oauth_redirect',
    'http://localhost:6274/oauth/callback',
    'http://127.0.0.1:33418/',
    'http://[::1]:8080/callback',
    'cursor://anysphere.cursor-mcp/oauth/callback',
  ])('accepts %s', (uri) => {
    expect(isValidOAuthRedirectUri(uri)).toBe(true);
  });

  it.each([
    'http://evil.example/callback',
    'https://claude.ai/callback#fragment',
    'https://user:pass@claude.ai/callback',
    'javascript:alert(1)',
    'data:text/html,hi',
    'file:///etc/passwd',
    'wss://example.com/socket',
    '/relative/path',
    '',
    42,
    `https://example.com/${'a'.repeat(2001)}`,
  ])('refuses %s', (uri) => {
    expect(isValidOAuthRedirectUri(uri)).toBe(false);
  });
});

describe('matchesRegisteredRedirectUri', () => {
  const registered = ['https://claude.ai/api/mcp/auth_callback', 'http://127.0.0.1:3000/callback'];

  it('matches exactly', () => {
    expect(matchesRegisteredRedirectUri('https://claude.ai/api/mcp/auth_callback', registered)).toBe(true);
  });

  it('refuses near misses on https URIs', () => {
    expect(matchesRegisteredRedirectUri('https://claude.ai/api/mcp/auth_callback/', registered)).toBe(false);
    expect(matchesRegisteredRedirectUri('https://claude.ai/api/mcp/auth_callback?x=1', registered)).toBe(false);
    expect(matchesRegisteredRedirectUri('https://claude.ai:8443/api/mcp/auth_callback', registered)).toBe(false);
  });

  it('allows any port for a registered loopback URI', () => {
    expect(matchesRegisteredRedirectUri('http://127.0.0.1:51234/callback', registered)).toBe(true);
  });

  it('does not let a loopback port change reach another path or host', () => {
    expect(matchesRegisteredRedirectUri('http://127.0.0.1:51234/other', registered)).toBe(false);
    expect(matchesRegisteredRedirectUri('http://localhost:3000/callback', registered)).toBe(false);
  });
});

describe('verifyPkceS256', () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

  it('accepts the RFC 7636 appendix B example', () => {
    expect(verifyPkceS256(verifier, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')).toBe(true);
  });

  it('refuses a different verifier', () => {
    expect(verifyPkceS256(`${verifier.slice(0, -1)}x`, challengeFor(verifier))).toBe(false);
  });

  it('refuses a plain challenge that equals the verifier', () => {
    expect(verifyPkceS256(verifier, verifier)).toBe(false);
  });

  it('refuses verifiers outside the RFC 7636 length and alphabet', () => {
    const short = 'a'.repeat(42);

    expect(verifyPkceS256(short, challengeFor(short))).toBe(false);
    expect(verifyPkceS256(`${'a'.repeat(43)}!`, challengeFor(`${'a'.repeat(43)}!`))).toBe(false);
  });

  it('validates the challenge format', () => {
    expect(isValidPkceChallenge(challengeFor(verifier))).toBe(true);
    expect(isValidPkceChallenge('too-short')).toBe(false);
    expect(isValidPkceChallenge(`${challengeFor(verifier)}=`)).toBe(false);
  });
});

describe('getRequiredOAuthScope', () => {
  it('maps allowed procedures to their scope', () => {
    expect(getRequiredOAuthScope('envelope.find')).toBe('envelopes:read');
    expect(getRequiredOAuthScope('envelope.distribute')).toBe('envelopes:send');
  });

  it('refuses procedures that are not on the allowlist', () => {
    expect(getRequiredOAuthScope('envelope.delete')).toBeNull();
    expect(getRequiredOAuthScope('apiToken.create')).toBeNull();
    expect(getRequiredOAuthScope('toString')).toBeNull();
    expect(getRequiredOAuthScope('__proto__')).toBeNull();
  });
});

describe('normalizeOAuthResource', () => {
  it('normalizes case and a trailing slash', () => {
    expect(normalizeOAuthResource('https://MCP.example.com/mcp/')).toBe('https://mcp.example.com/mcp');
    expect(normalizeOAuthResource('https://mcp.example.com')).toBe('https://mcp.example.com');
  });

  it('allows loopback http for local development', () => {
    expect(normalizeOAuthResource('http://localhost:3100/mcp')).toBe('http://localhost:3100/mcp');
  });

  it('refuses non-https, fragments and junk', () => {
    expect(normalizeOAuthResource('http://mcp.example.com/mcp')).toBeNull();
    expect(normalizeOAuthResource('https://mcp.example.com/mcp#x')).toBeNull();
    expect(normalizeOAuthResource('not a url')).toBeNull();
    expect(normalizeOAuthResource('')).toBeNull();
  });
});

describe('buildOAuthRedirectUrl', () => {
  it('keeps existing query parameters and skips empty values', () => {
    expect(
      buildOAuthRedirectUrl('https://app.example/cb?tenant=1', { code: 'dac_x', state: null, iss: 'https://d' }),
    ).toBe('https://app.example/cb?tenant=1&code=dac_x&iss=https%3A%2F%2Fd');
  });
});
