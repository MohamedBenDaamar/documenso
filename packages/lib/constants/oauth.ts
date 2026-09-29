/**
 * OAuth 2.1 authorization server settings.
 *
 * Tokens issued here are team-scoped, like API tokens, but each one is also limited to the
 * scopes the user approved. See `OAUTH_API_PROCEDURE_SCOPES` for what each scope unlocks.
 */

export const OAUTH_SCOPES = ['envelopes:read', 'envelopes:write', 'envelopes:send'] as const;

export type OAuthScope = (typeof OAUTH_SCOPES)[number];

export const OAUTH_DEFAULT_SCOPES: OAuthScope[] = ['envelopes:read'];

/**
 * The only API v2 procedures an OAuth access token can call, keyed by tRPC path.
 *
 * Anything not listed is refused for OAuth tokens, so a new API route never becomes
 * reachable by third-party applications without an explicit decision here.
 */
export const OAUTH_API_PROCEDURE_SCOPES: Record<string, OAuthScope> = {
  'envelope.find': 'envelopes:read',
  'envelope.get': 'envelopes:read',
  // `envelope.use` with `distributeDocument: true` additionally requires `envelopes:send`.
  'envelope.use': 'envelopes:write',
  'envelope.distribute': 'envelopes:send',
};

export const OAUTH_ACCESS_TOKEN_PREFIX = 'doa_';
export const OAUTH_REFRESH_TOKEN_PREFIX = 'dor_';
export const OAUTH_AUTHORIZATION_CODE_PREFIX = 'dac_';
export const OAUTH_CLIENT_SECRET_PREFIX = 'dcs_';

/** Time a user has to sign in and approve, which can include signing up. */
export const OAUTH_AUTHORIZATION_REQUEST_TTL_MS = 30 * 60 * 1000;

/** Time between approval and the code exchange. */
export const OAUTH_AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;

export const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 60 * 60;

export const OAUTH_REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export const OAUTH_TOKEN_ENDPOINT_AUTH_METHODS = ['none', 'client_secret_post', 'client_secret_basic'] as const;

export type OAuthTokenEndpointAuthMethod = (typeof OAUTH_TOKEN_ENDPOINT_AUTH_METHODS)[number];

export const OAUTH_MAX_REDIRECT_URIS = 10;
export const OAUTH_MAX_REDIRECT_URI_LENGTH = 2000;
export const OAUTH_MAX_CLIENT_NAME_LENGTH = 100;
export const OAUTH_MAX_STATE_LENGTH = 1000;
