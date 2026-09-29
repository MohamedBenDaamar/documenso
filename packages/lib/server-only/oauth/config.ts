import { NEXT_PUBLIC_WEBAPP_URL } from '../../constants/app';
import { OAUTH_SCOPES, OAUTH_TOKEN_ENDPOINT_AUTH_METHODS } from '../../constants/oauth';
import { env } from '../../utils/env';
import { createOAuthError } from './errors';
import { normalizeOAuthResource } from './oauth-utils';

export const getOAuthIssuer = () => NEXT_PUBLIC_WEBAPP_URL().replace(/\/$/, '');

/**
 * The resource servers (MCP servers) that tokens may be issued for, from
 * `NEXT_PRIVATE_OAUTH_RESOURCES` (comma separated). The authorization server is off when it is empty,
 * so self-hosters opt in explicitly.
 */
export const getOAuthAllowedResources = (): string[] =>
  (env('NEXT_PRIVATE_OAUTH_RESOURCES') ?? '')
    .split(',')
    .map((value) => normalizeOAuthResource(value.trim()))
    .filter((value): value is string => value !== null);

export const isOAuthServerEnabled = () => getOAuthAllowedResources().length > 0;

/**
 * Resolves the RFC 8707 `resource` parameter to an allowed audience.
 *
 * MCP clients always send it. When a client leaves it out and only one resource is configured,
 * that resource is unambiguous and is used.
 */
export const resolveOAuthResource = (requested: string | null | undefined): string => {
  const allowed = getOAuthAllowedResources();

  if (!requested) {
    if (allowed.length === 1) {
      return allowed[0];
    }

    throw createOAuthError('invalid_target', 'The resource parameter is required.');
  }

  const resource = normalizeOAuthResource(requested);

  if (!resource || !allowed.includes(resource)) {
    throw createOAuthError('invalid_target', 'Tokens cannot be issued for this resource.');
  }

  return resource;
};

/** RFC 8414 authorization server metadata. */
export const getOAuthServerMetadata = () => {
  const issuer = getOAuthIssuer();

  return {
    issuer,
    authorization_endpoint: `${issuer}/api/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    registration_endpoint: `${issuer}/api/oauth/register`,
    revocation_endpoint: `${issuer}/api/oauth/revoke`,
    scopes_supported: [...OAUTH_SCOPES],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: [...OAUTH_TOKEN_ENDPOINT_AUTH_METHODS],
    revocation_endpoint_auth_methods_supported: [...OAUTH_TOKEN_ENDPOINT_AUTH_METHODS],
    authorization_response_iss_parameter_supported: true,
  };
};
