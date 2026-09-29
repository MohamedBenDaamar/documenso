import { prisma } from '@documenso/prisma';
import { z } from 'zod';

import {
  OAUTH_CLIENT_SECRET_PREFIX,
  OAUTH_MAX_CLIENT_NAME_LENGTH,
  OAUTH_MAX_REDIRECT_URIS,
  OAUTH_TOKEN_ENDPOINT_AUTH_METHODS,
  type OAuthTokenEndpointAuthMethod,
} from '../../constants/oauth';
import { createOAuthError } from './errors';
import { isValidOAuthRedirectUri } from './oauth-utils';
import { generateOAuthId, generateOAuthSecret, hashOAuthSecret } from './tokens';

const SUPPORTED_GRANT_TYPES = new Set(['authorization_code', 'refresh_token']);

const ZRegisterClientRequestSchema = z.object({
  redirect_uris: z.array(z.unknown()).min(1).max(OAUTH_MAX_REDIRECT_URIS),
  client_name: z.string().optional(),
  token_endpoint_auth_method: z.string().optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
});

// Control and bidirectional-override characters could make a client name look like something else
// on the consent page.
const UNSAFE_NAME_CHARACTERS = /[\p{Cc}\p{Cf}]/gu;

const cleanClientName = (name: string | undefined) => {
  const cleaned = (name ?? '').replace(UNSAFE_NAME_CHARACTERS, '').trim().slice(0, OAUTH_MAX_CLIENT_NAME_LENGTH);

  return cleaned || 'Unnamed application';
};

/** RFC 7591 dynamic client registration. */
export const registerOAuthClient = async (body: unknown) => {
  const parsed = ZRegisterClientRequestSchema.safeParse(body);

  if (!parsed.success) {
    throw createOAuthError(
      'invalid_client_metadata',
      `redirect_uris must list between 1 and ${OAUTH_MAX_REDIRECT_URIS} URIs.`,
    );
  }

  const request = parsed.data;

  if (!request.redirect_uris.every(isValidOAuthRedirectUri)) {
    throw createOAuthError(
      'invalid_redirect_uri',
      'Redirect URIs must be https, http on a loopback address, or a private-use scheme, without a fragment.',
    );
  }

  const redirectUris = [...new Set(request.redirect_uris as string[])];

  const authMethod = request.token_endpoint_auth_method ?? 'none';

  if (!OAUTH_TOKEN_ENDPOINT_AUTH_METHODS.some((method) => method === authMethod)) {
    throw createOAuthError('invalid_client_metadata', `token_endpoint_auth_method ${authMethod} is not supported.`);
  }

  const grantTypes = request.grant_types ?? ['authorization_code', 'refresh_token'];

  if (!grantTypes.includes('authorization_code') || grantTypes.some((type) => !SUPPORTED_GRANT_TYPES.has(type))) {
    throw createOAuthError(
      'invalid_client_metadata',
      'Only the authorization_code and refresh_token grants are supported.',
    );
  }

  if (request.response_types?.some((type) => type !== 'code')) {
    throw createOAuthError('invalid_client_metadata', 'Only the code response type is supported.');
  }

  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  const tokenEndpointAuthMethod = authMethod as OAuthTokenEndpointAuthMethod;

  const clientSecret = tokenEndpointAuthMethod === 'none' ? null : generateOAuthSecret(OAUTH_CLIENT_SECRET_PREFIX);

  const client = await prisma.oAuthClient.create({
    data: {
      id: generateOAuthId(),
      name: cleanClientName(request.client_name),
      redirectUris,
      tokenEndpointAuthMethod,
      secretHash: clientSecret ? hashOAuthSecret(clientSecret) : null,
    },
  });

  return {
    client_id: client.id,
    client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
    ...(clientSecret ? { client_secret: clientSecret, client_secret_expires_at: 0 } : {}),
    client_name: client.name,
    redirect_uris: client.redirectUris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
  };
};
