import crypto from 'node:crypto';
import { prisma } from '@documenso/prisma';

import { createOAuthError } from './errors';
import { hashOAuthSecret } from './tokens';

type AuthenticateOAuthClientOptions = {
  /** Form body of the token or revocation request. */
  form: URLSearchParams;
  authorizationHeader: string | undefined;
};

const invalidClient = () => createOAuthError('invalid_client', 'Client authentication failed.', 401);

const readBasicCredentials = (header: string | undefined) => {
  if (!header?.startsWith('Basic ')) {
    return null;
  }

  try {
    const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');

    if (separator === -1) {
      return null;
    }

    // RFC 6749 section 2.3.1: both parts are form-urlencoded before being joined.
    return {
      clientId: decodeURIComponent(decoded.slice(0, separator)),
      clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
    };
  } catch {
    return null;
  }
};

/**
 * Identifies the client at the token and revocation endpoints, using the method it registered.
 *
 * Public clients (`none`) only send `client_id`; PKCE is what proves they started the flow.
 */
export const authenticateOAuthClient = async ({ form, authorizationHeader }: AuthenticateOAuthClientOptions) => {
  const basic = readBasicCredentials(authorizationHeader);

  const clientId = basic?.clientId ?? form.get('client_id');
  const clientSecret = basic?.clientSecret ?? form.get('client_secret');

  if (!clientId) {
    throw createOAuthError('invalid_client', 'client_id is required.', 401);
  }

  if (basic && form.get('client_id') && form.get('client_id') !== basic.clientId) {
    throw invalidClient();
  }

  const client = await prisma.oAuthClient.findUnique({ where: { id: clientId } });

  if (!client) {
    throw invalidClient();
  }

  const usedMethod = basic ? 'client_secret_basic' : clientSecret ? 'client_secret_post' : 'none';

  if (usedMethod !== client.tokenEndpointAuthMethod) {
    throw invalidClient();
  }

  if (client.secretHash) {
    const expected = Buffer.from(client.secretHash);
    const actual = Buffer.from(hashOAuthSecret(clientSecret ?? ''));

    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
      throw invalidClient();
    }
  }

  return client;
};
