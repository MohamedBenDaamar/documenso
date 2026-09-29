import type { Prisma } from '@prisma/client';
import { OAuthTokenType } from '@prisma/client';
import { customAlphabet } from 'nanoid';

import {
  OAUTH_ACCESS_TOKEN_PREFIX,
  OAUTH_ACCESS_TOKEN_TTL_SECONDS,
  OAUTH_REFRESH_TOKEN_PREFIX,
  OAUTH_REFRESH_TOKEN_TTL_MS,
} from '../../constants/oauth';
import { hashString } from '../auth/hash';
import { formatOAuthScopes } from './oauth-utils';

// 40 characters from a 62 character alphabet is about 238 bits, so tokens can be stored as a
// plain SHA-512 hash: there is nothing to brute force.
const randomSecret = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 40);

export const generateOAuthSecret = (prefix: string) => `${prefix}${randomSecret()}`;

export const hashOAuthSecret = (secret: string) => hashString(secret);

export const generateOAuthId = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 32);

export type OAuthTokenResponse = {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  scope: string;
};

/** Issues a new access and refresh token pair for a grant, inside the caller's transaction. */
export const issueOAuthTokens = async (
  tx: Prisma.TransactionClient,
  grant: { id: string; scopes: string[] },
): Promise<OAuthTokenResponse> => {
  const accessToken = generateOAuthSecret(OAUTH_ACCESS_TOKEN_PREFIX);
  const refreshToken = generateOAuthSecret(OAUTH_REFRESH_TOKEN_PREFIX);

  const now = Date.now();

  await tx.oAuthToken.createMany({
    data: [
      {
        type: OAuthTokenType.ACCESS,
        tokenHash: hashOAuthSecret(accessToken),
        grantId: grant.id,
        expiresAt: new Date(now + OAUTH_ACCESS_TOKEN_TTL_SECONDS * 1000),
      },
      {
        type: OAuthTokenType.REFRESH,
        tokenHash: hashOAuthSecret(refreshToken),
        grantId: grant.id,
        expiresAt: new Date(now + OAUTH_REFRESH_TOKEN_TTL_MS),
      },
    ],
  });

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshToken,
    scope: formatOAuthScopes(grant.scopes),
  };
};
