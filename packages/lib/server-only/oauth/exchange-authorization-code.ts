import { prisma } from '@documenso/prisma';

import { OAUTH_AUTHORIZATION_CODE_TTL_MS } from '../../constants/oauth';
import { logger } from '../../utils/logger';
import { buildTeamWhereQuery } from '../../utils/teams';
import { createOAuthError } from './errors';
import { normalizeOAuthResource, verifyPkceS256 } from './oauth-utils';
import { generateOAuthId, hashOAuthSecret, issueOAuthTokens } from './tokens';

type ExchangeAuthorizationCodeOptions = {
  clientId: string;
  code: string | null;
  redirectUri: string | null;
  codeVerifier: string | null;
  resource: string | null;
};

const invalidGrant = (description: string) => createOAuthError('invalid_grant', description);

/** The `authorization_code` grant (RFC 6749 section 4.1.3, with PKCE from RFC 7636). */
export const exchangeAuthorizationCode = async (options: ExchangeAuthorizationCodeOptions) => {
  const { clientId, code, redirectUri, codeVerifier, resource } = options;

  if (!code || !redirectUri || !codeVerifier) {
    throw createOAuthError('invalid_request', 'code, redirect_uri and code_verifier are required.');
  }

  const request = await prisma.oAuthAuthorizationRequest.findUnique({
    where: { codeHash: hashOAuthSecret(code) },
  });

  if (!request || !request.approvedAt || !request.userId || !request.teamId) {
    throw invalidGrant('The authorization code is invalid.');
  }

  if (request.clientId !== clientId) {
    throw invalidGrant('The authorization code was issued to another client.');
  }

  if (request.usedAt) {
    // A replayed code means it leaked. RFC 6749 section 4.1.2: revoke what it was used for.
    if (request.grantId) {
      await prisma.oAuthGrant.updateMany({
        where: { id: request.grantId, revokedAt: null },
        data: { revokedAt: new Date() },
      });

      logger.warn({ msg: 'OAuth authorization code reused; grant revoked', grantId: request.grantId, clientId });
    }

    throw invalidGrant('The authorization code was already used.');
  }

  if (request.approvedAt.getTime() + OAUTH_AUTHORIZATION_CODE_TTL_MS < Date.now()) {
    throw invalidGrant('The authorization code has expired.');
  }

  if (request.redirectUri !== redirectUri) {
    throw invalidGrant('redirect_uri does not match the authorization request.');
  }

  if (!verifyPkceS256(codeVerifier, request.codeChallenge)) {
    throw invalidGrant('code_verifier does not match the code challenge.');
  }

  if (resource !== null && normalizeOAuthResource(resource) !== request.resource) {
    throw createOAuthError('invalid_target', 'resource does not match the authorization request.');
  }

  const { userId, teamId } = request;

  const isMember = await prisma.team.findFirst({
    where: buildTeamWhereQuery({ teamId, userId }),
    select: { id: true },
  });

  if (!isMember) {
    throw invalidGrant('The user is no longer a member of this team.');
  }

  return await prisma.$transaction(async (tx) => {
    // Claims the code. A concurrent exchange of the same code finds `usedAt` already set.
    const { count } = await tx.oAuthAuthorizationRequest.updateMany({
      where: { id: request.id, usedAt: null },
      data: { usedAt: new Date() },
    });

    if (count === 0) {
      throw invalidGrant('The authorization code was already used.');
    }

    const grant = await tx.oAuthGrant.create({
      data: {
        id: generateOAuthId(),
        clientId,
        userId,
        teamId,
        scopes: request.scopes,
        resource: request.resource,
      },
    });

    await tx.oAuthAuthorizationRequest.update({
      where: { id: request.id },
      data: { grantId: grant.id },
    });

    return await issueOAuthTokens(tx, grant);
  });
};
