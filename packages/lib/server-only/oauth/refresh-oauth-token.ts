import { prisma } from '@documenso/prisma';
import { OAuthTokenType } from '@prisma/client';

import { OAUTH_SCOPES } from '../../constants/oauth';
import { logger } from '../../utils/logger';
import { buildTeamWhereQuery } from '../../utils/teams';
import { createOAuthError } from './errors';
import { normalizeOAuthResource } from './oauth-utils';
import { hashOAuthSecret, issueOAuthTokens } from './tokens';

type RefreshOAuthTokenOptions = {
  clientId: string;
  refreshToken: string | null;
  scope: string | null;
  resource: string | null;
};

const invalidGrant = (description: string) => createOAuthError('invalid_grant', description);

const revokeGrant = async (grantId: string) =>
  prisma.oAuthGrant.updateMany({
    where: { id: grantId, revokedAt: null },
    data: { revokedAt: new Date() },
  });

/**
 * The `refresh_token` grant. Refresh tokens rotate on every use, and presenting one that was
 * already used revokes the grant, because only a copy of a leaked token would be used twice
 * (OAuth 2.1 section 4.3.1).
 */
export const refreshOAuthToken = async ({ clientId, refreshToken, scope, resource }: RefreshOAuthTokenOptions) => {
  if (!refreshToken) {
    throw createOAuthError('invalid_request', 'refresh_token is required.');
  }

  const token = await prisma.oAuthToken.findUnique({
    where: { tokenHash: hashOAuthSecret(refreshToken) },
    include: { grant: true },
  });

  if (!token || token.type !== OAuthTokenType.REFRESH) {
    throw invalidGrant('The refresh token is invalid.');
  }

  const { grant } = token;

  if (grant.clientId !== clientId) {
    throw invalidGrant('The refresh token was issued to another client.');
  }

  if (grant.revokedAt) {
    throw invalidGrant('Access was revoked.');
  }

  if (token.usedAt) {
    await revokeGrant(grant.id);

    logger.warn({ msg: 'OAuth refresh token reused; grant revoked', grantId: grant.id, clientId });

    throw invalidGrant('The refresh token was already used.');
  }

  if (token.expiresAt < new Date()) {
    throw invalidGrant('The refresh token has expired.');
  }

  // RFC 6749 section 6: a refresh may never widen the scope. Narrowing is accepted but ignored,
  // which section 3.3 allows; the response's `scope` tells the client what it holds. Unknown scopes
  // such as `offline_access` are dropped here too, as they were at authorization.
  const knownScopes: readonly string[] = OAUTH_SCOPES;
  const requestedScopes = (scope ?? '').split(' ').filter((requested) => knownScopes.includes(requested));

  if (requestedScopes.some((requested) => !grant.scopes.includes(requested))) {
    throw createOAuthError('invalid_scope', 'The requested scope exceeds what the user approved.');
  }

  if (resource !== null && normalizeOAuthResource(resource) !== grant.resource) {
    throw createOAuthError('invalid_target', 'resource does not match the grant.');
  }

  const isMember = await prisma.team.findFirst({
    where: buildTeamWhereQuery({ teamId: grant.teamId, userId: grant.userId }),
    select: { id: true },
  });

  if (!isMember) {
    await revokeGrant(grant.id);

    throw invalidGrant('The user is no longer a member of this team.');
  }

  return await prisma.$transaction(async (tx) => {
    const { count } = await tx.oAuthToken.updateMany({
      where: { id: token.id, usedAt: null },
      data: { usedAt: new Date() },
    });

    if (count === 0) {
      throw invalidGrant('The refresh token was already used.');
    }

    return await issueOAuthTokens(tx, grant);
  });
};
