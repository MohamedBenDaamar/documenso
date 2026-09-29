import { prisma } from '@documenso/prisma';
import { OAuthTokenType } from '@prisma/client';

import type { OAuthScope } from '../../constants/oauth';
import { AppError, AppErrorCode } from '../../errors/app-error';
import { logger } from '../../utils/logger';
import { buildTeamWhereQuery } from '../../utils/teams';
import { assertOrganisationRatesAndLimits } from '../rate-limit/assert-organisation-rates-and-limits';
import { getRequiredOAuthScope, parseOAuthScopes } from './oauth-utils';
import { hashOAuthSecret } from './tokens';

const LAST_USED_AT_UPDATE_INTERVAL = 60_000;

const unauthorized = (message: string) =>
  new AppError(AppErrorCode.UNAUTHORIZED, {
    message,
    statusCode: 401,
    headers: { 'WWW-Authenticate': `Bearer error="invalid_token", error_description="${message}"` },
  });

type GetOAuthAccessTokenOptions = {
  token: string;

  /**
   * Defaults to false.
   *
   * Will assert that the organisation's API request limit is not exceeded.
   */
  bypassRateLimit?: boolean;
};

/**
 * Resolves an OAuth access token to the user and team it acts for.
 *
 * Every check that applies to API tokens applies here, plus: the grant must not be revoked and the
 * user must still belong to the team. Membership is checked on each call because a removed user's
 * grant should stop working at once, not when the token expires.
 */
export const getOAuthAccessToken = async ({ token, bypassRateLimit = false }: GetOAuthAccessTokenOptions) => {
  const record = await prisma.oAuthToken.findUnique({
    where: { tokenHash: hashOAuthSecret(token) },
    include: {
      grant: {
        include: {
          client: { select: { id: true, name: true } },
          user: { select: { id: true, name: true, email: true, disabled: true } },
          team: {
            include: {
              organisation: {
                include: {
                  organisationClaim: true,
                  owner: { select: { id: true, disabled: true } },
                },
              },
            },
          },
        },
      },
    },
  });

  if (!record || record.type !== OAuthTokenType.ACCESS) {
    throw unauthorized('Invalid token');
  }

  const { grant } = record;

  if (record.expiresAt < new Date()) {
    throw unauthorized('Expired token');
  }

  if (grant.revokedAt) {
    throw unauthorized('Access was revoked');
  }

  if (grant.user.disabled || grant.team.organisation.owner.disabled) {
    throw unauthorized('User is disabled');
  }

  const isMember = await prisma.team.findFirst({
    where: buildTeamWhereQuery({ teamId: grant.teamId, userId: grant.userId }),
    select: { id: true },
  });

  if (!isMember) {
    throw unauthorized('The user is no longer a member of this team');
  }

  if (!bypassRateLimit) {
    await assertOrganisationRatesAndLimits({
      organisationId: grant.team.organisationId,
      organisationClaim: grant.team.organisation.organisationClaim,
      type: 'api',
      count: 1,
    });
  }

  if (!grant.lastUsedAt || grant.lastUsedAt.getTime() + LAST_USED_AT_UPDATE_INTERVAL < Date.now()) {
    void prisma.oAuthGrant
      .updateMany({
        where: { id: grant.id, lastUsedAt: grant.lastUsedAt },
        data: { lastUsedAt: new Date() },
      })
      .catch((err) => {
        logger.warn({ msg: 'Failed to update OAuth grant lastUsedAt', grantId: grant.id, err });
      });
  }

  return {
    grantId: grant.id,
    client: grant.client,
    user: grant.user,
    team: grant.team,
    teamId: grant.teamId,
    scopes: parseOAuthScopes(grant.scopes.join(' ')),
    resource: grant.resource,
    expiresAt: record.expiresAt,
    issuedAt: record.createdAt,
  };
};

/**
 * Throws unless an OAuth token with these scopes may call the API v2 procedure at `procedurePath`.
 *
 * A missing scope is answered with `insufficient_scope` and the scope to ask for, so MCP clients
 * can send the user back to the consent page to approve it (step-up authorization).
 */
export const assertOAuthScopeForProcedure = (procedurePath: string, scopes: readonly OAuthScope[]) => {
  const required = getRequiredOAuthScope(procedurePath);

  if (!required) {
    throw new AppError(AppErrorCode.FORBIDDEN, {
      message: 'This endpoint is not available to OAuth applications.',
      statusCode: 403,
    });
  }

  assertOAuthScope(required, scopes);
};

export const assertOAuthScope = (required: OAuthScope, scopes: readonly OAuthScope[]) => {
  if (scopes.includes(required)) {
    return;
  }

  throw new AppError(AppErrorCode.FORBIDDEN, {
    message: `This action requires the ${required} scope.`,
    statusCode: 403,
    headers: {
      'WWW-Authenticate': `Bearer error="insufficient_scope", scope="${required}", error_description="This action requires the ${required} scope."`,
    },
  });
};
