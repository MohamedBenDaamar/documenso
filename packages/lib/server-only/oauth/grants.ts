import { prisma } from '@documenso/prisma';

import { AppError, AppErrorCode } from '../../errors/app-error';
import { parseOAuthScopes } from './oauth-utils';

/** Applications the user has connected and not revoked, for the settings page. */
export const findOAuthGrantsForUser = async ({ userId }: { userId: number }) => {
  const grants = await prisma.oAuthGrant.findMany({
    where: { userId, revokedAt: null },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      scopes: true,
      resource: true,
      createdAt: true,
      lastUsedAt: true,
      client: { select: { name: true } },
      team: { select: { id: true, name: true, url: true } },
    },
  });

  return grants.map((grant) => ({
    id: grant.id,
    clientName: grant.client.name,
    team: grant.team,
    scopes: parseOAuthScopes(grant.scopes.join(' ')),
    resource: grant.resource,
    createdAt: grant.createdAt,
    lastUsedAt: grant.lastUsedAt,
  }));
};

/** Revokes one of the user's grants. Its tokens stop working on their next use. */
export const revokeOAuthGrantForUser = async ({ userId, grantId }: { userId: number; grantId: string }) => {
  const { count } = await prisma.oAuthGrant.updateMany({
    where: { id: grantId, userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  if (count === 0) {
    throw new AppError(AppErrorCode.NOT_FOUND, { message: 'Connected application not found.' });
  }
};
