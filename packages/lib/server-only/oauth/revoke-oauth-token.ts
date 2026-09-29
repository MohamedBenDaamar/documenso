import { prisma } from '@documenso/prisma';

import { hashOAuthSecret } from './tokens';

type RevokeOAuthTokenOptions = {
  clientId: string;
  token: string | null;
};

/**
 * RFC 7009 token revocation. Revoking either token of a pair revokes the whole grant, so the
 * client cannot keep access through the other one.
 *
 * Unknown tokens and tokens of other clients are ignored without an error, as section 2.2 requires.
 */
export const revokeOAuthToken = async ({ clientId, token }: RevokeOAuthTokenOptions) => {
  if (!token) {
    return;
  }

  const record = await prisma.oAuthToken.findUnique({
    where: { tokenHash: hashOAuthSecret(token) },
    select: { grant: { select: { id: true, clientId: true } } },
  });

  if (!record || record.grant.clientId !== clientId) {
    return;
  }

  await prisma.oAuthGrant.updateMany({
    where: { id: record.grant.id, revokedAt: null },
    data: { revokedAt: new Date() },
  });
};
