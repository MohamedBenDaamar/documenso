import { revokeOAuthGrantForUser } from '@documenso/lib/server-only/oauth/grants';

import { authenticatedProcedure } from '../trpc';
import { ZRevokeOAuthGrantRequestSchema, ZRevokeOAuthGrantResponseSchema } from './revoke-oauth-grant.types';

export const revokeOAuthGrantRoute = authenticatedProcedure
  .input(ZRevokeOAuthGrantRequestSchema)
  .output(ZRevokeOAuthGrantResponseSchema)
  .mutation(async ({ input, ctx }) => {
    const { grantId } = input;

    ctx.logger.info({
      input: {
        grantId,
      },
    });

    await revokeOAuthGrantForUser({ userId: ctx.user.id, grantId });
  });
