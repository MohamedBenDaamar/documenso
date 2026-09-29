import { findOAuthGrantsForUser } from '@documenso/lib/server-only/oauth/grants';

import { authenticatedProcedure } from '../trpc';
import { ZFindOAuthGrantsRequestSchema, ZFindOAuthGrantsResponseSchema } from './find-oauth-grants.types';

export const findOAuthGrantsRoute = authenticatedProcedure
  .input(ZFindOAuthGrantsRequestSchema)
  .output(ZFindOAuthGrantsResponseSchema)
  .query(async ({ ctx }) => {
    return await findOAuthGrantsForUser({ userId: ctx.user.id });
  });
