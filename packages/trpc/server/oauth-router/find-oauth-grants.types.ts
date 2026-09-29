import { OAUTH_SCOPES } from '@documenso/lib/constants/oauth';
import { z } from 'zod';

export const ZFindOAuthGrantsRequestSchema = z.void();

export const ZFindOAuthGrantsResponseSchema = z.array(
  z.object({
    id: z.string(),
    clientName: z.string(),
    team: z.object({
      id: z.number(),
      name: z.string(),
      url: z.string(),
    }),
    scopes: z.array(z.enum(OAUTH_SCOPES)),
    resource: z.string(),
    createdAt: z.date(),
    lastUsedAt: z.date().nullable(),
  }),
);

export type TFindOAuthGrantsResponse = z.infer<typeof ZFindOAuthGrantsResponseSchema>;
