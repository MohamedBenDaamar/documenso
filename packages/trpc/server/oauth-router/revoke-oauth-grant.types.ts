import { z } from 'zod';

export const ZRevokeOAuthGrantRequestSchema = z.object({
  grantId: z.string().min(1),
});

export const ZRevokeOAuthGrantResponseSchema = z.void();
