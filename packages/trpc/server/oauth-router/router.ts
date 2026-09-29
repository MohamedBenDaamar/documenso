import { router } from '../trpc';
import { findOAuthGrantsRoute } from './find-oauth-grants';
import { revokeOAuthGrantRoute } from './revoke-oauth-grant';

/**
 * Session-only routes for the applications a user connected through OAuth. They have no OpenAPI
 * meta, so neither API tokens nor OAuth tokens can call them.
 */
export const oauthRouter = router({
  findGrants: findOAuthGrantsRoute,
  revokeGrant: revokeOAuthGrantRoute,
});
