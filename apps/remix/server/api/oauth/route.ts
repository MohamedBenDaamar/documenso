import { getOptionalSession } from '@documenso/auth/server/lib/utils/get-session';
import { NEXT_PUBLIC_WEBAPP_URL } from '@documenso/lib/constants/app';
import { AppError } from '@documenso/lib/errors/app-error';
import { authenticateOAuthClient } from '@documenso/lib/server-only/oauth/authenticate-client';
import {
  createAuthorizationRequest,
  decideAuthorizationRequest,
} from '@documenso/lib/server-only/oauth/authorization-request';
import { getOAuthIssuer, isOAuthServerEnabled } from '@documenso/lib/server-only/oauth/config';
import { createOAuthError, isOAuthError, toOAuthErrorBody } from '@documenso/lib/server-only/oauth/errors';
import { exchangeAuthorizationCode } from '@documenso/lib/server-only/oauth/exchange-authorization-code';
import { getOAuthAccessToken } from '@documenso/lib/server-only/oauth/get-oauth-access-token';
import { formatOAuthScopes, isOAuthAccessToken } from '@documenso/lib/server-only/oauth/oauth-utils';
import { refreshOAuthToken } from '@documenso/lib/server-only/oauth/refresh-oauth-token';
import { registerOAuthClient } from '@documenso/lib/server-only/oauth/register-client';
import { revokeOAuthToken } from '@documenso/lib/server-only/oauth/revoke-oauth-token';
import { createRateLimitMiddleware } from '@documenso/lib/server-only/rate-limit/rate-limit-middleware';
import {
  oauthAuthorizeRateLimit,
  oauthRegisterRateLimit,
  oauthTokenInfoRateLimit,
  oauthTokenRateLimit,
} from '@documenso/lib/server-only/rate-limit/rate-limits';
import type { Context } from 'hono';
import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { cors } from 'hono/cors';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { z } from 'zod';

import type { HonoEnv } from '../../router';

const NO_STORE_HEADERS = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

/** Every request body these endpoints accept is a few hundred bytes. */
const MAX_BODY_BYTES = 16 * 1024;

// Counted while streaming, so a request without Content-Length cannot get past it.
const limitBody = bodyLimit({
  maxSize: MAX_BODY_BYTES,
  onError: (c) => c.json({ error: 'invalid_request', error_description: 'Request body too large.' }, 413),
});

// The token, registration, revocation and token info endpoints are called by applications, not
// browsers carrying Documenso cookies, so any origin may call them.
const applicationCors = cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Authorization', 'Content-Type', 'MCP-Protocol-Version'],
  exposeHeaders: ['WWW-Authenticate'],
});

const oauthErrorResponse = (c: Context, err: unknown) => {
  if (isOAuthError(err)) {
    const headers: Record<string, string> = { ...NO_STORE_HEADERS };

    if (err.statusCode === 401) {
      headers['WWW-Authenticate'] = 'Basic realm="oauth"';
    }

    // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
    return c.json(toOAuthErrorBody(err), (err.statusCode ?? 400) as ContentfulStatusCode, headers);
  }

  c.get('logger').error({ msg: 'OAuth endpoint failed', err });

  return c.json({ error: 'server_error', error_description: 'Something went wrong.' }, 500, NO_STORE_HEADERS);
};

const readForm = async (c: Context) => {
  if (!c.req.header('Content-Type')?.startsWith('application/x-www-form-urlencoded')) {
    throw createOAuthError('invalid_request', 'The request body must be application/x-www-form-urlencoded.');
  }

  return new URLSearchParams(await c.req.text());
};

/**
 * A form post from the consent page must come from Documenso itself. The session cookie is
 * `SameSite=None` on https deployments, so the cookie alone does not prove that.
 */
const isSameOriginRequest = (c: Context) => {
  const origin = c.req.header('Origin');

  if (origin) {
    return origin === new URL(NEXT_PUBLIC_WEBAPP_URL()).origin;
  }

  return c.req.header('Sec-Fetch-Site') === 'same-origin';
};

const ZDecisionRequestSchema = z.discriminatedUnion('decision', [
  z.object({ requestId: z.string().min(1).max(64), decision: z.literal('deny') }),
  z.object({ requestId: z.string().min(1).max(64), decision: z.literal('approve'), teamId: z.number().int() }),
]);

export const oauthRoute = new Hono<HonoEnv>()
  .use('*', async (c, next) => {
    if (!isOAuthServerEnabled()) {
      return c.json({ error: 'not_found', error_description: 'The OAuth server is not enabled.' }, 404);
    }

    await next();
  })
  .use('/register', applicationCors)
  .use('/token', applicationCors)
  .use('/revoke', applicationCors)
  .use('/tokeninfo', applicationCors)

  /**
   * RFC 7591 dynamic client registration.
   */
  .post('/register', createRateLimitMiddleware(oauthRegisterRateLimit), limitBody, async (c) => {
    try {
      const body = await c.req.json().catch(() => {
        throw createOAuthError('invalid_client_metadata', 'The request body must be JSON.');
      });

      return c.json(await registerOAuthClient(body), 201, NO_STORE_HEADERS);
    } catch (err) {
      return oauthErrorResponse(c, err);
    }
  })

  /**
   * RFC 6749 authorization endpoint. Validates the request, then hands over to the consent page.
   */
  .get('/authorize', createRateLimitMiddleware(oauthAuthorizeRateLimit), async (c) => {
    const result = await createAuthorizationRequest(new URL(c.req.url).searchParams);

    c.header('Referrer-Policy', 'no-referrer');
    c.header('Cache-Control', 'no-store');

    if (result.type === 'redirect') {
      return c.redirect(result.url, 302);
    }

    const consentUrl = new URL(`${getOAuthIssuer()}/oauth/consent`);

    if (result.type === 'consent') {
      consentUrl.searchParams.set('request', result.requestId);
    } else {
      // Only the code is passed on: the consent page maps it to its own wording.
      consentUrl.searchParams.set('error', result.error.code);
    }

    return c.redirect(consentUrl.toString(), 302);
  })

  /**
   * The consent page's Allow and Deny buttons. Returns where to send the browser, because a form
   * post that redirects to another origin would be blocked by the page's `form-action 'self'` CSP.
   */
  .post('/authorize/decision', limitBody, async (c) => {
    if (!isSameOriginRequest(c)) {
      return c.json({ error: 'invalid_request', error_description: 'Cross-origin request refused.' }, 403);
    }

    const { user } = await getOptionalSession(c);

    if (!user) {
      return c.json({ error: 'access_denied', error_description: 'Sign in to continue.' }, 401);
    }

    const parsed = ZDecisionRequestSchema.safeParse(await c.req.json().catch(() => null));

    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: 'Invalid decision.' }, 400);
    }

    try {
      const redirectTo = await decideAuthorizationRequest({ ...parsed.data, userId: user.id });

      return c.json({ redirectTo }, 200, NO_STORE_HEADERS);
    } catch (err) {
      return oauthErrorResponse(c, err);
    }
  })

  /**
   * RFC 6749 token endpoint: `authorization_code` and `refresh_token` grants.
   */
  .post('/token', createRateLimitMiddleware(oauthTokenRateLimit), limitBody, async (c) => {
    try {
      const form = await readForm(c);

      const client = await authenticateOAuthClient({ form, authorizationHeader: c.req.header('Authorization') });

      const grantType = form.get('grant_type');

      if (grantType === 'authorization_code') {
        const tokens = await exchangeAuthorizationCode({
          clientId: client.id,
          code: form.get('code'),
          redirectUri: form.get('redirect_uri'),
          codeVerifier: form.get('code_verifier'),
          resource: form.get('resource'),
        });

        return c.json(tokens, 200, NO_STORE_HEADERS);
      }

      if (grantType === 'refresh_token') {
        const tokens = await refreshOAuthToken({
          clientId: client.id,
          refreshToken: form.get('refresh_token'),
          scope: form.get('scope'),
          resource: form.get('resource'),
        });

        return c.json(tokens, 200, NO_STORE_HEADERS);
      }

      throw createOAuthError('unsupported_grant_type', 'Only authorization_code and refresh_token are supported.');
    } catch (err) {
      return oauthErrorResponse(c, err);
    }
  })

  /**
   * RFC 7009 token revocation.
   */
  .post('/revoke', createRateLimitMiddleware(oauthTokenRateLimit), limitBody, async (c) => {
    try {
      const form = await readForm(c);

      const client = await authenticateOAuthClient({ form, authorizationHeader: c.req.header('Authorization') });

      await revokeOAuthToken({ clientId: client.id, token: form.get('token') });

      return c.body(null, 200, NO_STORE_HEADERS);
    } catch (err) {
      return oauthErrorResponse(c, err);
    }
  })

  /**
   * Describes the access token in the Authorization header, in RFC 7662 introspection format.
   *
   * Resource servers such as the MCP server call it to validate a token and read its audience
   * (`aud`), team and scopes. Only the token's holder can ask, and only about that token.
   */
  .get('/tokeninfo', createRateLimitMiddleware(oauthTokenInfoRateLimit), async (c) => {
    const authorization = c.req.header('Authorization') ?? '';
    const token = authorization.startsWith('Bearer ') ? authorization.slice('Bearer '.length).trim() : '';

    const inactive = () =>
      c.json({ active: false }, 401, {
        ...NO_STORE_HEADERS,
        'WWW-Authenticate': 'Bearer error="invalid_token"',
      });

    if (!isOAuthAccessToken(token)) {
      return inactive();
    }

    try {
      const accessToken = await getOAuthAccessToken({ token, bypassRateLimit: true });

      return c.json(
        {
          active: true,
          iss: getOAuthIssuer(),
          sub: String(accessToken.user.id),
          client_id: accessToken.client.id,
          team_id: accessToken.teamId,
          scope: formatOAuthScopes(accessToken.scopes),
          aud: accessToken.resource,
          iat: Math.floor(accessToken.issuedAt.getTime() / 1000),
          exp: Math.floor(accessToken.expiresAt.getTime() / 1000),
          token_type: 'Bearer',
        },
        200,
        NO_STORE_HEADERS,
      );
    } catch (err) {
      if (err instanceof AppError) {
        return inactive();
      }

      throw err;
    }
  });
