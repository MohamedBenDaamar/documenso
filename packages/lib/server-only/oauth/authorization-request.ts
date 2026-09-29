import { prisma } from '@documenso/prisma';

import {
  OAUTH_AUTHORIZATION_CODE_PREFIX,
  OAUTH_AUTHORIZATION_REQUEST_TTL_MS,
  OAUTH_MAX_STATE_LENGTH,
} from '../../constants/oauth';
import type { AppError } from '../../errors/app-error';
import { logger } from '../../utils/logger';
import { buildTeamWhereQuery } from '../../utils/teams';
import { getOAuthIssuer, resolveOAuthResource } from './config';
import { createOAuthError, isOAuthError } from './errors';
import {
  buildOAuthRedirectUrl,
  isValidPkceChallenge,
  matchesRegisteredRedirectUri,
  parseOAuthScopes,
} from './oauth-utils';
import { generateOAuthId, generateOAuthSecret, hashOAuthSecret } from './tokens';

export type CreateAuthorizationRequestResult =
  /** Show the consent page for this request. */
  | { type: 'consent'; requestId: string }
  /** Send the browser back to the client with an error (RFC 6749 section 4.1.2.1). */
  | { type: 'redirect'; url: string }
  /**
   * The client or redirect URI could not be verified, so the browser must not be sent to it.
   * Show the error to the user instead.
   */
  | { type: 'error'; error: AppError };

const errorRedirect = (
  redirectUri: string,
  error: AppError,
  state: string | null,
): CreateAuthorizationRequestResult => ({
  type: 'redirect',
  url: buildOAuthRedirectUrl(redirectUri, {
    error: error.code,
    error_description: error.message,
    state,
    iss: getOAuthIssuer(),
  }),
});

const PRUNE_AFTER_MS = 24 * 60 * 60 * 1000;

/** Validates an `/authorize` request and stores it for the consent page. */
export const createAuthorizationRequest = async (
  params: URLSearchParams,
): Promise<CreateAuthorizationRequestResult> => {
  const clientId = params.get('client_id');
  const redirectUri = params.get('redirect_uri');

  if (!clientId) {
    return { type: 'error', error: createOAuthError('invalid_request', 'client_id is required.') };
  }

  const client = await prisma.oAuthClient.findUnique({ where: { id: clientId } });

  if (!client) {
    return { type: 'error', error: createOAuthError('invalid_client', 'This application is not registered.') };
  }

  if (!redirectUri || !matchesRegisteredRedirectUri(redirectUri, client.redirectUris)) {
    return {
      type: 'error',
      error: createOAuthError('invalid_request', 'The redirect URI is not registered for this application.'),
    };
  }

  // The redirect URI is trusted from here on, so errors go back to the client.
  const state = params.get('state');

  if (state && state.length > OAUTH_MAX_STATE_LENGTH) {
    return errorRedirect(redirectUri, createOAuthError('invalid_request', 'state is too long.'), null);
  }

  if (params.get('response_type') !== 'code') {
    return errorRedirect(
      redirectUri,
      createOAuthError('unsupported_response_type', 'Only the code response type is supported.'),
      state,
    );
  }

  const codeChallenge = params.get('code_challenge');

  if (params.get('code_challenge_method') !== 'S256' || !isValidPkceChallenge(codeChallenge)) {
    return errorRedirect(
      redirectUri,
      createOAuthError('invalid_request', 'PKCE with code_challenge_method=S256 is required.'),
      state,
    );
  }

  let resource: string;

  try {
    resource = resolveOAuthResource(params.get('resource'));
  } catch (err) {
    if (isOAuthError(err)) {
      return errorRedirect(redirectUri, err, state);
    }

    throw err;
  }

  const request = await prisma.oAuthAuthorizationRequest.create({
    data: {
      id: generateOAuthId(),
      clientId: client.id,
      redirectUri,
      scopes: parseOAuthScopes(params.get('scope')),
      state,
      codeChallenge,
      resource,
      expiresAt: new Date(Date.now() + OAUTH_AUTHORIZATION_REQUEST_TTL_MS),
    },
  });

  // Requests are only needed until their code is exchanged, plus a margin for replay detection.
  void prisma.oAuthAuthorizationRequest
    .deleteMany({ where: { expiresAt: { lt: new Date(Date.now() - PRUNE_AFTER_MS) } } })
    .catch((err) => logger.warn({ msg: 'Failed to prune OAuth authorization requests', err }));

  return { type: 'consent', requestId: request.id };
};

/** The request the consent page shows, or `null` if it expired or was already answered. */
export const getAuthorizationRequestForConsent = async (requestId: string) => {
  const request = await prisma.oAuthAuthorizationRequest.findFirst({
    where: {
      id: requestId,
      approvedAt: null,
      expiresAt: { gt: new Date() },
    },
    include: {
      client: {
        select: { id: true, name: true },
      },
    },
  });

  if (!request) {
    return null;
  }

  return {
    id: request.id,
    clientName: request.client.name,
    redirectUri: request.redirectUri,
    resource: request.resource,
    scopes: parseOAuthScopes(request.scopes.join(' ')),
  };
};

type DecideAuthorizationRequestOptions = {
  requestId: string;
  userId: number;
} & ({ decision: 'deny' } | { decision: 'approve'; teamId: number });

/**
 * Records the user's answer on the consent page and returns where to send the browser.
 *
 * On approval, the authorization code is returned in the redirect only; the database keeps its hash.
 */
export const decideAuthorizationRequest = async (options: DecideAuthorizationRequestOptions) => {
  const { requestId, userId } = options;

  const request = await prisma.oAuthAuthorizationRequest.findFirst({
    where: {
      id: requestId,
      approvedAt: null,
      expiresAt: { gt: new Date() },
    },
  });

  if (!request) {
    throw createOAuthError('invalid_request', 'This authorization request has expired. Start connecting again.');
  }

  const issuer = getOAuthIssuer();

  if (options.decision === 'deny') {
    await prisma.oAuthAuthorizationRequest.deleteMany({ where: { id: request.id, approvedAt: null } });

    return buildOAuthRedirectUrl(request.redirectUri, {
      error: 'access_denied',
      error_description: 'The user denied access.',
      state: request.state,
      iss: issuer,
    });
  }

  const team = await prisma.team.findFirst({
    where: buildTeamWhereQuery({ teamId: options.teamId, userId }),
    select: { id: true },
  });

  if (!team) {
    throw createOAuthError('access_denied', 'You are not a member of this team.', 403);
  }

  const code = generateOAuthSecret(OAUTH_AUTHORIZATION_CODE_PREFIX);

  // The `approvedAt: null` condition makes approval single use even if two tabs submit at once.
  const { count } = await prisma.oAuthAuthorizationRequest.updateMany({
    where: {
      id: request.id,
      approvedAt: null,
      expiresAt: { gt: new Date() },
    },
    data: {
      codeHash: hashOAuthSecret(code),
      approvedAt: new Date(),
      userId,
      teamId: team.id,
    },
  });

  if (count === 0) {
    throw createOAuthError('invalid_request', 'This authorization request was already answered.');
  }

  return buildOAuthRedirectUrl(request.redirectUri, {
    code,
    state: request.state,
    iss: issuer,
  });
};
