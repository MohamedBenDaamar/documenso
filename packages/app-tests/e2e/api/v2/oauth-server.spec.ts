import crypto from 'node:crypto';
import { NEXT_PUBLIC_WEBAPP_URL } from '@documenso/lib/constants/app';
import { getOAuthAllowedResources } from '@documenso/lib/server-only/oauth/config';
import { prisma } from '@documenso/prisma';
import { FieldType, TeamMemberRole } from '@documenso/prisma/client';
import { seedDraftDocument } from '@documenso/prisma/seed/documents';
import { seedTeamMember } from '@documenso/prisma/seed/teams';
import { seedUser } from '@documenso/prisma/seed/users';
import { type APIRequestContext, expect, type Page, test } from '@playwright/test';

import { apiSignin } from '../../fixtures/authentication';

const WEBAPP_URL = NEXT_PUBLIC_WEBAPP_URL();
const ORIGIN = new URL(WEBAPP_URL).origin;
const REDIRECT_URI = 'http://127.0.0.1:47823/callback';

// The server under test must list at least one resource in NEXT_PRIVATE_OAUTH_RESOURCES.
const RESOURCE = getOAuthAllowedResources()[0];

test.describe.configure({ mode: 'parallel' });

test.skip(!RESOURCE, 'NEXT_PRIVATE_OAUTH_RESOURCES is not set, so the OAuth server is disabled.');

const createPkce = () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

  return { verifier, challenge };
};

const registerClient = async (request: APIRequestContext) => {
  const res = await request.post(`${WEBAPP_URL}/api/oauth/register`, {
    data: { client_name: 'E2E client', redirect_uris: [REDIRECT_URI] },
  });

  expect(res.status()).toBe(201);

  const body = await res.json();

  return body.client_id as string;
};

const authorizeUrl = ({ clientId, challenge, scope }: { clientId: string; challenge: string; scope: string }) => {
  const url = new URL(`${WEBAPP_URL}/api/oauth/authorize`);

  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope,
    state: 'e2e-state',
    resource: RESOURCE,
  }).toString();

  return url.toString();
};

/** Signs in as `email`, starts an authorization and approves it for `teamId` through the consent endpoint. */
const approve = async ({
  page,
  email,
  teamId,
  scope = 'envelopes:read',
}: {
  page: Page;
  email: string;
  teamId: number;
  scope?: string;
}) => {
  await apiSignin({ page, email });

  const clientId = await registerClient(page.request);
  const { verifier, challenge } = createPkce();

  const authorize = await page.request.get(authorizeUrl({ clientId, challenge, scope }), { maxRedirects: 0 });

  expect(authorize.status()).toBe(302);

  const consentUrl = new URL(authorize.headers().location);
  const requestId = consentUrl.searchParams.get('request');

  expect(consentUrl.pathname).toBe('/oauth/consent');
  expect(requestId).toBeTruthy();

  const decision = await page.request.post(`${WEBAPP_URL}/api/oauth/authorize/decision`, {
    headers: { Origin: ORIGIN },
    data: { requestId, decision: 'approve', teamId },
  });

  expect(decision.status()).toBe(200);

  const redirectTo = new URL((await decision.json()).redirectTo);

  expect(`${redirectTo.origin}${redirectTo.pathname}`).toBe(REDIRECT_URI);
  expect(redirectTo.searchParams.get('state')).toBe('e2e-state');
  expect(redirectTo.searchParams.get('iss')).toBe(WEBAPP_URL.replace(/\/$/, ''));

  return { clientId, verifier, code: redirectTo.searchParams.get('code') ?? '' };
};

const exchangeCode = async (
  request: APIRequestContext,
  { clientId, code, verifier }: { clientId: string; code: string; verifier: string },
) =>
  request.post(`${WEBAPP_URL}/api/oauth/token`, {
    form: {
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      code_verifier: verifier,
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
    },
  });

const refresh = async (
  request: APIRequestContext,
  { clientId, refreshToken }: { clientId: string; refreshToken: string },
) =>
  request.post(`${WEBAPP_URL}/api/oauth/token`, {
    form: { grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshToken },
  });

const listEnvelopes = async (request: APIRequestContext, token: string) =>
  request.get(`${WEBAPP_URL}/api/v2/envelope`, { headers: { Authorization: `Bearer ${token}` } });

/** Runs the whole flow and returns a fresh token pair. */
const connect = async (options: Parameters<typeof approve>[0]) => {
  const { clientId, verifier, code } = await approve(options);

  const res = await exchangeCode(options.page.request, { clientId, code, verifier });

  expect(res.status()).toBe(200);

  return { clientId, ...(await res.json()) } as {
    clientId: string;
    access_token: string;
    refresh_token: string;
    scope: string;
    expires_in: number;
  };
};

test.describe('OAuth server - discovery and registration', () => {
  test('publishes authorization server metadata', async ({ request }) => {
    const res = await request.get(`${WEBAPP_URL}/.well-known/oauth-authorization-server`);

    expect(res.status()).toBe(200);

    const metadata = await res.json();

    expect(metadata.issuer).toBe(WEBAPP_URL.replace(/\/$/, ''));
    expect(metadata.code_challenge_methods_supported).toEqual(['S256']);
    expect(metadata.registration_endpoint).toBe(`${metadata.issuer}/api/oauth/register`);
    expect(metadata.scopes_supported).toEqual(['envelopes:read', 'envelopes:write', 'envelopes:send']);
  });

  test('refuses redirect URIs that are not https, loopback or a private-use scheme', async ({ request }) => {
    for (const redirectUri of ['http://evil.example/callback', 'javascript:alert(1)', 'https://app.example/cb#frag']) {
      const res = await request.post(`${WEBAPP_URL}/api/oauth/register`, {
        data: { redirect_uris: [redirectUri] },
      });

      expect(res.status()).toBe(400);
      expect((await res.json()).error).toBe('invalid_redirect_uri');
    }
  });

  test('issues a secret only to clients that register as confidential', async ({ request }) => {
    const res = await request.post(`${WEBAPP_URL}/api/oauth/register`, {
      data: { redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: 'client_secret_post' },
    });

    const body = await res.json();

    expect(body.client_secret).toMatch(/^dcs_/);

    // Without the secret, the confidential client cannot use the token endpoint.
    const token = await request.post(`${WEBAPP_URL}/api/oauth/token`, {
      form: { grant_type: 'refresh_token', client_id: body.client_id, refresh_token: 'dor_x' },
    });

    expect(token.status()).toBe(401);
    expect((await token.json()).error).toBe('invalid_client');
  });
});

test.describe('OAuth server - authorization endpoint', () => {
  test('shows an error page, without redirecting, for an unknown client', async ({ request }) => {
    const res = await request.get(
      authorizeUrl({ clientId: 'unknown', challenge: createPkce().challenge, scope: 'envelopes:read' }),
      { maxRedirects: 0 },
    );

    expect(res.headers().location).toBe(`${WEBAPP_URL.replace(/\/$/, '')}/oauth/consent?error=invalid_client`);
  });

  test('shows an error page for a redirect URI the client did not register', async ({ request }) => {
    const clientId = await registerClient(request);

    const url = new URL(authorizeUrl({ clientId, challenge: createPkce().challenge, scope: 'envelopes:read' }));
    url.searchParams.set('redirect_uri', 'https://evil.example/callback');

    const res = await request.get(url.toString(), { maxRedirects: 0 });

    expect(res.headers().location).toContain('/oauth/consent?error=invalid_request');
  });

  test('sends requests without PKCE back to the client with an error', async ({ request }) => {
    const clientId = await registerClient(request);

    const url = new URL(authorizeUrl({ clientId, challenge: createPkce().challenge, scope: 'envelopes:read' }));
    url.searchParams.delete('code_challenge');

    const res = await request.get(url.toString(), { maxRedirects: 0 });
    const location = new URL(res.headers().location);

    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    expect(location.searchParams.get('state')).toBe('e2e-state');
  });

  test('refuses resources that are not configured', async ({ request }) => {
    const clientId = await registerClient(request);

    const url = new URL(authorizeUrl({ clientId, challenge: createPkce().challenge, scope: 'envelopes:read' }));
    url.searchParams.set('resource', 'https://attacker.example/mcp');

    const res = await request.get(url.toString(), { maxRedirects: 0 });

    expect(new URL(res.headers().location).searchParams.get('error')).toBe('invalid_target');
  });
});

test.describe('OAuth server - consent decision', () => {
  test('refuses cross-origin posts', async ({ page }) => {
    const { user, team } = await seedUser();

    await apiSignin({ page, email: user.email });

    const res = await page.request.post(`${WEBAPP_URL}/api/oauth/authorize/decision`, {
      headers: { Origin: 'https://evil.example' },
      data: { requestId: 'x', decision: 'approve', teamId: team.id },
    });

    expect(res.status()).toBe(403);
  });

  test('refuses a team the user does not belong to', async ({ page }) => {
    const { user } = await seedUser();
    const { team: otherTeam } = await seedUser();

    await apiSignin({ page, email: user.email });

    const clientId = await registerClient(page.request);
    const authorize = await page.request.get(
      authorizeUrl({ clientId, challenge: createPkce().challenge, scope: 'envelopes:read' }),
      { maxRedirects: 0 },
    );
    const requestId = new URL(authorize.headers().location).searchParams.get('request');

    const res = await page.request.post(`${WEBAPP_URL}/api/oauth/authorize/decision`, {
      headers: { Origin: ORIGIN },
      data: { requestId, decision: 'approve', teamId: otherTeam.id },
    });

    expect(res.status()).toBe(403);
    expect((await res.json()).error).toBe('access_denied');
  });

  test('a denial redirects with access_denied', async ({ page }) => {
    const { user } = await seedUser();

    await apiSignin({ page, email: user.email });

    const clientId = await registerClient(page.request);
    const authorize = await page.request.get(
      authorizeUrl({ clientId, challenge: createPkce().challenge, scope: 'envelopes:read' }),
      { maxRedirects: 0 },
    );
    const requestId = new URL(authorize.headers().location).searchParams.get('request');

    const res = await page.request.post(`${WEBAPP_URL}/api/oauth/authorize/decision`, {
      headers: { Origin: ORIGIN },
      data: { requestId, decision: 'deny' },
    });

    const redirectTo = new URL((await res.json()).redirectTo);

    expect(redirectTo.searchParams.get('error')).toBe('access_denied');
    expect(redirectTo.searchParams.get('code')).toBeNull();
  });
});

test.describe('OAuth server - tokens and API access', () => {
  test('a token reaches only the chosen team, through the allowed procedures', async ({ page }) => {
    const { user: userA, team: teamA } = await seedUser();
    const { user: userB, team: teamB } = await seedUser();

    const documentA = await seedDraftDocument(userA, teamA.id, ['recipient-a@test.documenso.com']);
    const documentB = await seedDraftDocument(userB, teamB.id, ['recipient-b@test.documenso.com']);

    const { clientId, verifier, code } = await approve({ page, email: userA.email, teamId: teamA.id });

    // A wrong verifier is refused and does not use up the code.
    const wrongVerifier = await exchangeCode(page.request, { clientId, code, verifier: createPkce().verifier });

    expect(wrongVerifier.status()).toBe(400);
    expect((await wrongVerifier.json()).error).toBe('invalid_grant');

    const res = await exchangeCode(page.request, { clientId, code, verifier });

    expect(res.status()).toBe(200);
    expect(res.headers()['cache-control']).toBe('no-store');

    const tokens = await res.json();

    expect(tokens.token_type).toBe('Bearer');
    expect(tokens.scope).toBe('envelopes:read');
    expect(tokens.access_token).toMatch(/^doa_/);
    expect(tokens.refresh_token).toMatch(/^dor_/);

    const auth = { Authorization: `Bearer ${tokens.access_token}` };

    const list = await listEnvelopes(page.request, tokens.access_token);

    expect(list.status()).toBe(200);

    const envelopeIds = (await list.json()).data.map((envelope: { id: string }) => envelope.id);

    expect(envelopeIds).toContain(documentA.id);
    expect(envelopeIds).not.toContain(documentB.id);

    const otherTeamEnvelope = await page.request.get(`${WEBAPP_URL}/api/v2/envelope/${documentB.id}`, {
      headers: auth,
    });

    expect(otherTeamEnvelope.status()).toBe(404);

    // Sending needs envelopes:send, and the error tells the client which scope to ask for.
    const distribute = await page.request.post(`${WEBAPP_URL}/api/v2/envelope/distribute`, {
      headers: auth,
      data: { envelopeId: documentA.id },
    });

    expect(distribute.status()).toBe(403);
    expect(distribute.headers()['www-authenticate']).toContain('error="insufficient_scope"');
    expect(distribute.headers()['www-authenticate']).toContain('scope="envelopes:send"');

    const unchanged = await prisma.envelope.findUniqueOrThrow({ where: { id: documentA.id } });

    expect(unchanged.status).toBe('DRAFT');

    // Procedures outside the OAuth allowlist are refused whatever the scopes.
    const folders = await page.request.get(`${WEBAPP_URL}/api/v2/folder`, { headers: auth });

    expect(folders.status()).toBe(403);

    // The v1 API does not accept OAuth tokens at all.
    const v1 = await page.request.get(`${WEBAPP_URL}/api/v1/documents`, {
      headers: { Authorization: tokens.access_token },
    });

    expect(v1.status()).toBe(401);

    const tokenInfo = await page.request.get(`${WEBAPP_URL}/api/oauth/tokeninfo`, { headers: auth });
    const info = await tokenInfo.json();

    expect(info).toMatchObject({
      active: true,
      sub: String(userA.id),
      client_id: clientId,
      team_id: teamA.id,
      scope: 'envelopes:read',
      aud: RESOURCE,
    });
  });

  test('a token with envelopes:send can distribute', async ({ page }) => {
    const { user, team } = await seedUser();
    const document = await seedDraftDocument(user, team.id, ['recipient@test.documenso.com']);

    // Documenso only sends when every signer has a signature field.
    const [recipient, envelopeItem] = await Promise.all([
      prisma.recipient.findFirstOrThrow({ where: { envelopeId: document.id } }),
      prisma.envelopeItem.findFirstOrThrow({ where: { envelopeId: document.id } }),
    ]);

    await prisma.field.create({
      data: {
        envelopeId: document.id,
        envelopeItemId: envelopeItem.id,
        recipientId: recipient.id,
        type: FieldType.SIGNATURE,
        page: 1,
        width: 10,
        height: 5,
        customText: '',
        inserted: false,
      },
    });

    const tokens = await connect({ page, email: user.email, teamId: team.id, scope: 'envelopes:read envelopes:send' });

    expect(tokens.scope).toBe('envelopes:read envelopes:send');

    const distribute = await page.request.post(`${WEBAPP_URL}/api/v2/envelope/distribute`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
      data: { envelopeId: document.id },
    });

    expect(distribute.status()).toBe(200);

    const sent = await prisma.envelope.findUniqueOrThrow({ where: { id: document.id } });

    expect(sent.status).toBe('PENDING');
  });

  test('an authorization code works once; replaying it revokes what it granted', async ({ page }) => {
    const { user, team } = await seedUser();

    const { clientId, verifier, code } = await approve({ page, email: user.email, teamId: team.id });

    const first = await exchangeCode(page.request, { clientId, code, verifier });
    const { access_token: accessToken } = await first.json();

    expect((await listEnvelopes(page.request, accessToken)).status()).toBe(200);

    const replay = await exchangeCode(page.request, { clientId, code, verifier });

    expect(replay.status()).toBe(400);
    expect((await replay.json()).error).toBe('invalid_grant');

    expect((await listEnvelopes(page.request, accessToken)).status()).toBe(401);
  });

  test('refresh tokens rotate; reusing an old one revokes the grant', async ({ page }) => {
    const { user, team } = await seedUser();

    const tokens = await connect({ page, email: user.email, teamId: team.id });

    const rotated = await refresh(page.request, { clientId: tokens.clientId, refreshToken: tokens.refresh_token });

    expect(rotated.status()).toBe(200);

    const next = await rotated.json();

    expect(next.refresh_token).not.toBe(tokens.refresh_token);
    expect((await listEnvelopes(page.request, next.access_token)).status()).toBe(200);

    const reuse = await refresh(page.request, { clientId: tokens.clientId, refreshToken: tokens.refresh_token });

    expect(reuse.status()).toBe(400);
    expect((await reuse.json()).error).toBe('invalid_grant');

    // Both the new access token and the new refresh token are dead now.
    expect((await listEnvelopes(page.request, next.access_token)).status()).toBe(401);
    expect(
      (await refresh(page.request, { clientId: tokens.clientId, refreshToken: next.refresh_token })).status(),
    ).toBe(400);
  });

  test('a refresh cannot widen the approved scope', async ({ page }) => {
    const { user, team } = await seedUser();

    const tokens = await connect({ page, email: user.email, teamId: team.id });

    const res = await page.request.post(`${WEBAPP_URL}/api/oauth/token`, {
      form: {
        grant_type: 'refresh_token',
        client_id: tokens.clientId,
        refresh_token: tokens.refresh_token,
        scope: 'envelopes:read envelopes:send',
      },
    });

    expect(res.status()).toBe(400);
    expect((await res.json()).error).toBe('invalid_scope');
  });

  test('tokens are bound to the client they were issued to', async ({ page }) => {
    const { user, team } = await seedUser();

    const tokens = await connect({ page, email: user.email, teamId: team.id });
    const otherClientId = await registerClient(page.request);

    const res = await refresh(page.request, { clientId: otherClientId, refreshToken: tokens.refresh_token });

    expect(res.status()).toBe(400);
    expect((await res.json()).error).toBe('invalid_grant');
  });

  test('the revocation endpoint revokes the grant', async ({ page }) => {
    const { user, team } = await seedUser();

    const tokens = await connect({ page, email: user.email, teamId: team.id });

    const res = await page.request.post(`${WEBAPP_URL}/api/oauth/revoke`, {
      form: { client_id: tokens.clientId, token: tokens.refresh_token },
    });

    expect(res.status()).toBe(200);
    expect((await listEnvelopes(page.request, tokens.access_token)).status()).toBe(401);
  });

  test('access ends as soon as the user leaves the team', async ({ page }) => {
    const { team } = await seedUser();
    const member = await seedTeamMember({ teamId: team.id, role: TeamMemberRole.MEMBER });

    const tokens = await connect({ page, email: member.email, teamId: team.id });

    expect((await listEnvelopes(page.request, tokens.access_token)).status()).toBe(200);

    await prisma.organisationMember.deleteMany({
      where: { userId: member.id, organisationId: team.organisationId },
    });

    expect((await listEnvelopes(page.request, tokens.access_token)).status()).toBe(401);
  });
});
