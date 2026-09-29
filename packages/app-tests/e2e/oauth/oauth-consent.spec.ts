import crypto from 'node:crypto';
import { NEXT_PUBLIC_WEBAPP_URL } from '@documenso/lib/constants/app';
import { getOAuthAllowedResources } from '@documenso/lib/server-only/oauth/config';
import { seedUser } from '@documenso/prisma/seed/users';
import { expect, test } from '@playwright/test';

import { apiSignin } from '../fixtures/authentication';
import { waitForHydration } from '../fixtures/hydration';

const WEBAPP_URL = NEXT_PUBLIC_WEBAPP_URL();
const REDIRECT_URI = 'http://127.0.0.1:47823/callback';
const RESOURCE = getOAuthAllowedResources()[0];

test.skip(!RESOURCE, 'NEXT_PRIVATE_OAUTH_RESOURCES is not set, so the OAuth server is disabled.');

const startAuthorization = async (request: import('@playwright/test').APIRequestContext, scope: string) => {
  const registration = await request.post(`${WEBAPP_URL}/api/oauth/register`, {
    data: { client_name: 'Claude', redirect_uris: [REDIRECT_URI] },
  });

  const { client_id: clientId } = await registration.json();

  const challenge = crypto
    .createHash('sha256')
    .update(crypto.randomBytes(32).toString('base64url'))
    .digest('base64url');

  const url = new URL(`${WEBAPP_URL}/api/oauth/authorize`);

  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope,
    state: 'ui-state',
    resource: RESOURCE,
  }).toString();

  return url.toString();
};

test('[OAUTH]: signed-out users sign in, choose a team and are sent back with a code', async ({ page }) => {
  const { user, team } = await seedUser();

  const authorizeUrl = await startAuthorization(page.request, 'envelopes:read');

  // The client's redirect URI is not a real server; capture the navigation instead.
  const callback: { url: URL | null } = { url: null };

  await page.route(`${REDIRECT_URI}**`, async (route) => {
    callback.url = new URL(route.request().url());
    await route.fulfill({ status: 200, body: 'connected' });
  });

  await page.goto(authorizeUrl);

  // Signed out: the consent page sends the user to sign in and back.
  await expect(page).toHaveURL(/\/signin\?returnTo=/);
  await waitForHydration(page, 'input[name="email"]');

  await page.getByLabel('Email').fill(user.email);
  await page.getByLabel('Password', { exact: true }).fill('password');
  await page.getByRole('button', { name: 'Sign In' }).click();

  await expect(page.getByRole('heading', { name: 'Connect Claude to Documenso' })).toBeVisible();
  await waitForHydration(page, 'button[role="radio"]');
  await expect(page.getByText("View the team's documents, templates and their signing status")).toBeVisible();
  await expect(page.getByText('Send documents to recipients for signing')).toHaveCount(0);
  await expect(page.getByText(`Signed in as ${user.email}.`)).toBeVisible();

  // The user's only team is preselected.
  await expect(page.getByRole('radio', { checked: true })).toHaveAccessibleName(new RegExp(`^${team.name}`));

  await page.screenshot({ path: 'test-results/oauth-consent-page.png' });

  await page.getByRole('button', { name: 'Allow access' }).click();

  await expect.poll(() => callback.url?.searchParams.get('code') ?? null).toMatch(/^dac_/);
  expect(callback.url?.searchParams.get('state')).toBe('ui-state');
});

test('[OAUTH]: the consent page lists every requested permission and supports denying', async ({ page }) => {
  const { user } = await seedUser();

  await apiSignin({ page, email: user.email });

  const authorizeUrl = await startAuthorization(page.request, 'envelopes:read envelopes:write envelopes:send openid');

  const callback: { url: URL | null } = { url: null };

  await page.route(`${REDIRECT_URI}**`, async (route) => {
    callback.url = new URL(route.request().url());
    await route.fulfill({ status: 200, body: 'denied' });
  });

  await page.goto(authorizeUrl);
  await waitForHydration(page, 'button[type="button"]');

  await expect(page.getByText("Create draft documents from the team's templates")).toBeVisible();
  await expect(page.getByText('Send documents to recipients for signing')).toBeVisible();
  await expect(page.getByText('127.0.0.1:47823')).toBeVisible();

  await page.getByRole('button', { name: 'Deny' }).click();

  await expect.poll(() => callback.url?.searchParams.get('error') ?? null).toBe('access_denied');
});

test('[OAUTH]: an expired or reused request shows an error instead of the consent form', async ({ page }) => {
  const { user } = await seedUser();

  await apiSignin({ page, email: user.email });

  await page.goto(`${WEBAPP_URL}/oauth/consent?request=doesnotexist`);

  await expect(page.getByRole('heading', { name: 'Authorization request expired' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Allow access' })).toHaveCount(0);
});

test('[OAUTH]: users can see and revoke connected apps in their security settings', async ({ page }) => {
  const { user, team } = await seedUser();

  await apiSignin({ page, email: user.email });

  // Connect through the API to get a token, then manage it from the UI.
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

  const registration = await page.request.post(`${WEBAPP_URL}/api/oauth/register`, {
    data: { client_name: 'Claude', redirect_uris: [REDIRECT_URI] },
  });
  const { client_id: clientId } = await registration.json();

  const authorize = await page.request.get(
    `${WEBAPP_URL}/api/oauth/authorize?${new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: RESOURCE,
    })}`,
    { maxRedirects: 0 },
  );
  const requestId = new URL(authorize.headers().location).searchParams.get('request');

  const decision = await page.request.post(`${WEBAPP_URL}/api/oauth/authorize/decision`, {
    headers: { Origin: new URL(WEBAPP_URL).origin },
    data: { requestId, decision: 'approve', teamId: team.id },
  });
  const code = new URL((await decision.json()).redirectTo).searchParams.get('code') ?? '';

  const tokenResponse = await page.request.post(`${WEBAPP_URL}/api/oauth/token`, {
    form: {
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      code_verifier: verifier,
      redirect_uri: REDIRECT_URI,
    },
  });
  const { access_token: accessToken } = await tokenResponse.json();

  const listEnvelopes = async () =>
    page.request.get(`${WEBAPP_URL}/api/v2/envelope`, { headers: { Authorization: `Bearer ${accessToken}` } });

  expect((await listEnvelopes()).status()).toBe(200);

  await page.goto(`${WEBAPP_URL}/settings/security`);
  await expect(page.getByRole('link', { name: 'Manage connected apps' })).toHaveAttribute(
    'href',
    '/settings/security/connected-apps',
  );

  await page.goto(`${WEBAPP_URL}/settings/security/connected-apps`);

  const row = page.getByRole('row', { name: /Claude/ });

  await expect(row).toContainText(team.name);
  await expect(row).toContainText("View the team's documents, templates and their signing status");

  await page.screenshot({ path: 'test-results/oauth-connected-apps.png' });
  await waitForHydration(page, 'table button');

  await row.getByRole('button', { name: 'Revoke' }).click();

  await expect(page.getByText('You have not connected any applications.')).toBeVisible();
  expect((await listEnvelopes()).status()).toBe(401);
});
