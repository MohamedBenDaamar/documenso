import { authClient } from '@documenso/auth/client';
import { getOptionalSession } from '@documenso/auth/server/lib/utils/get-session';
import { formatPath } from '@documenso/lib/constants/app';
import { OAUTH_SCOPE_DESCRIPTIONS } from '@documenso/lib/constants/oauth-translations';
import { getAuthorizationRequestForConsent } from '@documenso/lib/server-only/oauth/authorization-request';
import { buildTeamWhereQuery } from '@documenso/lib/utils/teams';
import { prisma } from '@documenso/prisma';
import { Alert, AlertDescription } from '@documenso/ui/primitives/alert';
import { Button } from '@documenso/ui/primitives/button';
import { Label } from '@documenso/ui/primitives/label';
import { RadioGroup, RadioGroupItem } from '@documenso/ui/primitives/radio-group';
import { msg } from '@lingui/core/macro';
import { Trans, useLingui } from '@lingui/react/macro';
import { CheckIcon } from 'lucide-react';
import { useState } from 'react';
import { Link, redirect } from 'react-router';

import { appMetaTags } from '~/utils/meta';

import type { Route } from './+types/oauth.consent';

/**
 * Consent page of the OAuth authorization server (`/api/oauth/authorize` redirects here).
 *
 * It lives in the unauthenticated layout for its centred card, and checks the session itself so it
 * can send signed-out users to sign in and back.
 */

export function meta() {
  return appMetaTags(msg`Authorize application`);
}

/** How the redirect target is shown to the user: the host for web apps, the scheme for native apps. */
const describeRedirectUri = (redirectUri: string) => {
  const url = new URL(redirectUri);

  return url.protocol === 'https:' ? url.host : `${url.protocol}//${url.host}`;
};

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);

  const requestId = url.searchParams.get('request');
  const error = url.searchParams.get('error');

  if (error || !requestId) {
    return { state: 'Invalid', error: error ?? 'invalid_request' } as const;
  }

  const { user } = await getOptionalSession(request);

  if (!user) {
    throw redirect(`/signin?returnTo=${encodeURIComponent(`/oauth/consent?request=${requestId}`)}`);
  }

  const authorization = await getAuthorizationRequestForConsent(requestId);

  if (!authorization) {
    return { state: 'Expired' } as const;
  }

  const teams = await prisma.team.findMany({
    where: buildTeamWhereQuery({ teamId: undefined, userId: user.id }),
    select: {
      id: true,
      name: true,
      organisation: { select: { name: true } },
    },
    orderBy: { name: 'asc' },
  });

  return {
    state: 'Pending',
    requestId: authorization.id,
    clientName: authorization.clientName,
    redirectTarget: describeRedirectUri(authorization.redirectUri),
    resourceHost: new URL(authorization.resource).host,
    scopes: authorization.scopes,
    userEmail: user.email,
    teams: teams.map((team) => ({ id: team.id, name: team.name, organisationName: team.organisation.name })),
  } as const;
}

export default function OAuthConsentPage({ loaderData }: Route.ComponentProps) {
  if (loaderData.state === 'Invalid') {
    return (
      <ConsentMessage
        title={<Trans>Invalid authorization link</Trans>}
        description={
          loaderData.error === 'invalid_client' ? (
            <Trans>This application is not registered with Documenso. Try connecting again from the application.</Trans>
          ) : (
            <Trans>
              This authorization link is not valid. Start connecting again from the application you came from.
            </Trans>
          )
        }
      />
    );
  }

  if (loaderData.state === 'Expired') {
    return (
      <ConsentMessage
        title={<Trans>Authorization request expired</Trans>}
        description={
          <Trans>
            This request has expired or was already answered. Start connecting again from the application you came from.
          </Trans>
        }
      />
    );
  }

  return <ConsentForm {...loaderData} />;
}

type ConsentMessageProps = {
  title: React.ReactNode;
  description: React.ReactNode;
};

const ConsentMessage = ({ title, description }: ConsentMessageProps) => (
  <div className="w-screen max-w-lg px-4">
    <h1 className="font-semibold text-4xl">{title}</h1>

    <p className="mt-2 mb-4 text-muted-foreground text-sm">{description}</p>

    <Button asChild>
      <Link to="/">
        <Trans>Go to Documenso</Trans>
      </Link>
    </Button>
  </div>
);

type ConsentFormProps = Extract<Route.ComponentProps['loaderData'], { state: 'Pending' }>;

const ConsentForm = ({
  requestId,
  clientName,
  redirectTarget,
  resourceHost,
  scopes,
  userEmail,
  teams,
}: ConsentFormProps) => {
  const { t, i18n } = useLingui();

  const [teamId, setTeamId] = useState<string | undefined>(teams.length === 1 ? String(teams[0].id) : undefined);
  const [pendingDecision, setPendingDecision] = useState<'approve' | 'deny' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async (decision: 'approve' | 'deny') => {
    setPendingDecision(decision);
    setError(null);

    try {
      const response = await fetch(formatPath('/api/oauth/authorize/decision'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          decision === 'approve' ? { requestId, decision, teamId: Number(teamId) } : { requestId, decision },
        ),
      });

      const body = await response.json().catch(() => null);

      if (response.ok && typeof body?.redirectTo === 'string') {
        // A navigation rather than a form redirect: the page's CSP only allows forms to post to Documenso.
        window.location.assign(body.redirectTo);
        return;
      }

      setError(typeof body?.error_description === 'string' ? body.error_description : t`Something went wrong.`);
    } catch {
      setError(t`Something went wrong.`);
    }

    setPendingDecision(null);
  };

  return (
    <div className="w-screen max-w-lg px-4">
      <h1 className="font-semibold text-3xl">
        <Trans>Connect {clientName} to Documenso</Trans>
      </h1>

      <p className="mt-2 text-muted-foreground text-sm">
        <Trans>
          <strong className="text-foreground">{clientName}</strong> wants to use your Documenso account through{' '}
          <strong className="text-foreground">{resourceHost}</strong>.
        </Trans>
      </p>

      <p className="mt-2 text-muted-foreground text-sm">
        <Trans>Signed in as {userEmail}.</Trans>{' '}
        <button
          type="button"
          className="text-documenso-700 underline underline-offset-2 hover:text-documenso-600"
          onClick={() =>
            void authClient.signOut({
              redirectPath: formatPath(`/signin?returnTo=${encodeURIComponent(`/oauth/consent?request=${requestId}`)}`),
            })
          }
        >
          <Trans>Use another account</Trans>
        </button>
      </p>

      <section className="mt-6">
        <h2 className="font-medium text-sm">
          <Trans>Team</Trans>
        </h2>

        {teams.length === 0 ? (
          <p className="mt-2 text-muted-foreground text-sm">
            <Trans>You are not a member of any team yet. Join or create a team, then connect again.</Trans>
          </p>
        ) : (
          <RadioGroup className="mt-2 gap-2" value={teamId} onValueChange={setTeamId}>
            {teams.map((team) => (
              <Label
                key={team.id}
                htmlFor={`team-${team.id}`}
                className="flex cursor-pointer items-center gap-3 rounded-lg border border-border px-4 py-3 font-normal hover:bg-muted/50"
              >
                <RadioGroupItem id={`team-${team.id}`} value={String(team.id)} />
                <span className="flex flex-col">
                  <span className="font-medium">{team.name}</span>
                  <span className="text-muted-foreground text-xs">{team.organisationName}</span>
                </span>
              </Label>
            ))}
          </RadioGroup>
        )}
      </section>

      <section className="mt-6">
        <h2 className="font-medium text-sm">
          <Trans>{clientName} will be able to</Trans>
        </h2>

        <ul className="mt-2 space-y-2">
          {scopes.map((scope) => (
            <li key={scope} className="flex items-start gap-2 text-sm">
              <CheckIcon className="mt-0.5 h-4 w-4 flex-shrink-0 text-documenso-700" />
              <span>{i18n._(OAUTH_SCOPE_DESCRIPTIONS[scope])}</span>
            </li>
          ))}
        </ul>

        <p className="mt-3 text-muted-foreground text-xs">
          <Trans>
            Access is limited to the team you choose and to what your role in that team allows. You can revoke it at any
            time from your security settings.
          </Trans>
        </p>
      </section>

      <p className="mt-6 text-muted-foreground text-xs">
        <Trans>
          After you choose, you will be sent to <strong className="text-foreground">{redirectTarget}</strong>. Only
          allow access if you trust this application.
        </Trans>
      </p>

      {error && (
        <Alert variant="destructive" className="mt-4">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="mt-6 flex justify-end gap-3">
        <Button
          type="button"
          variant="secondary"
          disabled={pendingDecision !== null}
          loading={pendingDecision === 'deny'}
          onClick={() => void submit('deny')}
        >
          <Trans>Deny</Trans>
        </Button>

        <Button
          type="button"
          disabled={pendingDecision !== null || !teamId}
          loading={pendingDecision === 'approve'}
          onClick={() => void submit('approve')}
        >
          <Trans>Allow access</Trans>
        </Button>
      </div>
    </div>
  );
};
