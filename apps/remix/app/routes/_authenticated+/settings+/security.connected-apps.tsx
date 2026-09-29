import { OAUTH_SCOPE_DESCRIPTIONS } from '@documenso/lib/constants/oauth-translations';
import { trpc } from '@documenso/trpc/react';
import type { TFindOAuthGrantsResponse } from '@documenso/trpc/server/oauth-router/find-oauth-grants.types';
import { Button } from '@documenso/ui/primitives/button';
import type { DataTableColumnDef } from '@documenso/ui/primitives/data-table';
import { DataTable } from '@documenso/ui/primitives/data-table';
import { Skeleton } from '@documenso/ui/primitives/skeleton';
import { TableCell } from '@documenso/ui/primitives/table';
import { useToast } from '@documenso/ui/primitives/use-toast';
import { msg } from '@lingui/core/macro';
import { Trans, useLingui } from '@lingui/react/macro';
import { DateTime } from 'luxon';
import { useMemo } from 'react';

import { SettingsHeader } from '~/components/general/settings-header';
import { appMetaTags } from '~/utils/meta';

export function meta() {
  return appMetaTags(msg`Connected apps`);
}

export default function SettingsSecurityConnectedApps() {
  const { t, i18n } = useLingui();

  const { data, isLoading, isLoadingError } = trpc.oauth.findGrants.useQuery();

  const results = data ?? [];

  const columns = useMemo(() => {
    return [
      {
        header: t`Application`,
        accessorKey: 'clientName',
        cell: ({ row }) => (
          <div className="flex flex-col">
            <span className="font-medium">{row.original.clientName}</span>
            <span className="text-muted-foreground text-xs">{new URL(row.original.resource).host}</span>
          </div>
        ),
      },
      {
        header: t`Team`,
        accessorKey: 'team',
        cell: ({ row }) => row.original.team.name,
      },
      {
        header: t`Access`,
        accessorKey: 'scopes',
        cell: ({ row }) => (
          <ul className="max-w-64 space-y-1 whitespace-normal text-xs">
            {row.original.scopes.map((scope) => (
              <li key={scope}>{i18n._(OAUTH_SCOPE_DESCRIPTIONS[scope])}</li>
            ))}
          </ul>
        ),
      },
      {
        header: t`Last used`,
        accessorKey: 'lastUsedAt',
        cell: ({ row }) => (
          <div className="flex flex-col">
            <span>
              {row.original.lastUsedAt ? DateTime.fromJSDate(row.original.lastUsedAt).toRelative() : t`Never`}
            </span>
            <span className="text-muted-foreground text-xs">
              <Trans>Connected {DateTime.fromJSDate(row.original.createdAt).toRelative()}</Trans>
            </span>
          </div>
        ),
      },
      {
        id: 'actions',
        cell: ({ row }) => <RevokeGrantButton grant={row.original} />,
      },
    ] satisfies DataTableColumnDef<(typeof results)[number]>[];
  }, []);

  return (
    <div>
      <SettingsHeader
        title={t`Connected apps`}
        subtitle={t`Applications such as AI assistants that you allowed to act on one of your teams.`}
      />

      <div className="mt-4">
        <DataTable
          columns={columns}
          data={results}
          hasFilters={false}
          error={{
            enable: isLoadingError,
          }}
          emptyState={
            <div className="py-8 text-center text-muted-foreground text-sm">
              <Trans>You have not connected any applications.</Trans>
            </div>
          }
          skeleton={{
            enable: isLoading,
            rows: 2,
            component: (
              <>
                <TableCell>
                  <Skeleton className="h-4 w-32 rounded-full" />
                </TableCell>
                <TableCell>
                  <Skeleton className="h-4 w-24 rounded-full" />
                </TableCell>
                <TableCell>
                  <Skeleton className="h-4 w-40 rounded-full" />
                </TableCell>
                <TableCell>
                  <Skeleton className="h-4 w-20 rounded-full" />
                </TableCell>
                <TableCell>
                  <Skeleton className="h-8 w-16 rounded" />
                </TableCell>
              </>
            ),
          }}
        />
      </div>
    </div>
  );
}

type RevokeGrantButtonProps = {
  grant: TFindOAuthGrantsResponse[number];
};

const RevokeGrantButton = ({ grant }: RevokeGrantButtonProps) => {
  const { toast } = useToast();
  const { t } = useLingui();

  const utils = trpc.useUtils();

  const { mutateAsync: revokeGrant, isPending } = trpc.oauth.revokeGrant.useMutation({
    onSuccess: async () => {
      await utils.oauth.findGrants.invalidate();
    },
  });

  const handleRevoke = async () => {
    try {
      await revokeGrant({ grantId: grant.id });

      toast({
        title: t`Access revoked`,
        description: t`${grant.clientName} can no longer access ${grant.team.name}.`,
      });
    } catch {
      toast({
        title: t`Error`,
        description: t`Failed to revoke access`,
        variant: 'destructive',
      });
    }
  };

  return (
    <Button variant="destructive" size="sm" onClick={handleRevoke} loading={isPending}>
      <Trans>Revoke</Trans>
    </Button>
  );
};
