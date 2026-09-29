import type { MessageDescriptor } from '@lingui/core';
import { msg } from '@lingui/core/macro';

import type { OAuthScope } from './oauth';

export const OAUTH_SCOPE_DESCRIPTIONS: Record<OAuthScope, MessageDescriptor> = {
  'envelopes:read': msg`View the team's documents, templates and their signing status`,
  'envelopes:write': msg`Create draft documents from the team's templates`,
  'envelopes:send': msg`Send documents to recipients for signing`,
};
