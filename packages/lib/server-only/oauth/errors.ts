import { AppError } from '../../errors/app-error';

/**
 * Error codes from RFC 6749 section 5.2, RFC 7591 section 3.2.2, RFC 6750 section 3.1 and
 * RFC 8707 section 2. OAuth endpoints return them as `{ error, error_description }`.
 */
const OAUTH_ERROR_CODES = [
  'invalid_request',
  'invalid_client',
  'invalid_grant',
  'unauthorized_client',
  'unsupported_grant_type',
  'unsupported_response_type',
  'invalid_scope',
  'invalid_target',
  'access_denied',
  'invalid_redirect_uri',
  'invalid_client_metadata',
  'server_error',
] as const;

export type OAuthErrorCode = (typeof OAUTH_ERROR_CODES)[number];

const OAUTH_ERROR_CODE_SET: ReadonlySet<string> = new Set(OAUTH_ERROR_CODES);

export const createOAuthError = (code: OAuthErrorCode, description: string, statusCode = 400) =>
  new AppError(code, { message: description, statusCode });

export const isOAuthError = (error: unknown): error is AppError =>
  error instanceof AppError && OAUTH_ERROR_CODE_SET.has(error.code);

export const toOAuthErrorBody = (error: AppError) => ({
  error: error.code,
  error_description: error.message,
});
