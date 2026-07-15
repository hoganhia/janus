import { randomBytes } from 'node:crypto';

// 48 hex characters — long enough to be unguessable (192 bits of entropy), short enough to
// paste cleanly into a single DNS TXT record or a one-line file.
const TOKEN_BYTES = 24;

/**
 * Generates a fresh ownership-verification token. Each call to `startDomainVerification`
 * (see @janus/db) should use a freshly generated one — restarting a challenge always
 * supersedes rather than reuses a prior token, so a stale token from an earlier attempt never
 * lingers as valid.
 */
export function generateVerificationToken(): string {
  return randomBytes(TOKEN_BYTES).toString('hex');
}
