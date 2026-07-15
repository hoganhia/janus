import { fetchPinned, validateScanTarget } from '@janus/shared';
import { WELL_KNOWN_VERIFICATION_PATH } from './constants.js';

export interface WellKnownChallengeOptions {
  requesterIp: string;
  userAgent: string;
  /** Default: 4 KiB — the file only ever needs to hold one short token. */
  maxBodyBytes?: number;
}

const DEFAULT_MAX_BODY_BYTES = 4 * 1024;
const MAX_REDIRECTS = 3;

/**
 * Checks whether `https://<domain>/.well-known/janus-verify.txt` exists and its body matches
 * `token`. Goes through `validateScanTarget` — the same SSRF/rebinding gate every scanner is
 * built on — since, unlike the DNS check, this opens a real connection to an address derived
 * from the target. Never throws: a validation failure, connection error, non-200 response, or
 * non-matching body are all just "not verified," not exceptional.
 */
export async function checkWellKnownFileChallenge(
  domain: string,
  token: string,
  options: WellKnownChallengeOptions,
): Promise<boolean> {
  const url = `https://${domain}${WELL_KNOWN_VERIFICATION_PATH}`;

  try {
    const validated = await validateScanTarget(url, {
      requesterIp: options.requesterIp,
      userAgent: options.userAgent,
      maxRedirects: MAX_REDIRECTS,
    });

    const response = await fetchPinned(new URL(validated.finalUrl), validated.pinnedAddress, {
      userAgent: options.userAgent,
      maxBodyBytes: options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
      captureBody: true,
    });

    if (response.statusCode !== 200 || response.body === undefined) return false;
    return response.body.toString('utf8').trim() === token;
  } catch {
    return false;
  }
}
