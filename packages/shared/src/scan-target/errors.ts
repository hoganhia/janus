export type ScanTargetRejectionReason =
  | 'MALFORMED_URL'
  | 'UNSUPPORTED_PROTOCOL'
  | 'CREDENTIALS_IN_URL'
  | 'BLOCKED_HOSTNAME'
  | 'DENIED_BY_LIST'
  | 'NOT_ALLOWLISTED'
  | 'PRIVATE_ADDRESS'
  | 'TOO_MANY_REDIRECTS'
  | 'PROBE_FAILED';

export class ScanTargetRejectedError extends Error {
  readonly reason: ScanTargetRejectionReason;

  constructor(reason: ScanTargetRejectionReason, message: string) {
    super(message);
    this.name = 'ScanTargetRejectedError';
    this.reason = reason;
  }
}
