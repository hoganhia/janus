export class InsufficientScanDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InsufficientScanDataError';
  }
}
