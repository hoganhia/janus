import { runRetentionSweep } from '@janus/db';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { runDataRetentionSweep } from './run-retention-sweep.js';

vi.mock('@janus/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@janus/db')>();
  return { ...actual, runRetentionSweep: vi.fn() };
});

const mockSweep = vi.mocked(runRetentionSweep);

const NOW = new Date('2026-07-15T00:00:00.000Z');

describe('runDataRetentionSweep', () => {
  afterEach(() => {
    vi.resetAllMocks();
  });

  it('computes the cutoff date as `retentionMonths` before `now`', async () => {
    mockSweep.mockResolvedValue({ scanReports: 0, scanConsents: 0 });

    await runDataRetentionSweep(12, NOW);

    expect(mockSweep).toHaveBeenCalledWith(new Date('2025-07-15T00:00:00.000Z'));
  });

  it('respects a custom retention period', async () => {
    mockSweep.mockResolvedValue({ scanReports: 0, scanConsents: 0 });

    await runDataRetentionSweep(1, NOW);

    expect(mockSweep).toHaveBeenCalledWith(new Date('2026-06-15T00:00:00.000Z'));
  });

  it('returns the cutoff date and per-table counts', async () => {
    mockSweep.mockResolvedValue({ scanReports: 42, scanConsents: 7 });

    const result = await runDataRetentionSweep(12, NOW);

    expect(result).toEqual({
      cutoffDate: '2025-07-15T00:00:00.000Z',
      scanReports: 42,
      scanConsents: 7,
    });
  });

  it('defaults now to the current time when not provided', async () => {
    mockSweep.mockResolvedValue({ scanReports: 0, scanConsents: 0 });
    const before = Date.now();

    const result = await runDataRetentionSweep(12);

    const after = Date.now();
    const cutoffMs = new Date(result.cutoffDate).getTime();
    // 12 months before "now" should fall strictly before both bounds, but within a sane range.
    expect(cutoffMs).toBeLessThan(before);
    expect(cutoffMs).toBeGreaterThan(before - 366 * 24 * 60 * 60 * 1000);
    expect(cutoffMs).toBeLessThan(after);
  });
});
