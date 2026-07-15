import { describe, expect, it } from 'vitest';
import { InMemoryScanTargetListStore } from './scan-target-list-store.js';

describe('InMemoryScanTargetListStore', () => {
  it('allows everything when no lists are configured', async () => {
    const store = new InMemoryScanTargetListStore();
    await expect(store.isDenied('example.com')).resolves.toBe(false);
    await expect(store.isAllowed('example.com')).resolves.toBe(true);
  });

  it('denies an exact hostname match and its subdomains', async () => {
    const store = new InMemoryScanTargetListStore({ denied: ['evil.example'] });
    await expect(store.isDenied('evil.example')).resolves.toBe(true);
    await expect(store.isDenied('sub.evil.example')).resolves.toBe(true);
    await expect(store.isDenied('notevil.example')).resolves.toBe(false);
    await expect(store.isDenied('good.example')).resolves.toBe(false);
  });

  it('is case-insensitive', async () => {
    const store = new InMemoryScanTargetListStore({ denied: ['Evil.Example'] });
    await expect(store.isDenied('evil.example')).resolves.toBe(true);
  });

  it('switches to allow-list-only mode once an allow list is configured', async () => {
    const store = new InMemoryScanTargetListStore({ allowed: ['good.example'] });
    await expect(store.isAllowed('good.example')).resolves.toBe(true);
    await expect(store.isAllowed('sub.good.example')).resolves.toBe(true);
    await expect(store.isAllowed('other.example')).resolves.toBe(false);
  });
});
