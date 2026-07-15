'use client';

import Link from 'next/link';
import { useSyncExternalStore } from 'react';
import { Button } from '@/components/ui/button';

const STORAGE_KEY = 'perimeter-cookie-notice-dismissed';

function subscribe(onStoreChange: () => void): () => void {
  window.addEventListener('storage', onStoreChange);
  return () => {
    window.removeEventListener('storage', onStoreChange);
  };
}

function getSnapshot(): boolean {
  return window.localStorage.getItem(STORAGE_KEY) === 'true';
}

/** Renders as dismissed during SSR/first paint — avoids a hydration mismatch, and means the
 * banner never flashes in before the client can check whether it was already dismissed. */
function getServerSnapshot(): boolean {
  return true;
}

/**
 * Not a full consent-management platform — this app doesn't set any third-party
 * advertising/tracking cookies as of Prompt 9 (see /privacy's Cookies section), so there's
 * nothing to actually opt in/out of yet. This just satisfies the "notify visitors" half of
 * GDPR/ePrivacy-style cookie notices; if third-party tracking cookies are ever added, this
 * needs to become a real accept/reject choice, not just a dismissible notice.
 */
export function CookieConsentBanner() {
  const dismissed = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  function dismiss(): void {
    window.localStorage.setItem(STORAGE_KEY, 'true');
    // Manually notify this tab — the native `storage` event only fires in *other* tabs.
    window.dispatchEvent(new StorageEvent('storage'));
  }

  if (dismissed) return null;

  return (
    <div className="border-border bg-card fixed inset-x-0 bottom-0 z-50 border-t px-6 py-4">
      <div className="mx-auto flex max-w-2xl flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-muted-foreground text-sm">
          We use a small number of strictly necessary and functional cookies/local storage entries.
          No third-party advertising or tracking cookies.{' '}
          <Link href="/privacy" className="underline underline-offset-2">
            Learn more
          </Link>
          .
        </p>
        <Button size="sm" onClick={dismiss} className="shrink-0">
          Got it
        </Button>
      </div>
    </div>
  );
}
