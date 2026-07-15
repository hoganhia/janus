'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (password.trim() === '' || isSubmitting) return;

    setIsSubmitting(true);
    setError(null);
    try {
      const response = await fetch('/api/site-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      if (!response.ok) {
        const body = (await response.json()) as { error?: string };
        setError(body.error ?? 'Incorrect password.');
        setIsSubmitting(false);
        return;
      }
      const destination = searchParams.get('from') ?? '/';
      router.push(destination);
      router.refresh();
    } catch {
      setError('Could not reach the server. Please try again.');
      setIsSubmitting(false);
    }
  }

  return (
    <div className="border-border bg-card w-full max-w-sm rounded-xl border p-6">
      <p className="text-primary font-mono text-xs tracking-widest uppercase">Janus</p>
      <h1 className="mt-2 text-xl font-semibold tracking-tight">
        This preview is password-protected
      </h1>
      <p className="text-muted-foreground mt-2 text-sm leading-relaxed">
        Enter the access password you were given to continue.
      </p>

      <form onSubmit={(event) => void handleSubmit(event)} className="mt-6 space-y-3">
        <Input
          type="password"
          value={password}
          onChange={(event) => {
            setPassword(event.target.value);
          }}
          placeholder="Password"
          autoFocus
          aria-label="Site password"
        />
        {error !== null && <p className="text-destructive text-sm">{error}</p>}
        <Button type="submit" disabled={password.trim() === '' || isSubmitting} className="w-full">
          {isSubmitting ? 'Checking…' : 'Continue'}
        </Button>
      </form>
    </div>
  );
}

export default function LoginPage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6">
      <Suspense>
        <LoginForm />
      </Suspense>
    </main>
  );
}
