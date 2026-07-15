'use client';

import { CheckCircle2 } from 'lucide-react';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { ApiError, submitAbuseReport } from '@/lib/api-client';

export function AbuseReportForm() {
  const [domain, setDomain] = useState('');
  const [reason, setReason] = useState('');
  const [details, setDetails] = useState('');
  const [contact, setContact] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (domain.trim() === '' || reason.trim() === '' || isSubmitting) return;

    setIsSubmitting(true);
    setError(null);
    try {
      await submitAbuseReport({
        domain: domain.trim(),
        reason: reason.trim(),
        ...(details.trim() !== '' ? { details: details.trim() } : {}),
        ...(contact.trim() !== '' ? { contact: contact.trim() } : {}),
      });
      setSubmitted(true);
    } catch (err) {
      setError(
        err instanceof ApiError ? err.body.message : 'Could not submit this report right now.',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  if (submitted) {
    return (
      <div className="border-border bg-card flex items-start gap-3 rounded-xl border p-5">
        <CheckCircle2 className="text-primary size-5 shrink-0" />
        <p className="text-sm">
          Thanks — this report has been logged for review. If you left contact info, we may follow
          up.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={(event) => void handleSubmit(event)} className="space-y-4">
      <div>
        <label htmlFor="abuse-domain" className="text-sm font-medium">
          Domain
        </label>
        <Input
          id="abuse-domain"
          value={domain}
          onChange={(event) => {
            setDomain(event.target.value);
          }}
          placeholder="yourcompany.com"
          className="mt-1.5"
          disabled={isSubmitting}
        />
      </div>

      <div>
        <label htmlFor="abuse-reason" className="text-sm font-medium">
          What happened
        </label>
        <Input
          id="abuse-reason"
          value={reason}
          onChange={(event) => {
            setReason(event.target.value);
          }}
          placeholder="e.g. Excessive request volume"
          className="mt-1.5"
          disabled={isSubmitting}
        />
      </div>

      <div>
        <label htmlFor="abuse-details" className="text-sm font-medium">
          Details <span className="text-muted-foreground font-normal">(optional)</span>
        </label>
        <Textarea
          id="abuse-details"
          value={details}
          onChange={(event) => {
            setDetails(event.target.value);
          }}
          placeholder="Anything else that would help us look into this"
          className="mt-1.5"
          disabled={isSubmitting}
        />
      </div>

      <div>
        <label htmlFor="abuse-contact" className="text-sm font-medium">
          Contact <span className="text-muted-foreground font-normal">(optional)</span>
        </label>
        <Input
          id="abuse-contact"
          value={contact}
          onChange={(event) => {
            setContact(event.target.value);
          }}
          placeholder="you@yourcompany.com, if you'd like a reply"
          className="mt-1.5"
          disabled={isSubmitting}
        />
      </div>

      <Button type="submit" disabled={domain.trim() === '' || reason.trim() === '' || isSubmitting}>
        {isSubmitting ? 'Submitting…' : 'Submit report'}
      </Button>

      {error !== null && <p className="text-destructive text-sm">{error}</p>}
    </form>
  );
}
