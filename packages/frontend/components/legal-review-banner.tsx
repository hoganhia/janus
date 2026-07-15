import { TriangleAlert } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

/**
 * Every legal document page needs this — see LEGAL_REVIEW.md at the repo root. None of the
 * text on /terms, /acceptable-use, or /privacy has been reviewed by a lawyer; none of it is
 * launch-ready.
 */
export function LegalReviewBanner() {
  return (
    <Alert
      className="border-warning/40 bg-warning/5 [&_svg]:text-warning mb-8"
      data-slot="legal-review-banner"
    >
      <TriangleAlert />
      <AlertTitle>[PLACEHOLDER — REQUIRES LEGAL REVIEW]</AlertTitle>
      <AlertDescription>
        The text on this page is a placeholder for structure and scope only. It has not been
        reviewed by a lawyer and must not be treated as launch-ready — see LEGAL_REVIEW.md in the
        repository root.
      </AlertDescription>
    </Alert>
  );
}
