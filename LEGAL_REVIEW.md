# Legal review required before launch

> **Do not launch this product on any of the legal/consent text below without a lawyer's
> review.** Everything in this file is scaffolding — structure, scope, and the general shape of
> the policies a service like this needs — written by an engineer, not counsel. None of it has
> been reviewed for legal accuracy, jurisdiction-specific requirements (GDPR, CCPA, ePrivacy,
> etc.), or enforceability.

## Placeholder legal text

Every one of these is marked `[PLACEHOLDER — REQUIRES LEGAL REVIEW]` inline, next to the exact
sentence/section it applies to, so a reviewer doesn't have to guess what's real vs. scaffolding.

| Document              | File                                            | Covers                                                                                                                                                                             |
| --------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Terms of Service      | `packages/frontend/app/terms/page.tsx`          | Acceptance, service description, no-compliance-certification disclaimer, liability limitation for scan accuracy, authorization requirement, suspension/termination, change process |
| Acceptable Use Policy | `packages/frontend/app/acceptable-use/page.tsx` | Purpose, prohibited uses (unauthorized scanning, opt-out circumvention, harassment, abuse), consequences, change process                                                           |
| Privacy Policy        | `packages/frontend/app/privacy/page.tsx`        | User data vs. third-party-domain data distinction, what's collected, retention, user rights, cookies, change process                                                               |

The scan-attestation checkbox copy on the landing page
(`packages/frontend/components/scan-console.tsx`, "I own this domain or have authorization to
assess it") is not itself marked as a placeholder — it's short, functional UI text rather than a
legal document — but it references the Acceptable Use Policy above, which is placeholder text.
Review it together with the AUP, not in isolation.

## What's actually real (infrastructure, not text)

Everything below is functioning code, already covered by tests, and not blocked on legal review
itself — only the _text it displays or gates access to_ is:

- `ScanConsent` (Prisma model, `packages/db/prisma/schema.prisma`) — one row per scan
  submission's attestation: requester IP, target domain, timestamp, and which Acceptable Use
  Policy version was in effect. This is the audit trail if a scanned domain's owner ever
  disputes being scanned.
- `LegalVersion` (same file) — a timestamped changelog of every version of every legal document.
  **All three documents are currently seeded at version `1.0.0-placeholder`** (see the `INSERT`
  statements in `packages/db/prisma/migrations/20260715134341_add_legal_consent_models/migration.sql`).
  Bump these to a real version number the moment real, reviewed text replaces the placeholder —
  every `LegalAcceptance` row points at a specific version ID, so this is what makes "prove what
  a user agreed to" actually provable.
- `LegalAcceptance` — one row per (user, document, version) acceptance, recorded via
  `POST /api/v1/legal/accept`.
- The daily data-retention sweep (`packages/workers/src/data-retention`) — deletes scan records
  and the consent/IP-log audit trail older than `RETENTION_MONTHS` (default 12). Deliberately
  does not delete `LegalAcceptance`, since proof of acceptance needs to survive as long as the
  account does.
- `POST /api/v1/legal/delete-account` — deletes a signed-in user's own `ScanConsent` and
  `LegalAcceptance` rows. **Scoping decision, not yet lawyer-reviewed**: it does not delete
  `Domain`/`ScanReport` rows, on the reasoning that those describe a third-party target's public
  security posture (shared, relied on by anyone who's scanned or looked up that domain), not
  personal data about the requesting user. Confirm this reasoning holds under whatever privacy
  regime actually applies (GDPR's right-to-erasure scope, CCPA, etc.) before relying on it.

## Known scope gaps (not oversights — deliberate, but worth a second look)

- **No dedicated "signup" flow exists to gate ToS/AUP acceptance at.** This app has no local
  User table and no Clerk-integrated frontend signup UI — Clerk owns identity, and this app
  never sees a distinct "account created" event. Acceptance is instead enforced at the first
  account-tied action that does exist: starting domain-ownership verification (see
  `requireLegalAcceptance` in `packages/api/src/plugins/legal.ts`). If a real signup flow is
  built later, move (or duplicate) the enforcement point there.
- **No frontend UI consumes `POST /legal/accept`, `GET /legal/status`, or
  `POST /legal/delete-account` yet.** The backend endpoints exist and are tested; there is no
  in-product settings/account page. The privacy policy's "Your rights" section says as much and
  points people at the abuse-report contact form in the meantime — that's a real gap, not just
  missing polish.
- **The cookie consent banner is a notice, not a consent-management platform.** As of this
  writing the app sets no third-party advertising/tracking cookies, so there is nothing to
  actually opt in or out of — the banner just satisfies "tell visitors cookies/local storage are
  in use." If third-party tracking is ever added, this needs to become a real accept/reject
  choice before that ships, not after.
- **Scan submission remains anonymous** (per an earlier product decision) — `ScanConsent.userId`
  is always `null` today. The audit trail for an anonymous scan is IP + timestamp + target
  domain + attestation only, not tied to any account.
- While implementing the data-retention job, discovered that two pre-existing scheduled jobs
  (`cve-sync`, `domain-verification-expiry`) were fully built and tested in earlier work but
  were never actually wired into the worker process (`packages/workers/src/main.ts`) — meaning
  the CVE cache never refreshed and verified domains never expired in any running deployment.
  Fixed as part of this work (all three scheduled jobs are now wired up together), not something
  that needs legal review, but flagging since it's a meaningful pre-existing correctness gap
  that was silently present until now.

## Suggested review checklist

- [ ] Terms of Service — full legal review, especially the liability-limitation and
      no-compliance-certification language
- [ ] Acceptable Use Policy — full legal review, especially "prohibited uses" and consequences
- [ ] Privacy Policy — full legal review; confirm the user-data-vs-third-party-data framing is
      correct under GDPR/CCPA/whatever regimes actually apply, and that the retention periods
      and "your rights" section meet the applicable legal minimums
- [ ] Confirm whether `POST /legal/delete-account`'s scope (own consent records only, not
      Domain/ScanReport) actually satisfies right-to-erasure obligations where applicable
- [ ] Decide whether a real signup-time acceptance flow is needed, vs. the current
      first-account-tied-action enforcement point
- [ ] Once real text is approved: bump each `LegalVersion` row's `version` field away from
      `1.0.0-placeholder` and update `changeNote`
