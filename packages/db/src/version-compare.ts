/**
 * Compares dot-separated numeric version strings (e.g. "1.18.0" vs "1.9.2"). Not a full semver
 * parser — sufficient for the products this catalog tracks (nginx, PHP, WordPress, etc.),
 * which use simple numeric dotted versions in practice, without semver prerelease/build
 * metadata. Returns negative/zero/positive like an Array.prototype.sort comparator.
 */
export function compareVersions(a: string, b: string): number {
  const aParts = a.split('.').map((p) => parseInt(p, 10) || 0);
  const bParts = b.split('.').map((p) => parseInt(p, 10) || 0);
  const length = Math.max(aParts.length, bParts.length);
  // Plain numeric loop index into arrays built locally in this function, not attacker-controlled
  // property access.
  for (let i = 0; i < length; i++) {
    // eslint-disable-next-line security/detect-object-injection
    const av = aParts[i] ?? 0;
    // eslint-disable-next-line security/detect-object-injection
    const bv = bParts[i] ?? 0;
    if (av !== bv) return av - bv;
  }
  return 0;
}

export interface VersionRange {
  versionStartIncluding?: string | null;
  versionStartExcluding?: string | null;
  versionEndIncluding?: string | null;
  versionEndExcluding?: string | null;
  exactVersion?: string | null;
}

/** True if `version` falls inside `range`. A range with no bounds at all (every field null)
 * came from a CPE match with no version constraint — i.e. it matches any version — so that
 * case returns true rather than false. */
export function isVersionInRange(version: string, range: VersionRange): boolean {
  if (range.exactVersion !== null && range.exactVersion !== undefined) {
    return compareVersions(version, range.exactVersion) === 0;
  }
  if (
    range.versionStartIncluding !== null &&
    range.versionStartIncluding !== undefined &&
    compareVersions(version, range.versionStartIncluding) < 0
  ) {
    return false;
  }
  if (
    range.versionStartExcluding !== null &&
    range.versionStartExcluding !== undefined &&
    compareVersions(version, range.versionStartExcluding) <= 0
  ) {
    return false;
  }
  if (
    range.versionEndIncluding !== null &&
    range.versionEndIncluding !== undefined &&
    compareVersions(version, range.versionEndIncluding) > 0
  ) {
    return false;
  }
  if (
    range.versionEndExcluding !== null &&
    range.versionEndExcluding !== undefined &&
    compareVersions(version, range.versionEndExcluding) >= 0
  ) {
    return false;
  }
  return true;
}
