const WEAK_CIPHER_KEYWORDS = ['RC4', 'RC2', 'DES', 'MD5', 'NULL', 'EXPORT', 'ANON', 'PSK'];

/** Flags a cipher (by OpenSSL or IANA/standard name) as weak using well-known weak-algorithm keywords. */
export function isWeakCipher(cipherName: string): boolean {
  const upper = cipherName.toUpperCase();
  return WEAK_CIPHER_KEYWORDS.some((keyword) => upper.includes(keyword));
}
