/**
 * Generates a feed ingest token.
 *
 * Deliberately the same shape and strength as the server's `auth.GenerateFeedToken`:
 * 32 bytes of CSPRNG output, base64url without padding. A vendor puts this in an
 * `Authorization: Bearer` header, and the platform stores only a reference to it — so a
 * token that is weak here is weak for good, and nobody can tell after the fact.
 *
 * `crypto.getRandomValues` is a cryptographically secure source and, unlike
 * `crypto.randomUUID`, is available outside a secure context. `Math.random` is NOT an
 * acceptable fallback for a credential, so this throws instead: refusing to mint a token
 * is far better than minting a guessable one and reporting success.
 */
export function generateFeedToken(): string {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error(
      'This browser cannot generate a secure token. Rotate the credential from a ' +
        'browser with Web Crypto support, or via the API.',
    )
  }

  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)

  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)

  // base64url, unpadded — matches Go's base64.RawURLEncoding so a token minted here is
  // indistinguishable from one the server issued.
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
