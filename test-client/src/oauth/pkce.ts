export function generateCodeVerifier(): string {
  const array = new Uint8Array(96);
  window.crypto.getRandomValues(array);
  return b64url(array);
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await window.crypto.subtle.digest('SHA-256', data);
  return b64url(new Uint8Array(hash));
}

function b64url(array: Uint8Array): string {
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
