// Minimal JWT helper using only Bun/Bun-compatible APIs
// Only supports HS256 for safety in local dev
type JwtResult = { token: string, error?: undefined } | { token?: undefined, error: string };

function base64url(input: Uint8Array): string {
  // btoa is not present in Bun; use Buffer styles
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function utf8(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

// Only supports HS256 (HMAC SHA256) for safety
declare global {
  interface Crypto {
    subtle: SubtleCrypto;
  }
}
const textEncoder = new TextEncoder();

export async function generateMockJwt(
  payload: Record<string, unknown>,
  secret: string,
  header: Record<string, unknown> = {}
): Promise<JwtResult> {
  try {
    // Only allow HS256
    const alg = 'HS256';
    let headerData = { alg, typ: 'JWT', ...header };
    if (headerData.alg !== 'HS256') {
      return { error: "Only HS256 ('alg':'HS256') is supported" };
    }
    // No JWK etc support: just a string secret
    const encoder = textEncoder;
    const headerEncoded = base64url(encoder.encode(JSON.stringify(headerData)));
    const payloadEncoded = base64url(encoder.encode(JSON.stringify(payload)));
    const signingInput = `${headerEncoded}.${payloadEncoded}`;
    // HMAC SHA256 signature
    let key: CryptoKey;
    if (typeof Bun !== 'undefined' && Bun.CryptoHasher) {
      // Bun has built-in HMAC utils
      const signature = Buffer.from(
        Bun.CryptoHasher
          .hmac('sha256', secret, signingInput)
      );
      return { token: `${signingInput}.${base64url(signature)}` };
    } else if (typeof crypto !== 'undefined' && crypto.subtle) {
      // WebCrypto
      key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: { name: 'SHA-256' } },
        false,
        ['sign']
      );
      const sigArrBuf = await crypto.subtle.sign(
        { name: 'HMAC', hash: { name: 'SHA-256' } },
        key,
        encoder.encode(signingInput)
      );
      const signature = new Uint8Array(sigArrBuf);
      return { token: `${signingInput}.${base64url(signature)}` };
    } else {
      // Last resort: node crypto
      let cryptoNode;
      try {
        cryptoNode = await import('crypto');
      } catch {
        return { error: 'No crypto implementation available.' };
      }
      const signature = cryptoNode.createHmac('sha256', secret).update(signingInput).digest();
      return { token: `${signingInput}.${base64url(signature)}` };
    }
  } catch (e) {
    return { error: 'Failed to generate JWT: ' + (e instanceof Error ? e.message : String(e)) };
  }
}
