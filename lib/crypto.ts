// Sealed values: JSON encrypted and authenticated with AES-256-GCM under HUB_SECRET. They keep the server
// stateless (no database of its own): an authorization code, a refresh token or a registered client id carries
// its own data, and nobody without the key can read or forge one. Rotating the key revokes all of them.

const encoder = new TextEncoder();
const decoder = new TextDecoder();
let keyPromise: Promise<CryptoKey> | null = null;

function key(): Promise<CryptoKey> {
  keyPromise ??= (async () => {
    const secret = process.env.HUB_SECRET;
    if (!secret || secret.length < 32) throw new Error("HUB_SECRET is not set (32+ random characters).");
    const raw = await crypto.subtle.digest("SHA-256", encoder.encode(secret));
    return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  })();
  return keyPromise;
}

export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** [purpose] is bound into the ciphertext: a sealed refresh token cannot be passed off as a code. */
export async function seal(purpose: string, value: unknown): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(purpose) },
    await key(),
    encoder.encode(JSON.stringify(value)),
  );
  return base64url(iv) + "." + base64url(new Uint8Array(data));
}

/** null when the value was not sealed by this server for [purpose] (or was tampered with). */
export async function open<T>(purpose: string, sealed: string | null | undefined): Promise<T | null> {
  if (!sealed) return null;
  const [iv, data] = sealed.split(".");
  if (!iv || !data) return null;
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: Buffer.from(iv, "base64url"), additionalData: encoder.encode(purpose) },
      await key(),
      Buffer.from(data, "base64url"),
    );
    return JSON.parse(decoder.decode(plain)) as T;
  } catch {
    return null;
  }
}

/** PKCE S256: base64url(sha256(verifier)). */
export async function pkceChallenge(verifier: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(verifier))));
}
