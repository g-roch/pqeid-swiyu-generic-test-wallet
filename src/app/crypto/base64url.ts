/**
 * PQEID: base64url helpers shared by the ML-DSA / X-Wing wrapper (src/app/crypto/*).
 * Kept self-contained here rather than reusing ad hoc base64Url helpers duplicated across
 * services/components, since this module is meant to be usable independently of Angular.
 */

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64UrlDecode(input: string): Uint8Array {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function utf8Encode(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function base64UrlEncodeJson(value: unknown): string {
  return base64UrlEncode(utf8Encode(JSON.stringify(value)));
}

export function base64UrlDecodeJson<T = unknown>(input: string): T {
  return JSON.parse(utf8Decode(base64UrlDecode(input))) as T;
}

/**
 * Casts a Uint8Array to BufferSource for WebCrypto SubtleCrypto calls. Needed because
 * TypeScript 5.7+ made Uint8Array generic over its backing ArrayBufferLike, and SubtleCrypto's
 * BufferSource type only accepts the ArrayBuffer-backed variant - a purely type-level
 * mismatch (every Uint8Array we build here is always ArrayBuffer-backed at runtime).
 */
export function toBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
