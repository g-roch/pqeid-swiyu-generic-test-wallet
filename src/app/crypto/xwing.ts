/**
 * PQEID: X-Wing hybrid post-quantum KEM (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem)
 * JWE wrapper, built on @noble/post-quantum's ready-made `XWing` KEM export. Neither `jose`
 * nor WebCrypto has any notion of a KEM-based "alg" - see the TODO-PQEID comments in
 * crypto-service.ts / oidvp-service.ts for the call sites this is meant to replace.
 *
 * Verified byte-for-byte compatible with the BouncyCastle X-Wing implementation used by
 * repos/nimbus-jose-jwt's XWingKey/XWingEncrypter/XWingDecrypter: same combiner
 * (SHA3-256(ss_mlkem || ss_x25519 || ct_x25519 || pk_x25519 || "\.//^\")), same public-key
 * encoding (ML-KEM-768 pubkey || X25519 pubkey, 1184 + 32 = 1216 bytes), same ciphertext
 * encoding (ML-KEM ciphertext || X25519 ephemeral pubkey, 1088 + 32 = 1120 bytes), and same
 * private-key convention (a 32-byte seed, not the expanded secret key - noble's
 * `XWing.keygen()` returns the seed itself as `secretKey`, and `XWing.decapsulate(ct, seed)`
 * takes that same seed, matching nimbus's XWingKey `d` field exactly).
 *
 * JWE shape follows the convention established on the Java side (see XWingEncrypter/
 * XWingDecrypter and the "XWING" JWEAlgorithm added to the nimbus fork): the compact JWE's
 * "encrypted key" part carries the raw ~1120-byte KEM ciphertext (not a wrapped CEK, unlike
 * RSA-OAEP/AES-KW's usual meaning of that field but consistent with how any KEM must use
 * it, since - unlike ECDH-ES - a KEM ciphertext is asymmetric and must travel with the
 * message). The actual content-encryption key is derived from the KEM shared secret via
 * RFC 7518 Concat KDF (concat-kdf.ts), then content is encrypted with standard JWE AES-GCM.
 */

import { XWing } from "@noble/post-quantum/hybrid.js";
import { deriveDirectCek } from "./concat-kdf";
import {
  base64UrlDecode,
  base64UrlEncode,
  base64UrlEncodeJson,
  concatBytes,
  toBufferSource,
  utf8Encode,
} from "./base64url";

const XWING_KEY_TYPE = "XWING";
const XWING_ALG = "XWING";
const IV_LENGTH_BYTES = 12;
const GCM_TAG_LENGTH_BITS = 128;

/**
 * RFC 7516 §4.1.3 "DEF" = raw DEFLATE (RFC 1951, no zlib wrapper). Matches `jose`'s own
 * zip="DEF" implementation (CompressionStream/DecompressionStream("deflate-raw")) and the
 * Java backend's java.util.zip.Deflater(nowrap=true), so this interops with both.
 */
async function deflateRaw(input: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  void writer.write(toBufferSource(input)).catch(() => {});
  void writer.close().catch(() => {});
  const chunks: Uint8Array[] = [];
  const reader = cs.readable.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concatBytes(...chunks);
}

async function inflateRaw(input: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  void writer.write(toBufferSource(input)).catch(() => {});
  void writer.close().catch(() => {});
  const chunks: Uint8Array[] = [];
  const reader = ds.readable.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concatBytes(...chunks);
}

export type XWingEnc = "A128GCM" | "A192GCM" | "A256GCM";

function cekBitsFor(enc: XWingEnc): number {
  switch (enc) {
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
      return 256;
    default:
      throw new Error(`Unsupported enc: ${enc}`);
  }
}

export interface XWingKeyPair {
  publicKey: Uint8Array;
  /** 32-byte private key seed - the same value @noble/post-quantum calls "secretKey". */
  secretKeySeed: Uint8Array;
}

/** Generates a fresh X-Wing key pair. */
export function generateXWingKeyPair(): XWingKeyPair {
  const { publicKey, secretKey } = XWing.keygen();
  return { publicKey, secretKeySeed: secretKey };
}

export interface XWingJwk {
  kty: "XWING";
  kid?: string;
  x: string;
  d?: string;
}

/** Exports the public half of an X-Wing key pair as a JWK (kty="XWING", no "d"). */
export function exportXWingPublicJwk(pair: XWingKeyPair, kid?: string): XWingJwk {
  return {
    kty: XWING_KEY_TYPE,
    ...(kid ? { kid } : {}),
    x: base64UrlEncode(pair.publicKey),
  };
}

/** Exports the full (public + private-seed) X-Wing key pair as a JWK. */
export function exportXWingPrivateJwk(pair: XWingKeyPair, kid?: string): XWingJwk {
  return {
    ...exportXWingPublicJwk(pair, kid),
    d: base64UrlEncode(pair.secretKeySeed),
  };
}

/** Parses an X-Wing JWK's public key bytes (works for both public-only and private JWKs). */
export function importXWingPublicKey(jwk: XWingJwk): Uint8Array {
  if (jwk.kty !== XWING_KEY_TYPE) {
    throw new Error(`Expected kty "${XWING_KEY_TYPE}", got "${jwk.kty}"`);
  }
  if (!jwk.x) {
    throw new Error('XWING JWK is missing the "x" parameter');
  }
  return base64UrlDecode(jwk.x);
}

/** Parses an X-Wing JWK's private key seed. Throws if the JWK has no "d" parameter. */
export function importXWingPrivateKey(jwk: XWingJwk): XWingKeyPair {
  if (jwk.kty !== XWING_KEY_TYPE) {
    throw new Error(`Expected kty "${XWING_KEY_TYPE}", got "${jwk.kty}"`);
  }
  if (!jwk.x || !jwk.d) {
    throw new Error('XWING JWK is missing "x" or "d" parameter');
  }
  return { publicKey: base64UrlDecode(jwk.x), secretKeySeed: base64UrlDecode(jwk.d) };
}

async function importAesGcmKey(cek: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toBufferSource(cek), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export interface EncryptXWingOptions {
  enc?: XWingEnc;
  /** Extra protected header params merged in alongside {alg, enc} (e.g. "kid"). */
  additionalHeaderParams?: Record<string, unknown>;
}

/**
 * Encrypts `plaintext` for `recipientPublicKey` as a 5-part compact JWE:
 * base64url(header).base64url(KEM ciphertext).base64url(iv).base64url(ciphertext).base64url(tag)
 */
export async function encryptXWingJwe(
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  options: EncryptXWingOptions = {},
): Promise<string> {
  const enc = options.enc ?? "A128GCM";
  const header: Record<string, unknown> = {
    alg: XWING_ALG,
    enc,
    ...(options.additionalHeaderParams ?? {}),
  };
  const headerB64 = base64UrlEncodeJson(header);
  const aad = utf8Encode(headerB64);

  const { cipherText: kemCipherText, sharedSecret } = XWing.encapsulate(recipientPublicKey);
  const cek = deriveDirectCek(sharedSecret, enc, cekBitsFor(enc));
  const key = await importAesGcmKey(cek);

  const toEncrypt = header["zip"] === "DEF" ? await deflateRaw(plaintext) : plaintext;

  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toBufferSource(iv), additionalData: toBufferSource(aad), tagLength: GCM_TAG_LENGTH_BITS },
      key,
      toBufferSource(toEncrypt),
    ),
  );
  const tagLengthBytes = GCM_TAG_LENGTH_BITS / 8;
  const cipherTextOnly = encrypted.slice(0, encrypted.length - tagLengthBytes);
  const tag = encrypted.slice(encrypted.length - tagLengthBytes);

  return [
    headerB64,
    base64UrlEncode(kemCipherText),
    base64UrlEncode(iv),
    base64UrlEncode(cipherTextOnly),
    base64UrlEncode(tag),
  ].join(".");
}

/** Decrypts a 5-part compact JWE produced by encryptXWingJwe using the recipient's private key seed. */
export async function decryptXWingJwe(recipientSecretKeySeed: Uint8Array, jwe: string): Promise<Uint8Array> {
  const parts = jwe.split(".");
  if (parts.length !== 5) {
    throw new Error("Invalid JWE compact serialization: expected 5 parts");
  }
  const [headerB64, encryptedKeyB64, ivB64, cipherTextB64, tagB64] = parts;
  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64))) as {
    alg: string;
    enc: XWingEnc;
    zip?: string;
  };
  if (header.alg !== XWING_ALG) {
    throw new Error(`Unexpected alg: expected ${XWING_ALG}, got ${header.alg}`);
  }

  const kemCipherText = base64UrlDecode(encryptedKeyB64);
  const sharedSecret = XWing.decapsulate(kemCipherText, recipientSecretKeySeed);
  const cek = deriveDirectCek(sharedSecret, header.enc, cekBitsFor(header.enc));
  const key = await importAesGcmKey(cek);

  const iv = base64UrlDecode(ivB64);
  const aad = utf8Encode(headerB64);
  const cipherTextAndTag = concatBytes(base64UrlDecode(cipherTextB64), base64UrlDecode(tagB64));

  const decrypted = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toBufferSource(iv), additionalData: toBufferSource(aad), tagLength: GCM_TAG_LENGTH_BITS },
      key,
      toBufferSource(cipherTextAndTag),
    ),
  );
  return header.zip === "DEF" ? await inflateRaw(decrypted) : decrypted;
}
