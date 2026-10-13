/**
 * PQEID: ML-DSA (FIPS 204) signing/verification wrapper for the test wallet, built on
 * @noble/post-quantum since neither `jose` (the npm package used everywhere else in this
 * codebase) nor the browser's WebCrypto SubtleCrypto API has any ML-DSA support - see the
 * TODO-PQEID comments in crypto-service.ts / wallet-service.ts / verification.service.ts
 * etc. for the call sites this is meant to eventually replace.
 *
 * JWK shape follows the same convention established in repos/nimbus-jose-jwt's AKPJWK/
 * MLDSAKey (kty "AKP", "pub"/"priv" fields holding raw base64url key bytes) so that keys and
 * signed JWTs stay interoperable with the issuer/verifier's Java-side ML-DSA implementation.
 *
 * API intentionally mirrors `jose`'s `SignJWT`/`jwtVerify` shape closely (fluent builder +
 * verify function returning {payload, protectedHeader}) to keep this a close-to-drop-in
 * replacement at existing call sites, not a from-scratch API to learn.
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import type { Signer } from "@noble/post-quantum/utils.js";
import { COMPOSITE_ALG, CompositeAlg, signComposite, verifyComposite } from "./composite";
import {
  base64UrlDecode,
  base64UrlDecodeJson,
  base64UrlEncode,
  base64UrlEncodeJson,
  utf8Encode,
} from "./base64url";

export type MLDSAAlg = "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87";

const AKP_KEY_TYPE = "AKP";

/** PQEID: every algorithm carried by an AKP JWK: plain ML-DSA or the composite ML-DSA-65-ES256. */
export type AKPAlg = MLDSAAlg | CompositeAlg;

function signerFor(alg: MLDSAAlg): Signer {
  switch (alg) {
    case "ML-DSA-44":
      return ml_dsa44;
    case "ML-DSA-65":
      return ml_dsa65;
    case "ML-DSA-87":
      return ml_dsa87;
    default:
      throw new Error(`Unsupported ML-DSA algorithm: ${alg}`);
  }
}

export interface MLDSAKeyPair {
  alg: AKPAlg;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Generates a fresh ML-DSA key pair for the given parameter set. */
export function generateMLDSAKeyPair(alg: MLDSAAlg): MLDSAKeyPair {
  const { publicKey, secretKey } = signerFor(alg).keygen();
  return { alg, publicKey, secretKey };
}

export interface AKPJwk {
  kty: "AKP";
  alg: AKPAlg;
  kid?: string;
  pub: string;
  priv?: string;
}

/** Exports the public half of an ML-DSA key pair as an AKP JWK (kty="AKP", no "priv"). */
export function exportMLDSAPublicJwk(pair: MLDSAKeyPair, kid?: string): AKPJwk {
  return {
    kty: AKP_KEY_TYPE,
    alg: pair.alg,
    ...(kid ? { kid } : {}),
    pub: base64UrlEncode(pair.publicKey),
  };
}

/** Exports the full (public + private) ML-DSA key pair as an AKP JWK. */
export function exportMLDSAPrivateJwk(pair: MLDSAKeyPair, kid?: string): AKPJwk {
  return {
    ...exportMLDSAPublicJwk(pair, kid),
    priv: base64UrlEncode(pair.secretKey),
  };
}

/** Parses an AKP JWK's public key bytes (works for both public-only and private JWKs). */
export function importMLDSAPublicKey(jwk: AKPJwk): { alg: AKPAlg; publicKey: Uint8Array } {
  if (jwk.kty !== AKP_KEY_TYPE) {
    throw new Error(`Expected kty "${AKP_KEY_TYPE}", got "${jwk.kty}"`);
  }
  if (!jwk.pub) {
    throw new Error('AKP JWK is missing the "pub" parameter');
  }
  return { alg: jwk.alg, publicKey: base64UrlDecode(jwk.pub) };
}

/** Parses an AKP JWK's private key bytes. Throws if the JWK has no "priv" parameter. */
export function importMLDSAPrivateKey(jwk: AKPJwk): MLDSAKeyPair {
  if (jwk.kty !== AKP_KEY_TYPE) {
    throw new Error(`Expected kty "${AKP_KEY_TYPE}", got "${jwk.kty}"`);
  }
  if (!jwk.pub || !jwk.priv) {
    throw new Error('AKP JWK is missing "pub" or "priv" parameter');
  }
  return {
    alg: jwk.alg,
    publicKey: base64UrlDecode(jwk.pub),
    secretKey: base64UrlDecode(jwk.priv),
  };
}

/** Signs raw bytes with an ML-DSA or composite secret key. */
export function signMLDSA(alg: AKPAlg, secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (alg === COMPOSITE_ALG) {
    return signComposite(secretKey, message);
  }
  return signerFor(alg).sign(message, secretKey);
}

/** Verifies a raw ML-DSA or composite signature. Returns false (not throw) on a bad signature. */
export function verifyMLDSA(
  alg: AKPAlg, 
  publicKey: Uint8Array,
   signature: Uint8Array,
    message: Uint8Array): boolean {
  if (alg === COMPOSITE_ALG) {
    return verifyComposite(signature, message, publicKey);
  }
  return signerFor(alg).verify(signature, message, publicKey);
}

/**
 * Minimal `jose`-SignJWT-compatible builder for ML-DSA-signed compact JWS/JWTs.
 *
 * Usage mirrors `jose`:
 * ```ts
 * const jwt = await new MLDSASignJWT(claims)
 *   .setProtectedHeader({ alg: "ML-DSA-44", typ: "openid4vci-proof+jwt", jwk })
 *   .setIssuedAt()
 *   .setAudience(aud)
 *   .setExpirationTime("2h")
 *   .sign(secretKey);
 * ```
 */
export class MLDSASignJWT {
  private claims: Record<string, unknown>;
  private header: Record<string, unknown> = {};

  constructor(claims: Record<string, unknown> = {}) {
    this.claims = { ...claims };
  }

  setProtectedHeader(header: Record<string, unknown>): this {
    this.header = { ...this.header, ...header };
    return this;
  }

  setIssuedAt(iat: number = Math.floor(Date.now() / 1000)): this {
    this.claims["iat"] = iat;
    return this;
  }

  setAudience(aud: string | string[]): this {
    this.claims["aud"] = aud;
    return this;
  }

  setSubject(sub: string): this {
    this.claims["sub"] = sub;
    return this;
  }

  setIssuer(iss: string): this {
    this.claims["iss"] = iss;
    return this;
  }

  /** Accepts a small subset of jose's relative-time strings (e.g. "2h", "5m", "30s"). */
  setExpirationTime(exp: string | number): this {
    if (typeof exp === "number") {
      this.claims["exp"] = exp;
      return this;
    }
    const match = /^(\d+)\s*([smhd])$/.exec(exp.trim());
    if (!match) {
      throw new Error(`Unsupported expiration time format: ${exp}`);
    }
    const amount = parseInt(match[1], 10);
    const unitSeconds = { s: 1, m: 60, h: 3600, d: 86400 }[match[2] as "s" | "m" | "h" | "d"];
    const iat = (this.claims["iat"] as number) ?? Math.floor(Date.now() / 1000);
    this.claims["exp"] = iat + amount * unitSeconds;
    return this;
  }

  /**
   * Signs and serializes as a compact JWS: base64url(header).base64url(payload).base64url(sig).
   * `alg` must be present in the protected header (set via setProtectedHeader) and match the
   * key's own algorithm.
   */
  sign(secretKey: Uint8Array): string {
    const alg = this.header["alg"] as AKPAlg | undefined;
    if (!alg) {
      throw new Error('Protected header is missing "alg"');
    }
    const headerB64 = base64UrlEncodeJson(this.header);
    const payloadB64 = base64UrlEncodeJson(this.claims);
    const signingInput = utf8Encode(`${headerB64}.${payloadB64}`);
    const signature = signMLDSA(alg, secretKey, signingInput);
    return `${headerB64}.${payloadB64}.${base64UrlEncode(signature)}`;
  }
}

export interface MLDSAVerifyResult<T = Record<string, unknown>> {
  payload: T;
  protectedHeader: Record<string, unknown>;
}

/**
 * `jose`-jwtVerify-compatible verification of an ML-DSA-signed compact JWS/JWT.
 * `alg`, if provided, is checked against the token's own header alg (defense against alg
 * confusion); otherwise the header's alg is trusted as-is (same behavior as importing the
 * key with a matching alg elsewhere in this codebase).
 */
export function verifyMLDSAJwt<T = Record<string, unknown>>(
  jwt: string,
  publicKey: Uint8Array,
  expectedAlg?: AKPAlg,
): MLDSAVerifyResult<T> {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWS compact serialization: expected 3 parts");
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  const protectedHeader = base64UrlDecodeJson<Record<string, unknown>>(headerB64);
  const alg = protectedHeader["alg"] as AKPAlg;

  if (expectedAlg && alg !== expectedAlg) {
    throw new Error(`Unexpected alg: expected ${expectedAlg}, got ${alg}`);
  }

  const signingInput = utf8Encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecode(signatureB64);

  if (!verifyMLDSA(alg, publicKey, signature, signingInput)) {
    throw new Error("ML-DSA signature verification failed");
  }

  const payload = base64UrlDecodeJson<T>(payloadB64);
  return { payload, protectedHeader };
}
