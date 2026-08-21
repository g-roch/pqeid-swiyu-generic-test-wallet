/**
 * PQEID: algorithm-aware JWE encrypt/decrypt, unifying `jose` (classical ECDH-ES and other
 * jose-supported algs) and xwing.ts (XWING, the issuer/verifier's post-quantum KEM) behind
 * one call site. Replaces the ad hoc `importJWK`/`CompactEncrypt`/`compactDecrypt` calls in
 * crypto-service.ts and oidvp-service.ts, neither of which could previously handle "XWING".
 */

import { compactDecrypt, CompactEncrypt, CompactJWEHeaderParameters, exportJWK, generateKeyPair, importJWK, JWK } from "jose";
import { decryptXWingJwe, encryptXWingJwe, exportXWingPublicJwk, generateXWingKeyPair, importXWingPublicKey, XWingJwk } from "./xwing";

export function isXWingAlg(alg: string | undefined): boolean {
  return alg === "XWING";
}

export type EphemeralKeyPair =
  | { kind: "jose"; alg: string; privateKey: CryptoKey; publicKey: CryptoKey }
  | { kind: "xwing"; publicKey: Uint8Array; secretKeySeed: Uint8Array };

/** Generates an ephemeral JWE key pair for `alg`: X-Wing via xwing.ts, anything else via `jose`. */
export async function generateEphemeralKeyPair(alg: string): Promise<EphemeralKeyPair> {
  if (isXWingAlg(alg)) {
    const pair = generateXWingKeyPair();
    return { kind: "xwing", publicKey: pair.publicKey, secretKeySeed: pair.secretKeySeed };
  }
  const { publicKey, privateKey } = await generateKeyPair(alg, { crv: "P-256" });
  return { kind: "jose", alg, privateKey, publicKey };
}

/** Exports the public half of an ephemeral key pair as a JWE-recipient JWK ("use":"enc"). */
export async function exportEphemeralPublicJwk(pair: EphemeralKeyPair, kid?: string): Promise<JWK | XWingJwk> {
  if (pair.kind === "xwing") {
    return { ...exportXWingPublicJwk({ publicKey: pair.publicKey, secretKeySeed: pair.secretKeySeed }, kid), use: "enc" } as XWingJwk;
  }
  const jwk = await exportJWK(pair.publicKey);
  return { ...jwk, ...(kid ? { kid } : {}), use: "enc", alg: pair.alg, crv: "P-256" };
}

/** Encrypts `payload` as a compact JWE for `jwk`, dispatching on `alg`. `zip` ("DEF" or falsy) is optional - jose throws on any other value if present at all. */
export async function encryptJwe(
  payload: unknown,
  jwk: JWK | XWingJwk,
  alg: string,
  enc: string,
  zip?: string,
): Promise<string> {
  const encoded = new TextEncoder().encode(JSON.stringify(payload));

  if (isXWingAlg(alg)) {
    const publicKey = importXWingPublicKey(jwk as XWingJwk);
    return encryptXWingJwe(publicKey, encoded, {
      enc: enc as "A128GCM" | "A192GCM" | "A256GCM",
      additionalHeaderParams: { typ: "JWT", kid: (jwk as XWingJwk).kid, ...(zip ? { zip } : {}) },
    });
  }

  const publicKey = await importJWK(jwk as JWK, alg);
  const protectedHeader: CompactJWEHeaderParameters = {
    typ: "JWT",
    kid: (jwk as JWK).kid,
    alg,
    enc,
    ...(zip ? { zip } : {}),
  };
  return new CompactEncrypt(encoded).setProtectedHeader(protectedHeader).encrypt(publicKey);
}

/** Decrypts a compact JWE with `keyPair`, dispatching on `keyPair.kind`. Non-string input passes through unchanged. */
export async function decryptJwe(input: unknown | string, keyPair: EphemeralKeyPair): Promise<unknown> {
  if (typeof input !== "string") {
    return input;
  }

  try {
    if (keyPair.kind === "xwing") {
      const plaintext = await decryptXWingJwe(keyPair.secretKeySeed, input);
      return JSON.parse(new TextDecoder().decode(plaintext));
    }

    const { plaintext } = await compactDecrypt(input, keyPair.privateKey, {
      maxDecompressedLength: 10 * 1024 * 1024,
    });
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch (error) {
    throw new Error(`Failed to decrypt payload: ${error}`);
  }
}
