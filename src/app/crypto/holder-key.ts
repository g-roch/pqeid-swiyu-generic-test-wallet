/**
 * PQEID: algorithm-aware holder key pair generation, unifying classical (WebCrypto ECDSA
 * P-256 via `jose`) and post-quantum (ML-DSA via mldsa.ts) key generation behind one type,
 * so callers can generate "whatever the issuer/verifier asked for" without knowing in
 * advance whether that's a classical or PQC algorithm.
 *
 * This is the wallet-side equivalent of the `signerFor`/`algorithmFor` JWK-instanceof
 * dispatch pattern used on the Java side (SDJWTCredentialMock/StatusListGenerator in
 * swiyu-verifier's test fixtures) - same idea, dispatch on what the key actually is rather
 * than hardcoding one algorithm.
 */

import { exportJWK, JWK } from "jose";
import { AKPJwk, exportMLDSAPublicJwk, generateMLDSAKeyPair, MLDSAAlg, MLDSAKeyPair } from "./mldsa";

export function isMLDSAAlg(alg: string | undefined): alg is MLDSAAlg {
  return alg === "ML-DSA-44" || alg === "ML-DSA-65" || alg === "ML-DSA-87";
}

export type HolderKeyPair =
  | { kind: "jose"; alg: string; privateKey: CryptoKey; publicKey: CryptoKey; jwk: JWK }
  | { kind: "mldsa"; alg: MLDSAAlg; secretKey: Uint8Array; publicKey: Uint8Array; jwk: AKPJwk };

/** Generates a holder key pair for `alg`: ML-DSA via mldsa.ts, anything else via WebCrypto ECDSA P-256. */
export async function generateHolderKeyPair(alg: string): Promise<HolderKeyPair> {
  if (isMLDSAAlg(alg)) {
    const pair: MLDSAKeyPair = generateMLDSAKeyPair(alg);
    return {
      kind: "mldsa",
      alg,
      secretKey: pair.secretKey,
      publicKey: pair.publicKey,
      // Public-only JWK: `.jwk` gets embedded verbatim in JOSE header `jwk` claims
      // (DPoP proofs, holder-binding/proof-of-possession JWTs, kb+jwt) sent to the
      // issuer/verifier - it must never carry the "priv" field.
      jwk: exportMLDSAPublicJwk(pair),
    };
  }

  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await exportJWK(publicKey);

  return { kind: "jose", alg, privateKey, publicKey, jwk: { ...jwk, alg } };
}
