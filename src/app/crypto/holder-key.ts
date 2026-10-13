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
import { AKPAlg, AKPJwk, exportMLDSAPublicJwk, generateMLDSAKeyPair, MLDSAAlg, MLDSAKeyPair } from "./mldsa";
import { COMPOSITE_ALG, generateCompositeKeyPair } from "./composite";
import { base64UrlEncode } from "./base64url";

export function isMLDSAAlg(alg: string | undefined): alg is MLDSAAlg {
  return alg === "ML-DSA-44" || alg === "ML-DSA-65" || alg === "ML-DSA-87";
}

/** PQEID: algorithms carried by an AKP JWK: plain ML-DSA or the composite ML-DSA-65-ES256. */
export function isAKPAlg(alg: string | undefined): alg is AKPAlg {
  return isMLDSAAlg(alg) || alg === COMPOSITE_ALG;
}

/**
 * PQEID: the wallet's choice among the algorithms an issuer/verifier advertises: hybrid first,
 * then plain ML-DSA, else the first entry. Never an algorithm that isn't advertised (stays compatible),
 * so the wallet switches to the composite by itself once the issuer advertises it (expand -> migrate).
 */
export function preferredAlg(advertised: string[] | undefined): string | undefined {
  if (!advertised?.length) {
    return undefined;
  }
  return advertised.find((a) => a === COMPOSITE_ALG) ?? advertised.find(isMLDSAAlg) ?? advertised[0];
}

export type HolderKeyPair =
  | { kind: "jose"; alg: string; privateKey: CryptoKey; publicKey: CryptoKey; jwk: JWK }
  | { kind: "mldsa"; alg: AKPAlg; secretKey: Uint8Array; publicKey: Uint8Array; jwk: AKPJwk };

/** Generates a holder key pair for `alg`: ML-DSA via mldsa.ts, anything else via WebCrypto ECDSA P-256. */
export async function generateHolderKeyPair(alg: string): Promise<HolderKeyPair> {
   if (alg === COMPOSITE_ALG) {
    // kind "mldsa" = the AKP family (signJwtWithHolderKey / verifyJwtWithJwk dispatch the composite by alg)
    const pair = generateCompositeKeyPair();
    return {
      kind: "mldsa",
      alg,
      secretKey: pair.secretKey,
      publicKey: pair.publicKey,
      jwk: { kty: "AKP", alg, pub: base64UrlEncode(pair.publicKey) }, // public only, never "priv"
    };
  }
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

/**
 * PQEID: best-effort detection of whether an issuer is PQC- or classical-crypto-based, from
 * its OID4VCI metadata - used to pick the DPoP proof algorithm. Unlike the credential
 * proof/response-encryption algorithms, DPoP has no per-request negotiation field of its
 * own (swiyu-generic-java-lib's DpopJwtValidator accepts one deployment-wide algorithm), so
 * it can only be inferred from other advertised algorithms, not read off directly. Checks
 * each credential configuration's proof_signing_alg_values_supported first (the same signal
 * already used for the holder-binding proof itself), then falls back to
 * credential_response_encryption's alg_values_supported ("XWING" implies a PQC issuer).
 * Defaults to "ES256" (classical) when nothing indicates otherwise, so a wallet built
 * against this issuer talks classical DPoP unless the issuer positively advertises PQC.
 */
export function detectIssuerDpopAlg(issuerMetadata?: {
  credential_configurations_supported?: Record<string, unknown>;
  credential_response_encryption?: { alg_values_supported?: string[] };
}): string {
  const configs = Object.values(issuerMetadata?.credential_configurations_supported ?? {});
  for (const config of configs) {
    const proofTypes = (config as Record<string, unknown>)?.["proof_types_supported"] as
      | Record<string, { proof_signing_alg_values_supported?: string[] }>
      | undefined;
    const akpAlg = preferredAlg(proofTypes?.["jwt"]?.proof_signing_alg_values_supported);
    if (isAKPAlg(akpAlg)) {
      return akpAlg;
    }
  }

  if (issuerMetadata?.credential_response_encryption?.alg_values_supported?.includes("XWING")) {
    return "ML-DSA-44";
  }

  return "ES256";
}
