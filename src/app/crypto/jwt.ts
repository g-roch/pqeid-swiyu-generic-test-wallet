/**
 * PQEID: algorithm-aware JWS sign/verify, unifying `jose` (classical algorithms) and
 * mldsa.ts (ML-DSA) behind one call site. Replaces the scattered `new jose.SignJWT(...)`/
 * `jose.jwtVerify(...)` calls across wallet-service.ts, verification.service.ts,
 * credential-verification.ts, and credential-input.component.ts, none of which could
 * previously handle a real "ML-DSA-44" alg or an "AKP" JWK from the migrated issuer/verifier.
 */

import { JWK, jwtVerify, SignJWT } from "jose";
import { AKPJwk, importMLDSAPublicKey, MLDSASignJWT, verifyMLDSAJwt } from "./mldsa";
import { HolderKeyPair } from "./holder-key";

export interface JwtSigningOptions {
  audience?: string;
  /** jose-style relative expiry string, e.g. "2h". */
  expiresIn?: string;
  issuedAt?: number | Date;
}

/** Signs `claims` as a compact JWS, dispatching on `keyPair.kind`. `protectedHeader.alg` is overridden with `keyPair.alg`. */
export async function signJwtWithHolderKey(
  keyPair: HolderKeyPair,
  claims: Record<string, unknown>,
  protectedHeader: Record<string, unknown>,
  options: JwtSigningOptions = {},
): Promise<string> {
  if (keyPair.kind === "mldsa") {
    let builder = new MLDSASignJWT(claims).setProtectedHeader({ ...protectedHeader, alg: keyPair.alg });
    builder = builder.setIssuedAt(
      typeof options.issuedAt === "number"
        ? options.issuedAt
        : Math.floor((options.issuedAt ?? new Date()).getTime() / 1000),
    );
    if (options.audience) builder = builder.setAudience(options.audience);
    if (options.expiresIn) builder = builder.setExpirationTime(options.expiresIn);
    return builder.sign(keyPair.secretKey);
  }

  let builder = new SignJWT(claims).setProtectedHeader({ ...protectedHeader, alg: keyPair.alg });
  builder = builder.setIssuedAt(options.issuedAt ?? new Date());
  if (options.audience) builder = builder.setAudience(options.audience);
  if (options.expiresIn) builder = builder.setExpirationTime(options.expiresIn);
  return builder.sign(keyPair.privateKey);
}

/**
 * Verifies a compact JWS against a JWK resolved from a DID registry / verification method,
 * dispatching on `jwk.kty`: "AKP" goes through mldsa.ts, everything else through `jose`.
 */
export async function verifyJwtWithJwk(
  jwt: string,
  jwk: JWK | AKPJwk,
): Promise<{ payload: Record<string, unknown>; protectedHeader: Record<string, unknown> }> {
  if ((jwk as AKPJwk).kty === "AKP") {
    const { publicKey } = importMLDSAPublicKey(jwk as AKPJwk);
    return verifyMLDSAJwt(jwt, publicKey);
  }

  const { payload, protectedHeader } = await jwtVerify(jwt, jwk as JWK);
  return { payload, protectedHeader };
}
