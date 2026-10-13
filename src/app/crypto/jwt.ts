/**
 * PQEID: algorithm-aware JWS sign/verify, unifying `jose` (classical algorithms) and
 * mldsa.ts (ML-DSA) behind one call site. Replaces the scattered `new jose.SignJWT(...)`/
 * `jose.jwtVerify(...)` calls across wallet-service.ts, verification.service.ts,
 * credential-verification.ts, and credential-input.component.ts, none of which could
 * previously handle a real "ML-DSA-44" alg or an "AKP" JWK from the migrated issuer/verifier.
 */

import { JWK, jwtVerify, SignJWT, decodeProtectedHeader } from "jose";
import { AKPJwk, importMLDSAPublicKey, MLDSASignJWT, verifyMLDSAJwt } from "./mldsa";
import { HolderKeyPair } from "./holder-key";
import { environment } from "../../environments/environment";

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
  accepted: readonly string[] = environment.acceptedSignatureAlgorithms,
): Promise<{ payload: Record<string, unknown>; protectedHeader: Record<string, unknown> }> {
  // PQEID step 5: algorithm policy first (RFC 8725 §3.1); a refused alg never reaches any crypto code
  const headerAlg = decodeProtectedHeader(jwt).alg;
  if (!headerAlg || !accepted.includes(headerAlg)) {
    throw new Error(`JWS algorithm ${headerAlg} is not accepted (accepted: ${accepted.join(", ")})`);
  }

  if ((jwk as AKPJwk).kty === "AKP") {
    const { alg, publicKey } = importMLDSAPublicKey(jwk as AKPJwk);
    if (!alg) {
      throw new Error('AKP JWK without "alg": the algorithm must come from the key, not from the token');
    }
    // PQEID: the token's header alg must equal the key's alg (RFC 8725 §3.1), so the token
    // can't choose the algorithm
    return verifyMLDSAJwt(jwt, publicKey, alg);
     }

  const { payload, protectedHeader } = await jwtVerify(jwt, jwk as JWK, { algorithms: [...accepted] });
  return { payload, protectedHeader };
}
