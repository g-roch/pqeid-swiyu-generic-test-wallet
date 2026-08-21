import { Injectable } from "@angular/core";
import { importJWK, JWK, jwtVerify } from "jose";
import {
  decryptJwe,
  EphemeralKeyPair,
  encryptJwe,
  exportEphemeralPublicJwk,
  generateEphemeralKeyPair as generateEphemeralKeyPairImpl,
} from "@app/crypto/jwe";
import { verifyJwtWithJwk } from "@app/crypto/jwt";
import { AKPJwk, importMLDSAPublicKey } from "@app/crypto/mldsa";
import { XWingJwk } from "@app/crypto/xwing";

@Injectable({
  providedIn: "root",
})
export class CryptoService {
  /** Ephemeral JWE key generation - X-Wing when `alg` is "XWING", classical `jose` otherwise. */
  async generateEphemeralKeyPair(alg: string): Promise<EphemeralKeyPair> {
    return generateEphemeralKeyPairImpl(alg);
  }

  /** Exports the public half of an ephemeral JWE key pair as a JWK ("use":"enc"). */
  async exportPublicJwk(keyPair: EphemeralKeyPair): Promise<JWK | XWingJwk> {
    return exportEphemeralPublicJwk(keyPair);
  }

  decodeJwtPayload<T = any>(token: string): T {
    const parts = token.split(".");

    if (parts.length !== 3) {
      throw new Error("Invalid JWT format");
    }

    try {
      const payload = parts[1];
      const decoded = atob(payload);
      return JSON.parse(decoded) as T;
    } catch (error) {
      console.error("Failed to decode JWT payload:", error);
      throw new Error(`Failed to decode JWT payload: ${error}`);
    }
  }

  decodeIfJwt<T>(input: string | T): T {
    if (typeof input === "string") {
      return this.decodeJwtPayload<T>(input);
    }

    return input;
  }

  isJwt(input: unknown): boolean {
    return typeof input === "string" && input.split(".").length === 3;
  }

  /** JWE compact encryption for the recipient's `jwk` - dispatches to X-Wing (jwe.ts) when `alg` is "XWING". */
  async encryptPayload(
    payload: unknown,
    jwk: JWK | XWingJwk,
    alg: string,
    enc: string,
    zip: string,
  ): Promise<string> {
    return encryptJwe(payload, jwk, alg, enc, zip);
  }

  /** JWE compact decryption with an ephemeral key pair from generateEphemeralKeyPair - dispatches on `keyPair.kind`. */
  async decryptPayload(
    input: unknown | string,
    keyPair: EphemeralKeyPair,
  ): Promise<unknown> {
    return decryptJwe(input, keyPair);
  }

  /** JWS verification against an already-resolved key. Classical only - not reachable with an "AKP" key today, see verifyJwt. */
  async checkJwtIsValid(token: string, publicKey: CryptoKey): Promise<boolean> {
    try {
      await jwtVerify(token, publicKey);
      return true;
    } catch (error) {
      console.warn("JWT verification failed:", error);
      return false;
    }
  }

  /** JWS verification against a raw JWK (e.g. a DID verification method) - dispatches on jwk.kty. */
  async verifyJwt(
    token: string,
    jwk: JWK | AKPJwk,
  ): Promise<{ payload: Record<string, unknown>; protectedHeader: Record<string, unknown> }> {
    return verifyJwtWithJwk(token, jwk);
  }

  /**
   * Imports a registry-resolved public key JWK for signature verification, dispatching on
   * `jwk.kty` ("AKP" -> ML-DSA raw public key bytes, else classical via `jose`, using the
   * JWK's own `alg` when present rather than assuming ES256).
   */
  async getCryptoKeyFromJwk(jwk: JWK | AKPJwk): Promise<CryptoKey | Uint8Array> {
    if ((jwk as AKPJwk).kty === "AKP") {
      return importMLDSAPublicKey(jwk as AKPJwk).publicKey;
    }
    return (await importJWK(jwk as JWK, (jwk as JWK).alg ?? "ES256")) as CryptoKey | Uint8Array;
  }
}
