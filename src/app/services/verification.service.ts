import { Injectable } from "@angular/core";
import * as jose from "jose";
import { DcqlCredentialDto, DcqlQueryDto } from "src/generated/verifier";
import { JwtPayload, RegistryEntry } from "@app/models/api-response";
import { DeeplinkService } from "./deeplink.service";

@Injectable({
  providedIn: "root",
})
export class VerificationService {
  constructor(private deeplinkService: DeeplinkService) {}

  public decodeDeeplink(url: string): Record<string, string> {
    return this.deeplinkService.decodeVerificationDeeplink(url);
  }

  public async createHolderBinding(
    credentialIssuer: string,
    nonce: string,
    proofSigningAlgValuesSupported: string,
    privateKey: CryptoKey,
    jwk: jose.JWK,
  ): Promise<string> {
    const claims: Record<string, unknown> = {
      aud: credentialIssuer,
      iat: Math.floor(Date.now() / 1000),
      nonce,
    };

    // TODO-PQEID: holder-binding proof signature, alg taken dynamically from the issuer's
    // proof_signing_alg_values_supported (now "ML-DSA-44" after the issuer's PQC migration).
    // Same "jose has no ML-DSA support" gap as credential.service.ts::createHolderBinding.
    const jwt = await new jose.SignJWT(claims)
      .setProtectedHeader({
        alg: proofSigningAlgValuesSupported,
        typ: "openid4vci-proof+jwt",
        jwk: jwk,
      })
      .setIssuedAt(Math.floor(Date.now() / 1000))
      .setAudience(credentialIssuer)
      .setExpirationTime("2h")
      .sign(privateKey);

    return jwt;
  }

  public async decodeResponse(
    jwt: string,
    registryEntry: RegistryEntry[],
  ): Promise<{ payload: JwtPayload; protectedHeader: JwtPayload }> {
    const kid = (jose.decodeProtectedHeader(jwt) as JwtPayload)["kid"];
    const verificationMethods = (registryEntry[3] as Record<string, unknown>)?.[
      "value"
    ] as Record<string, unknown>;
    const verificationMethod = (
      (verificationMethods?.["verificationMethod"] as Record<
        string,
        unknown
      >[]) || []
    )
      .map((meth) =>
        (meth as Record<string, unknown>)["id"] === kid ? meth : null,
      )
      .filter(
        (
          meth: Record<string, unknown> | null,
        ): meth is Record<string, unknown> => meth != null,
      )[0];
    const jwk = verificationMethod?.["publicKeyJwk"] as CryptoKey;
    // TODO-PQEID: signature verification against a DID-registry-resolved key - same
    // "jose has no ML-DSA support" gap as createHolderBinding above.
    const { payload, protectedHeader } = await jose.jwtVerify(jwt, jwk, {});

    return {
      payload: payload as JwtPayload,
      protectedHeader: protectedHeader as JwtPayload,
    };
  }

  // TODO-PQEID: generic key set generator, hardcoded to classical ECDSA P-256 - same
  // WebCrypto/PQC gap as holder-key.service.ts and vc-key-store.service.ts.
  public async createKeySet(): Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    jwk: jose.JWK;
  }> {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"],
    );

    const jwk = await jose.exportJWK(publicKey);

    return { publicKey: publicKey, privateKey: privateKey, jwk: jwk };
  }

  public extractCredentialsFromDCQL(
    dcqlQuery: DcqlQueryDto,
  ): DcqlCredentialDto[] {
    if (!dcqlQuery?.credentials) {
      return [];
    }

    return dcqlQuery.credentials;
  }

  public async createVerifiablePresentation(
    credential: string,
    verifierId: string,
    nonce: string,
    privateKey: CryptoKey,
    jwk: jose.JWK,
  ): Promise<string> {
    const claims: Record<string, unknown> = {
      iss: "did:example:holder",
      aud: verifierId,
      nonce: nonce,
      iat: Math.floor(Date.now() / 1000),
      vp: {
        type: ["VerifiablePresentation"],
        verifiableCredential: [credential],
      },
    };

    // TODO-PQEID: key-binding JWT signature for the verifiable presentation, alg hardcoded
    // to "ES256" - unlike createHolderBinding above, this one isn't even wired to the
    // dynamic proof-signing algorithm, so it's doubly stale against the holder's own
    // ECDSA-only key generation and the wider ML-DSA migration. Note: this method does not
    // appear to be called anywhere in src/ (createAndSignPresentation in
    // credential-verification.ts duplicates this logic inline instead) - dead code, kept
    // annotated for completeness.
    const vpToken = await new jose.SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", typ: "kb+jwt", jwk: jwk })
      .setIssuedAt(Math.floor(Date.now() / 1000))
      .setAudience(verifierId)
      .setExpirationTime("2h")
      .sign(privateKey);

    return vpToken;
  }
}
