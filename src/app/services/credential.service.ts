import { Injectable, inject } from '@angular/core';
import * as jose from "jose";
import { RegistryEntry, JwtPayload } from "@app/models/api-response";
import { ToastService } from "./toast.service";

@Injectable({
  providedIn: 'root'
})
export class CredentialService {
  private toastService = inject(ToastService);

  public decodeDeeplink(url: string): Record<string, unknown> {
    if (!url) {
      this.toastService.showError('The deeplink is missing');
      throw new Error('No url provided');
    }
    if (url.startsWith('swiyu://')) {
      const decodedUri = decodeURIComponent(url);
      const json = this.getCredentialOfferString(decodedUri);
      try {
        return JSON.parse(json) as Record<string, unknown>;
      } catch (error) {
        console.error(error);
        this.toastService.showError(`Failed to parse credential offer: ${error}`);
        throw new Error(`Failed to parse credential offer: ${error}`);
      }
    }
    this.toastService.showError('Invalid deeplink format');
    throw new Error('Invalid deeplink format');
  }

  public async createHolderBinding(
    credentialIssuer: string,
    nonce: string,
    proofSigningAlgValuesSupported: string,
    privateKey: CryptoKey,
    jwk: jose.JWK
  ): Promise<string> {
    const claims: Record<string, unknown> = {
      "aud": credentialIssuer,
      "iat": Math.floor(Date.now() / 1000),
      nonce
    }

    // TODO-PQEID: holder-binding proof signature, alg taken dynamically from the issuer's
    // proof_signing_alg_values_supported (now "ML-DSA-44" after the issuer's PQC migration).
    // Algorithm-agnostic call site, but `privateKey`/`jwk` must actually be an ML-DSA key
    // pair for this to work - `jose`'s SignJWT has no ML-DSA support, so this will throw
    // once called with a real "ML-DSA-44" alg (see also the EC-key-only generation in
    // vc-key-store.service.ts / wallet-service.ts).
    const jwt = await new jose.SignJWT(claims)
      .setProtectedHeader({ alg: proofSigningAlgValuesSupported, typ: 'openid4vci-proof+jwt', jwk: jwk })
      .setIssuedAt(Math.floor(Date.now() / 1000))
      .setAudience(credentialIssuer)
      .setExpirationTime('2h')
      .sign(privateKey);

    return jwt;
  }

  public async decodeResponse(jwt: string, registryEntry: RegistryEntry[]): Promise<{ payload: JwtPayload, protectedHeader: JwtPayload, }> {
    const kid = (jose.decodeProtectedHeader(jwt) as JwtPayload)['kid'];
    const verificationMethods = (registryEntry[3] as Record<string, unknown>)?.['value'] as Record<string, unknown>;
    const verificationMethod = ((verificationMethods?.['verificationMethod'] as Record<string, unknown>[]) || [])
      .map(meth => (meth as Record<string, unknown>)['id'] === kid ? meth : null)
      .filter((meth: Record<string, unknown> | null): meth is Record<string, unknown> => meth != null)[0];
    const jwk = verificationMethod?.['publicKeyJwk'] as CryptoKey;
    // TODO-PQEID: signature verification against a DID-registry-resolved key - same
    // "jose has no ML-DSA support" gap as createHolderBinding above. Note: this
    // CredentialService class appears unused (superseded by VerificationService, which has
    // the same methods) - not imported anywhere else in src/, kept annotated for
    // completeness since it's still real crypto-calling code.
    const { payload, protectedHeader } = await jose.jwtVerify(jwt, jwk, {})

    return { payload: payload as JwtPayload, protectedHeader: protectedHeader as JwtPayload };
  }


  private getCredentialOfferString(deeplink: string): string {
    return deeplink.split('credential_offer=')[1];
  }
}
