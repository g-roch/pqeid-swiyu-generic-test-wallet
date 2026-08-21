import { Injectable } from '@angular/core';
import { generateHolderKeyPair, HolderKeyPair } from '@app/crypto/holder-key';

export interface VcKeyPair {
  vcId: string;
  credentialType: string;
  keyPair: HolderKeyPair;
  createdAt: Date;
  issuerId: string;
}

export type DpopKeyPair = HolderKeyPair;

@Injectable({
  providedIn: 'root'
})
export class VcKeyStoreService {
  private vcKeyPair = new Map<string, VcKeyPair>();

  /**
   * DPoP proof key pair. `alg` must match what the target authorization server's DPoP
   * validator actually accepts - a PQC-migrated backend
   * (swiyu-generic-java-lib's DpopJwtValidator.SUPPORTED_ALGORITHMS) only accepts
   * "ML-DSA-44", a classical one only ES256/similar. There's no per-request negotiation
   * for DPoP itself, so callers derive `alg` from other issuer metadata via
   * holder-key.ts::detectIssuerDpopAlg().
   */
  async generateDpopKeyPair(alg: string): Promise<DpopKeyPair> {
    return generateHolderKeyPair(alg);
  }

  async generateKeyPairForVc(
    vcId: string,
    credentialType: string,
    issuerId: string,
    existingKeyPair?: HolderKeyPair,
    alg = 'ML-DSA-44',
  ): Promise<VcKeyPair> {
    // The per-VC holder-binding key: reused from wallet-service.ts::buildRequestCredential
    // when available (the key that was actually committed to the credential's `cnf` claim
    // during issuance), since the key-binding JWT at presentation time must be signed with
    // that exact key - generating a fresh one here would no longer match `cnf`. Falls back
    // to generating a fresh key only when no proof key pair was produced during issuance.
    const keyPair = existingKeyPair ?? (await generateHolderKeyPair(alg));

    const vcKeyPair: VcKeyPair = {
      vcId,
      credentialType,
      keyPair,
      createdAt: new Date(),
      issuerId
    };

    this.vcKeyPair.set(vcId, vcKeyPair);
    return vcKeyPair;
  }

  getKeyPairByVcId(vcId: string): VcKeyPair | undefined {
    return this.vcKeyPair.get(vcId);
  }

  getHolderKeyPairByVcId(vcId: string): HolderKeyPair | null {
    return this.vcKeyPair.get(vcId)?.keyPair ?? null;
  }

  getAllKeyPairs(): VcKeyPair[] {
    return Array.from(this.vcKeyPair.values());
  }

  deleteKeyPairByVcId(vcId: string): boolean {
    return this.vcKeyPair.delete(vcId);
  }

  clearAllKeyPairs(): void {
    this.vcKeyPair.clear();
  }
}

