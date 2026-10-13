import { Injectable } from '@angular/core';
import { JWK } from 'jose';
import { AKPJwk } from '@app/crypto/mldsa';
import { generateHolderKeyPair, HolderKeyPair } from '@app/crypto/holder-key';
import { COMPOSITE_ALG } from '@app/crypto/composite';

@Injectable({
  providedIn: 'root'
})
export class HolderKeyService {
  private keyPair: HolderKeyPair | null = null;
  private keyGeneratedAt: Date | null = null;
  private currentKeyId: string | null = null;

  /**
   * Holder's long-lived fallback key pair, used by
   * credential-verification.ts::findCredentialKeyPair when no per-VC key was stored for the
   * credential being presented. Defaults to the composite ML-DSA-65-ES256 (hybrid); the verifier's policy accepts it alongside ML-DSA-44 (expand phase).
   */
  async initializeKeys(): Promise<void> {
    this.keyPair = await generateHolderKeyPair(COMPOSITE_ALG);
    this.keyGeneratedAt = new Date();

    this.currentKeyId = `key_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getKeyPair(): HolderKeyPair {
    if (this.keyPair) return this.keyPair;
    throw new Error('getKeyPair');
  }

  getPrivateKey(): CryptoKey {
    const keyPair = this.getKeyPair();
    if (keyPair.kind !== 'jose') {
      throw new Error('Holder key is not a WebCrypto key (kind=' + keyPair.kind + ')');
    }
    return keyPair.privateKey;
  }

  getPublicKey(): CryptoKey | null {
    return this.keyPair?.kind === 'jose' ? this.keyPair.publicKey : null;
  }

  getJwk(): JWK | AKPJwk {
    if (this.keyPair) return this.keyPair.jwk;
    throw new Error("getJwk")
  }

  getKeyGeneratedAt(): Date | null {
    return this.keyGeneratedAt;
  }

  getCurrentKeyId(): string | null {
    return this.currentKeyId;
  }

  hasKeys(): boolean {
    return this.keyPair !== null;
  }
}

