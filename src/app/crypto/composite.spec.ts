import { describe, it, expect } from 'vitest';
import { hexToBytes } from '@noble/hashes/utils.js';
import vector from './testdata/ML-DSA-65-ES256.json';
import { base64UrlDecode } from './base64url';
import {
  COMPOSITE_ALG, compositePublicKeyFromSecret, encodeCompositeSecretKey, generateCompositeKeyPair,
  messageRepresentative, signComposite, verifyComposite,
} from './composite';

/** PQEID: composite ML-DSA-65-ES256 in TypeScript, checked against the official
 *  draft-ietf-jose-pq-composite-sigs-04 vector (the same one nimbus passes). */
describe('composite ML-DSA-65-ES256', () => {
  const M = hexToBytes(vector.raw_to_be_signed);
  const pub = hexToBytes(vector.raw_composite_public_key);
  const sig = hexToBytes(vector.raw_composite_signature);

  it("builds the draft's message representative M'", () => {
    expect(messageRepresentative(M)).toEqual(hexToBytes(vector.raw_message_representative));
  });

  it('verifies the official signature', () => {
    expect(verifyComposite(sig, M, pub)).toBe(true);
  });

  it('encodes the private key exactly like the vector (seed || RFC 5915 ECPrivateKey)', () => {
    const sk = encodeCompositeSecretKey(hexToBytes(vector.mldsa_seed), hexToBytes(vector.ecdsa_d));
    expect(sk).toEqual(base64UrlDecode(vector.jwk.priv));
    expect(compositePublicKeyFromSecret(sk)).toEqual(pub);
  });

  it('rejects a tampered ML-DSA half', () => {
    const t = sig.slice(); t[10] ^= 1;
    expect(verifyComposite(t, M, pub)).toBe(false);
  });

  it('rejects a tampered ECDSA half', () => {
    const t = sig.slice(); t[t.length - 5] ^= 1;
    expect(verifyComposite(t, M, pub)).toBe(false);
  });

  it('rejects the ML-DSA half alone (stripping)', () => {
    expect(verifyComposite(sig.slice(0, 3309), M, pub)).toBe(false);
  });

  it('rejects a different message', () => {
    expect(verifyComposite(sig, Uint8Array.of(...M, 0x20), pub)).toBe(false);
  });

  it('signs and verifies its own signatures (fresh key)', () => {
    const kp = generateCompositeKeyPair();
    const s = signComposite(kp.secretKey, M);
    expect(kp.publicKey.length).toBe(2017);
    expect(kp.secretKey.length).toBe(83);
    expect(s.length).toBeGreaterThanOrEqual(3309 + 70);
    expect(verifyComposite(s, M, kp.publicKey)).toBe(true);
    expect(COMPOSITE_ALG).toBe('ML-DSA-65-ES256');
  });
});