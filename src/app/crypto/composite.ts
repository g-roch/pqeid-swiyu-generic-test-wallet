/**
 * PQEID: composite ML-DSA-65-ES256 (draft-ietf-jose-pq-composite-sigs-04), the wallet-side twin of
 * nimbus's CompositeSigner/CompositeVerifier: same construction, same official test vector.
 *
 *   M'   = "CompositeAlgorithmSignatures2025" || Label || 0x00 (empty ctx) || SHA-512(M)
 *   sig  = ML-DSA-65.Sign(M', context = Label) || ECDSA-P256-SHA256(M') in DER
 *   pub  = ML-DSA-65 public key (1952) || 0x04 || x || y (65)
 *   priv = ML-DSA-65 seed (32) || ECPrivateKey DER per RFC 5915, without public key (51)
 *
 * Do NOT use @noble/post-quantum's hybrid.combineSigners: a generic combiner, not this IETF format.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { p256 } from '@noble/curves/nist.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { utf8Encode } from './base64url';

export const COMPOSITE_ALG = 'ML-DSA-65-ES256' as const;
export type CompositeAlg = typeof COMPOSITE_ALG;

const PREFIX = utf8Encode('CompositeAlgorithmSignatures2025');
const LABEL = utf8Encode('COMPSIG-MLDSA65-ECDSA-P256-SHA512');
const PQ_PUB_LEN = 1952;
const PQ_SIG_LEN = 3309;
const EC_PUB_LEN = 65;
const SEED_LEN = 32;
// RFC 5915 ECPrivateKey for P-256: SEQ { INT 1, OCTET STRING d(32), [0] OID prime256v1 }, no public key
const EC_PRIV_HEAD = Uint8Array.of(0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20);
const EC_PRIV_TAIL = Uint8Array.of(0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07);
const SECRET_LEN = SEED_LEN + EC_PRIV_HEAD.length + 32 + EC_PRIV_TAIL.length; // 83

export interface CompositeKeyPair {
  publicKey: Uint8Array; // 2017
  secretKey: Uint8Array; // 83
}

/** M' = Prefix || Label || len(ctx)=0 || SHA-512(M). */
export function messageRepresentative(message: Uint8Array): Uint8Array {
  return concatBytes(PREFIX, LABEL, Uint8Array.of(0x00), sha512(message));
}

/** priv = ML-DSA-65 seed || ECPrivateKey(d), the same layout as nimbus's CompositeMLDSAKey "priv". */
export function encodeCompositeSecretKey(mldsaSeed: Uint8Array, ecdsaD: Uint8Array): Uint8Array {
  if (mldsaSeed.length !== SEED_LEN || ecdsaD.length !== 32) {
    throw new Error('Composite key: expected a 32-byte ML-DSA seed and a 32-byte P-256 scalar');
  }
  return concatBytes(mldsaSeed, EC_PRIV_HEAD, ecdsaD, EC_PRIV_TAIL);
}

function splitSecret(secretKey: Uint8Array): { seed: Uint8Array; d: Uint8Array } {
  if (secretKey.length !== SECRET_LEN) {
    throw new Error(`Composite secret key must be ${SECRET_LEN} bytes, got ${secretKey.length}`);
  }
  const start = SEED_LEN + EC_PRIV_HEAD.length;
  return { seed: secretKey.slice(0, SEED_LEN), d: secretKey.slice(start, start + 32) };
}

/** The composite public key (ML-DSA-65 pub || uncompressed P-256 point) derived from a secret key. */
export function compositePublicKeyFromSecret(secretKey: Uint8Array): Uint8Array {
  const { seed, d } = splitSecret(secretKey);
  return concatBytes(ml_dsa65.keygen(seed).publicKey, p256.getPublicKey(d, false));
}

export function generateCompositeKeyPair(): CompositeKeyPair {
  const secretKey = encodeCompositeSecretKey(randomBytes(SEED_LEN), p256.utils.randomSecretKey());
  return { publicKey: compositePublicKeyFromSecret(secretKey), secretKey };
}

export function signComposite(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  const { seed, d } = splitSecret(secretKey);
  const mPrime = messageRepresentative(message);
  const pqSig = ml_dsa65.sign(mPrime, ml_dsa65.keygen(seed).secretKey, { context: LABEL });
  const ecSig = p256.sign(mPrime, d, { format: 'der' });
  return concatBytes(pqSig, ecSig);
}

/** True only if BOTH component signatures verify. Never throws on malformed input (returns false). */
export function verifyComposite(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (publicKey.length !== PQ_PUB_LEN + EC_PUB_LEN || signature.length <= PQ_SIG_LEN) {
    return false;
  }
  try {
    const mPrime = messageRepresentative(message);
    const pqOk = ml_dsa65.verify(signature.slice(0, PQ_SIG_LEN), mPrime, publicKey.slice(0, PQ_PUB_LEN), { context: LABEL });
    const ecOk = p256.verify(signature.slice(PQ_SIG_LEN), mPrime, publicKey.slice(PQ_PUB_LEN), { format: 'der', lowS: false });
    return pqOk && ecOk;
  } catch {
    return false;
  }
}