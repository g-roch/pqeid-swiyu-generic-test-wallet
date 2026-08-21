/**
 * PQEID: RFC 7518 §4.6.2 Concat KDF (NIST SP 800-56A Concatenation KDF, SHA-256).
 *
 * Needed to derive the JWE Content Encryption Key (CEK) from the X-Wing KEM shared secret
 * in xwing.ts, mirroring how the Java fork's ECDHCryptoProvider.encryptWithZ()/
 * decryptWithZ() derive the CEK for XWingEncrypter/XWingDecrypter on the backend (treated
 * as ECDH-ES "Direct Key Agreement" mode: AlgorithmID = the JWE "enc" value's UTF-8 bytes,
 * PartyUInfo/PartyVInfo empty, SuppPubInfo = keydatalen as a 32-bit big-endian integer,
 * SuppPrivInfo empty). Both sides must derive byte-identical CEKs from the same shared
 * secret for content decryption to succeed.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8Encode } from "./base64url";

function uint32BE(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/** A single "PartyUInfo"/"PartyVInfo"/"SuppPubInfo"/"SuppPrivInfo"-style datum: length-prefixed bytes. */
function lengthPrefixed(data: Uint8Array): Uint8Array {
  return concatBytes(uint32BE(data.length), data);
}

/**
 * RFC 7518 §4.6.2 Concat KDF, SHA-256 hash function (the only hash JOSE's ECDH-ES ever
 * uses). `keyDataLenBits` is the desired output key length in *bits* (e.g. 128 or 256 for
 * A128GCM/A256GCM).
 */
export function concatKdf(
  sharedSecret: Uint8Array,
  keyDataLenBits: number,
  algorithmId: Uint8Array,
  partyUInfo: Uint8Array = new Uint8Array(0),
  partyVInfo: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const keyDataLenBytes = keyDataLenBits / 8;
  const otherInfo = concatBytes(
    lengthPrefixed(algorithmId),
    lengthPrefixed(partyUInfo),
    lengthPrefixed(partyVInfo),
    uint32BE(keyDataLenBits),
  );

  const hashLenBytes = 32; // SHA-256 output size
  const reps = Math.ceil(keyDataLenBytes / hashLenBytes);
  if (reps > 0xffffffff) {
    throw new Error("Concat KDF: requested key length is too large");
  }

  const chunks: Uint8Array[] = [];
  for (let counter = 1; counter <= reps; counter++) {
    const input = concatBytes(uint32BE(counter), sharedSecret, otherInfo);
    chunks.push(sha256(input));
  }

  return concatBytes(...chunks).slice(0, keyDataLenBytes);
}

/**
 * Convenience wrapper matching how ECDHCryptoProvider derives the CEK in "Direct Key
 * Agreement" mode: AlgorithmID is the JWE "enc" value's UTF-8 bytes, PartyUInfo/PartyVInfo
 * are empty (this codebase never sets apu/apv), and the output length is the target
 * content-encryption key length for that "enc" algorithm.
 */
export function deriveDirectCek(
  sharedSecret: Uint8Array,
  enc: string,
  keyDataLenBits: number,
): Uint8Array {
  return concatKdf(sharedSecret, keyDataLenBits, utf8Encode(enc));
}
