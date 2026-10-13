import { describe, it, expect } from 'vitest';
import vector from './testdata/ML-DSA-65-ES256.json';
import { signJwtWithHolderKey, verifyJwtWithJwk } from './jwt';
import { COMPOSITE_ALG, generateCompositeKeyPair } from './composite';
import type { AKPJwk } from './mldsa';
import type { HolderKeyPair } from './holder-key';
import { base64UrlEncode } from './base64url';
import { generateHolderKeyPair } from './holder-key';

/** PQEID: wallet JWT signing/verification with composite ML-DSA-65-ES256. */
describe('JWT with composite ML-DSA-65-ES256', () => {
  const { priv: _priv, ...officialPublicJwk } = vector.jwk as unknown as AKPJwk & { priv: string };

  it("verifies the draft's official JWS signature (its payload is plain text, not a JWT)", async () => {
    // The vector's payload is "It's a dangerous business, Frodo, going out your door." (JOSE test-vector
    // tradition), so verifyMLDSAJwt passes the signature check and then fails parsing the payload as JSON.
    // Assert exactly that: anything else (e.g. "signature verification failed") would be a real failure.
    await expect(verifyJwtWithJwk(vector.jws, officialPublicJwk as AKPJwk))
      .rejects.toThrow(/JSON/);
    await expect(verifyJwtWithJwk(vector.jws, officialPublicJwk as AKPJwk))
      .rejects.not.toThrow(/signature verification failed|Unexpected alg/);
  });

  it('rejects the official JWS with a tampered payload', async () => {
     const [h, p, s] = vector.jws.split('.');
    const q = p.slice(0, 5) + (p[5] === 'A' ? 'B' : 'A') + p.slice(6);
    await expect(verifyJwtWithJwk(`${h}.${q}.${s}`, officialPublicJwk as AKPJwk)).rejects.toThrow();
  });

  it("rejects a header alg that differs from the key's alg (alg confusion)", async () => {
    const wrongAlgJwk = { ...officialPublicJwk, alg: 'ML-DSA-65' } as AKPJwk;
    await expect(verifyJwtWithJwk(vector.jws, wrongAlgJwk)).rejects.toThrow(/Unexpected alg/);
  });

  it('signs with a composite holder key and verifies it back', async () => {
    const kp = generateCompositeKeyPair();
    const jwk: AKPJwk = { kty: 'AKP', alg: COMPOSITE_ALG, pub: base64UrlEncode(kp.publicKey) };
    const holder: HolderKeyPair = { kind: 'mldsa', alg: COMPOSITE_ALG, secretKey: kp.secretKey, publicKey: kp.publicKey, jwk };

    const jwt = await signJwtWithHolderKey(holder, { nonce: 'n' }, { typ: 'openid4vci-proof+jwt', jwk }, { audience: 'https://issuer' });
    const { payload, protectedHeader } = await verifyJwtWithJwk(jwt, jwk);

    expect(protectedHeader['alg']).toBe(COMPOSITE_ALG);
    expect(payload['aud']).toBe('https://issuer');
      });
});

 describe('verification policy', () => {
    const EXPAND = ['ML-DSA-44', COMPOSITE_ALG] as const;

    it('accepts a composite JWT under the expand policy', async () => {
      const kp = generateCompositeKeyPair();
      const jwk: AKPJwk = { kty: 'AKP', alg: COMPOSITE_ALG, pub: base64UrlEncode(kp.publicKey) };
      const holder: HolderKeyPair = { kind: 'mldsa', alg: COMPOSITE_ALG, secretKey: kp.secretKey, publicKey: kp.publicKey, jwk };
      const jwt = await signJwtWithHolderKey(holder, { sub: 's' }, {});
      await expect(verifyJwtWithJwk(jwt, jwk, EXPAND)).resolves.toBeTruthy();
    });

    it('refuses a classical ES256 JWT (fail closed), before any crypto', async () => {
      // No real ES256 key/signature needed (and jose + jsdom's CryptoKey don't mix): the policy must
      // refuse on the header alg alone, before any key handling or signature check.
      const b64 = (o: object) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(o)));
      const jwt = `${b64({ alg: 'ES256' })}.${b64({ sub: 's' })}.AAAA`;
      const ecJwk = { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA', alg: 'ES256' };
      await expect(verifyJwtWithJwk(jwt, ecJwk, EXPAND)).rejects.toThrow(/not accepted/);
    });

    it('contract policy (composite only) refuses ML-DSA-44', async () => {
      const kp = await generateHolderKeyPair('ML-DSA-44');
      const jwt = await signJwtWithHolderKey(kp, { sub: 's' }, {});
      await expect(verifyJwtWithJwk(jwt, kp.jwk, [COMPOSITE_ALG])).rejects.toThrow(/not accepted/);
    });
  });
