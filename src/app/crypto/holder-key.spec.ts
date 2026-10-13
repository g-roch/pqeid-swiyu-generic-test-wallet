import { describe, it, expect } from 'vitest';
import { detectIssuerDpopAlg, generateHolderKeyPair, isAKPAlg, preferredAlg } from './holder-key';
import { COMPOSITE_ALG } from './composite';
import { signJwtWithHolderKey, verifyJwtWithJwk } from './jwt';
import { base64UrlDecode } from './base64url';
import type { AKPJwk } from './mldsa';

const issuer = (algs: string[]) => ({
  credential_configurations_supported: { vc: { proof_types_supported: { jwt: { proof_signing_alg_values_supported: algs } } } },
});

/** PQEID: composite holder keys, preferring hybrid among the algorithms the issuer advertises. */
describe('holder keys', () => {
  it('prefers the composite, then ML-DSA, never an unadvertised algorithm', () => {
    expect(preferredAlg(['ML-DSA-44', COMPOSITE_ALG])).toBe(COMPOSITE_ALG);
    expect(preferredAlg(['ES256', 'ML-DSA-44'])).toBe('ML-DSA-44');
    expect(preferredAlg(['ES256'])).toBe('ES256');
    expect(preferredAlg([])).toBeUndefined();
    expect(preferredAlg(undefined)).toBeUndefined();
  });

  it('recognises the AKP family', () => {
    expect(isAKPAlg(COMPOSITE_ALG)).toBe(true);
    expect(isAKPAlg('ML-DSA-44')).toBe(true);
    expect(isAKPAlg('ES256')).toBe(false);
  });

  it('generates a composite holder key with a public-only AKP JWK', async () => {
    const kp = await generateHolderKeyPair(COMPOSITE_ALG);
    expect(kp.kind).toBe('mldsa');
    const jwk = kp.jwk as AKPJwk;
    expect(jwk).toMatchObject({ kty: 'AKP', alg: COMPOSITE_ALG });
    expect(jwk.priv).toBeUndefined();
    expect(base64UrlDecode(jwk.pub).length).toBe(2017);
  });

  it('a composite holder key signs a proof that verifies with its JWK', async () => {
    const kp = await generateHolderKeyPair(COMPOSITE_ALG);
    const jwt = await signJwtWithHolderKey(kp, { nonce: 'n' }, { typ: 'openid4vci-proof+jwt', jwk: kp.jwk });
    expect((await verifyJwtWithJwk(jwt, kp.jwk)).protectedHeader['alg']).toBe(COMPOSITE_ALG);
  });

  it('DPoP follows the issuer: composite if advertised, else ML-DSA, else the existing fallbacks', () => {
    expect(detectIssuerDpopAlg(issuer(['ML-DSA-44', COMPOSITE_ALG]))).toBe(COMPOSITE_ALG);
    expect(detectIssuerDpopAlg(issuer(['ML-DSA-44']))).toBe('ML-DSA-44');
    expect(detectIssuerDpopAlg({ credential_response_encryption: { alg_values_supported: ['XWING'] } })).toBe('ML-DSA-44');
    expect(detectIssuerDpopAlg({})).toBe('ES256');
  });
});