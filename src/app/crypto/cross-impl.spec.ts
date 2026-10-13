import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateHolderKeyPair } from './holder-key';
import { signJwtWithHolderKey, verifyJwtWithJwk } from './jwt';
import { COMPOSITE_ALG } from './composite';
import type { AKPJwk } from './mldsa';

const dir = process.env['CROSS_IMPL_DIR'];

/** PQEID: cross-implementation with nimbus (Java). Runs only with CROSS_IMPL_DIR set (guide §42). */
describe.skipIf(!dir)('cross-implementation with nimbus', () => {
  it('verifies a composite JWT signed by nimbus', async () => {
    const f = join(dir!, 'java-signed.json');
    expect(existsSync(f)).toBe(true);
    const { jwk, jwt } = JSON.parse(readFileSync(f, 'utf8'));
    const { payload, protectedHeader } = await verifyJwtWithJwk(jwt, jwk as AKPJwk);
    expect(protectedHeader['alg']).toBe(COMPOSITE_ALG);
    expect(payload['sub']).toBe('signed-by-nimbus');
});

  it('signs a composite JWT for nimbus to verify', async () => {
    const kp = await generateHolderKeyPair(COMPOSITE_ALG);
    const jwt = await signJwtWithHolderKey(kp, { sub: 'signed-by-wallet' }, { kid: 'wallet-key' });
    writeFileSync(join(dir!, 'ts-signed.json'), JSON.stringify({ jwk: { ...kp.jwk, kid: 'wallet-key' }, jwt }));
  });
});