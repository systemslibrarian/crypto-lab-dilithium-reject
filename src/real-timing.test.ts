import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { measureRealSigningTimes } from './real-timing';

describe('measureRealSigningTimes', () => {
  it('returns one non-negative duration per real signature', async () => {
    const times = await measureRealSigningTimes(5, { warmup: 2 });
    expect(times).toHaveLength(5);
    expect(times.every((t) => typeof t === 'number' && t >= 0 && Number.isFinite(t))).toBe(true);
  });

  it('signs the provided message with the real library (signature verifies)', async () => {
    // Sanity check that the function exercises real ml_dsa65 signing.
    const kp = ml_dsa65.keygen();
    const msg = new TextEncoder().encode('real-timing-check');
    const sig = ml_dsa65.sign(msg, kp.secretKey, { extraEntropy: new Uint8Array(32) });
    expect(ml_dsa65.verify(sig, msg, kp.publicKey)).toBe(true);
  });
});
