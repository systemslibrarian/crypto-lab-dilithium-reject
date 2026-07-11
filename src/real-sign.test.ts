import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { REAL_PRESETS, type MlDsaPresetName, type RealIterationRecord, realInstrumentedSign } from './real-sign';

const PRESET_NAMES = Object.keys(REAL_PRESETS) as MlDsaPresetName[];
const encoder = new TextEncoder();

function fixedEntropy(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

describe('real instrumented sign — byte-identical to untouched noble', () => {
  for (const preset of PRESET_NAMES) {
    it(`${preset}: same secretKey + extraEntropy ⇒ identical signature bytes`, () => {
      const { noble } = REAL_PRESETS[preset];
      const kp = noble.keygen();
      const msg = encoder.encode('cross-validation message');
      // Several entropies so different iteration counts are exercised.
      for (const fill of [0, 1, 7, 42, 255]) {
        const entropy = fixedEntropy(fill);
        const reference = noble.sign(msg, kp.secretKey, { extraEntropy: entropy });
        const instrumented = realInstrumentedSign(preset, msg, kp.secretKey, { extraEntropy: entropy });
        expect(Buffer.from(instrumented.signature).equals(Buffer.from(reference))).toBe(true);
        expect(noble.verify(instrumented.signature, msg, kp.publicKey)).toBe(true);
      }
    }, 60000);
  }

  it('detail mode and light mode produce the same signature and iteration count', () => {
    const { noble } = REAL_PRESETS['ML-DSA-65'];
    const kp = noble.keygen();
    const msg = encoder.encode('detail-vs-light');
    for (const fill of [3, 9, 77]) {
      const entropy = fixedEntropy(fill);
      const light = realInstrumentedSign('ML-DSA-65', msg, kp.secretKey, { extraEntropy: entropy });
      const detail = realInstrumentedSign('ML-DSA-65', msg, kp.secretKey, { extraEntropy: entropy, detail: true });
      expect(Buffer.from(light.signature).equals(Buffer.from(detail.signature))).toBe(true);
      expect(light.acceptedIteration).toBe(detail.acceptedIteration);
      expect(light.iterations.map((r) => r.rejectionReason)).toEqual(detail.iterations.map((r) => r.rejectionReason));
    }
  }, 60000);
});

describe('real iteration records', () => {
  it('detail mode: every check is populated, internally consistent, and the last record accepts', () => {
    const { noble, params } = REAL_PRESETS['ML-DSA-65'];
    const kp = noble.keygen();
    const streamed: RealIterationRecord[] = [];
    const res = realInstrumentedSign('ML-DSA-65', encoder.encode('records'), kp.secretKey, {
      detail: true,
      onIteration: (r) => streamed.push(r),
    });
    expect(streamed).toHaveLength(res.iterations.length);
    expect(res.acceptedIteration).toBe(res.iterations.length);

    const last = res.iterations.at(-1);
    expect(last?.result).toBe('ACCEPTED');
    expect(last?.rejectionReason).toBeNull();

    for (const [idx, rec] of res.iterations.entries()) {
      expect(rec.kappa).toBe(idx * params.l);
      expect(rec.cTildeHex).toMatch(/^[0-9a-f]{8}$/);
      expect(rec.yInf).toBeGreaterThan(0);
      expect(rec.yInf).toBeLessThanOrEqual(params.gamma1);
      for (const key of ['z', 'r0', 'ct0', 'hint'] as const) {
        const check = rec[key];
        expect(check, `${key} at iteration ${idx}`).not.toBeNull();
        if (!check) continue;
        if (key === 'hint') expect(check.pass).toBe(check.value <= check.threshold);
        else expect(check.pass).toBe(check.value < check.threshold);
      }
      if (rec.result === 'REJECTED') {
        expect(rec.rejectionReason).not.toBeNull();
        // The stated reason's check must actually fail.
        const failing = {
          z_too_large: rec.z,
          r0_too_large: rec.r0,
          ct0_too_large: rec.ct0,
          hint_too_dense: rec.hint,
        }[rec.rejectionReason ?? 'z_too_large'];
        expect(failing?.pass).toBe(false);
      } else {
        expect(rec.z?.pass && rec.r0?.pass && rec.ct0?.pass && rec.hint?.pass).toBe(true);
      }
    }
  }, 60000);

  it('measured acceptance rate over a real batch is in a sane band (ML-DSA-65)', () => {
    const { noble } = REAL_PRESETS['ML-DSA-65'];
    const kp = noble.keygen();
    const msg = encoder.encode('acceptance-batch');
    let signatures = 0;
    let iterations = 0;
    for (let i = 0; i < 150; i += 1) {
      const res = realInstrumentedSign('ML-DSA-65', msg, kp.secretKey);
      signatures += 1;
      iterations += res.acceptedIteration;
    }
    const pHat = signatures / iterations;
    // The Dilithium spec's expected repetitions for level 3 is 5.1, i.e.
    // p ≈ 0.196; a wide band keeps the test meaningful without flaking at N=150.
    expect(pHat).toBeGreaterThan(0.13);
    expect(pHat).toBeLessThan(0.28);
  }, 120000);

  it('deterministic variant (extraEntropy: false) reproduces the exact same trace', () => {
    const { noble } = REAL_PRESETS['ML-DSA-65'];
    const kp = noble.keygen();
    const msg = encoder.encode('deterministic');
    const a = realInstrumentedSign('ML-DSA-65', msg, kp.secretKey, { extraEntropy: false, detail: true });
    const b = realInstrumentedSign('ML-DSA-65', msg, kp.secretKey, { extraEntropy: false, detail: true });
    expect(Buffer.from(a.signature).equals(Buffer.from(b.signature))).toBe(true);
    expect(a.iterations.map((r) => r.cTildeHex)).toEqual(b.iterations.map((r) => r.cTildeHex));
    expect(noble.verify(a.signature, msg, kp.publicKey)).toBe(true);
    expect(ml_dsa65.verify(a.signature, msg, kp.publicKey)).toBe(true);
  }, 60000);
});
