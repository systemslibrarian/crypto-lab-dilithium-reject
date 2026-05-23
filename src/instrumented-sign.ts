/**
 * Didactic ML-DSA rejection-sampling trace.
 *
 * This module simulates the FIPS 204 Fiat-Shamir-with-Aborts loop for
 * teaching purposes. Each iteration is a calibrated coin flip:
 *   - acceptance probability is fixed per preset to match published
 *     ML-DSA implementation results;
 *   - when a candidate is rejected, the rejection reason is sampled
 *     from the published reason mix and the displayed ||z||, ||r0||,
 *     ||c*t0|| values are positioned above/below their thresholds
 *     consistently with that reason.
 *
 * The displayed values are NOT computed from a live z = y + c*s1 etc.
 * The returned signature IS real: it is produced by `@noble/post-quantum`
 * ml_dsa65, independent of the iteration trace.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  ML_DSA_65,
  expandMask,
  hintWeight,
  infinityNorm,
  randomBytes,
  randomInt,
  sampleInBall,
  uniform01,
} from './mldsa-primitives';

export type PresetName = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

interface PresetParams {
  acceptance: number;
  rejectionMix: { z: number; r0: number; ct0: number; hint: number };
  gamma1: number;
  gamma2: number;
  beta: number;
  omega: number;
}

export const PRESETS: Record<PresetName, PresetParams> = {
  'ML-DSA-44': {
    acceptance: 0.31,
    rejectionMix: { z: 0.50, r0: 0.42, ct0: 0.07, hint: 0.01 },
    gamma1: 131072,
    gamma2: 95232,
    beta: 78,
    omega: 80,
  },
  'ML-DSA-65': {
    acceptance: 0.26,
    rejectionMix: { z: 0.52, r0: 0.41, ct0: 0.06, hint: 0.01 },
    gamma1: ML_DSA_65.gamma1,
    gamma2: ML_DSA_65.gamma2,
    beta: ML_DSA_65.beta,
    omega: ML_DSA_65.omega,
  },
  'ML-DSA-87': {
    acceptance: 0.22,
    rejectionMix: { z: 0.53, r0: 0.40, ct0: 0.06, hint: 0.01 },
    gamma1: 524288,
    gamma2: 261888,
    beta: 120,
    omega: 75,
  },
};

export interface IterationRecord {
  kappa: number;
  yStats: {
    infNorm: number;
    maxCoefficient: number;
    minCoefficient: number;
  };
  cTildeFingerprint: string;
  sampleInBall: {
    nonzeroPositions: number[];
  };
  zStats: {
    infNorm: number;
    checkThreshold: number;
    passesCheck: boolean;
  } | null;
  r0Stats: {
    infNorm: number;
    checkThreshold: number;
    passesCheck: boolean;
  } | null;
  ct0Stats: {
    infNorm: number;
    checkThreshold: number;
    passesCheck: boolean;
  } | null;
  hintWeight: number | null;
  hintThreshold: number;
  result: 'REJECTED' | 'ACCEPTED';
  rejectionReason: 'z_too_large' | 'r0_too_large' | 'ct0_too_large' | 'hint_too_dense' | null;
  timeMs: number;
}

export interface SigningResult {
  signature: Uint8Array;
  iterations: IterationRecord[];
  acceptedIteration: number;
  totalTimeMs: number;
  message: string;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function utf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function chooseRejectionReason(
  mix: PresetParams['rejectionMix'],
): IterationRecord['rejectionReason'] {
  const x = uniform01();
  const cz = mix.z;
  const cr0 = cz + mix.r0;
  const cct0 = cr0 + mix.ct0;
  if (x < cz) return 'z_too_large';
  if (x < cr0) return 'r0_too_large';
  if (x < cct0) return 'ct0_too_large';
  return 'hint_too_dense';
}

function summarizePolyRange(poly: Int32Array): { min: number; max: number } {
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  for (let i = 0; i < poly.length; i += 1) {
    const v = poly[i] ?? 0;
    if (v < min) min = v;
    if (v > max) max = v;
  }
  return { min, max };
}

function nonzeroPositions(poly: Int32Array): number[] {
  const out: number[] = [];
  for (let i = 0; i < poly.length; i += 1) {
    if ((poly[i] ?? 0) !== 0) out.push(i);
  }
  return out;
}

function quantile(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  if (lo === hi) return sorted[lo] ?? 0;
  const weight = pos - lo;
  const low = sorted[lo] ?? 0;
  const high = sorted[hi] ?? 0;
  return low + (high - low) * weight;
}

export async function instrumentedSign(
  message: Uint8Array,
  secretKey: Uint8Array,
  onIteration?: (record: IterationRecord) => void,
  options: { preset?: PresetName; maxIterations?: number } = {},
): Promise<SigningResult> {
  const preset = options.preset ?? 'ML-DSA-65';
  const maxIterations = options.maxIterations ?? 100;
  const params = PRESETS[preset];
  const rhoPrime = randomBytes(64);
  const iterations: IterationRecord[] = [];
  let kappa = 0;
  let accepted = false;

  while (!accepted) {
    if (iterations.length >= maxIterations) {
      throw new Error(`Reached max iterations (${maxIterations}) before acceptance`);
    }

    const y = expandMask(rhoPrime, kappa, params.gamma1, ML_DSA_65.n);
    const yRange = summarizePolyRange(y);
    const cTilde = randomBytes(32);
    const c = await sampleInBall(cTilde, ML_DSA_65.tau, ML_DSA_65.n);

    const zThreshold = params.gamma1 - params.beta;
    const r0Threshold = params.gamma2 - params.beta;
    const ct0Threshold = params.gamma2;

    const shouldAccept = uniform01() < params.acceptance;
    const reason = shouldAccept ? null : chooseRejectionReason(params.rejectionMix);

    const zInf = shouldAccept || reason !== 'z_too_large'
      ? randomInt(Math.max(0, zThreshold - 2400), zThreshold - 1)
      : randomInt(zThreshold, zThreshold + 3200);
    const r0Inf = shouldAccept || reason !== 'r0_too_large'
      ? randomInt(Math.max(0, r0Threshold - 1800), r0Threshold - 1)
      : randomInt(r0Threshold, r0Threshold + 2600);
    const ct0Inf = shouldAccept || reason !== 'ct0_too_large'
      ? randomInt(Math.max(0, ct0Threshold - 1400), ct0Threshold - 1)
      : randomInt(ct0Threshold, ct0Threshold + 2200);

    const hintPoly = new Int32Array(ML_DSA_65.n);
    const forcedHint = reason === 'hint_too_dense';
    const targetHintWeight = forcedHint
      ? randomInt(params.omega + 1, params.omega + 10)
      : randomInt(0, params.omega);
    for (let i = 0; i < targetHintWeight; i += 1) {
      hintPoly[randomInt(0, ML_DSA_65.n - 1)] = 1;
    }

    const record: IterationRecord = {
      kappa,
      yStats: {
        infNorm: infinityNorm(y, ML_DSA_65.q),
        maxCoefficient: yRange.max,
        minCoefficient: yRange.min,
      },
      cTildeFingerprint: bytesToHex(cTilde).slice(0, 8),
      sampleInBall: {
        nonzeroPositions: nonzeroPositions(c),
      },
      zStats: {
        infNorm: zInf,
        checkThreshold: zThreshold,
        passesCheck: zInf < zThreshold,
      },
      r0Stats: {
        infNorm: r0Inf,
        checkThreshold: r0Threshold,
        passesCheck: r0Inf < r0Threshold,
      },
      ct0Stats: {
        infNorm: ct0Inf,
        checkThreshold: ct0Threshold,
        passesCheck: ct0Inf < ct0Threshold,
      },
      hintWeight: hintWeight([hintPoly]),
      hintThreshold: params.omega,
      result: shouldAccept ? 'ACCEPTED' : 'REJECTED',
      rejectionReason: reason,
      timeMs: 0.11 + uniform01() * 0.09,
    };

    iterations.push(record);
    onIteration?.(record);
    accepted = shouldAccept;
    if (!accepted) kappa += ML_DSA_65.l;
  }

  const signature = ml_dsa65.sign(message, secretKey, { extraEntropy: randomBytes(32) });
  const totalTimeMs = iterations.reduce((acc, it) => acc + it.timeMs, 0);

  return {
    signature,
    iterations,
    acceptedIteration: iterations.length,
    totalTimeMs,
    message: utf8(message),
  };
}

export async function collectIterationStatistics(
  numSignatures: number,
  secretKey: Uint8Array,
  message: Uint8Array,
  options: { preset?: PresetName; onProgress?: (done: number) => void } = {},
): Promise<{
  iterationCounts: number[];
  mean: number;
  median: number;
  p90: number;
  p99: number;
  max: number;
  rejectionReasonBreakdown: Map<string, number>;
}> {
  const iterationCounts: number[] = [];
  const reasons = new Map<string, number>();
  const chunkSize = 25;

  for (let i = 0; i < numSignatures; i += 1) {
    const res = await instrumentedSign(message, secretKey, undefined, { preset: options.preset });
    iterationCounts.push(res.acceptedIteration);
    for (const iter of res.iterations) {
      if (iter.result === 'REJECTED' && iter.rejectionReason) {
        reasons.set(iter.rejectionReason, (reasons.get(iter.rejectionReason) ?? 0) + 1);
      }
    }
    if (options.onProgress && (i + 1) % chunkSize === 0) {
      options.onProgress(i + 1);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  options.onProgress?.(numSignatures);

  const sorted = [...iterationCounts].sort((a, b) => a - b);
  const sum = iterationCounts.reduce((a, b) => a + b, 0);
  return {
    iterationCounts,
    mean: iterationCounts.length > 0 ? sum / iterationCounts.length : 0,
    median: quantile(sorted, 0.5),
    p90: quantile(sorted, 0.9),
    p99: quantile(sorted, 0.99),
    max: sorted.at(-1) ?? 0,
    rejectionReasonBreakdown: reasons,
  };
}
