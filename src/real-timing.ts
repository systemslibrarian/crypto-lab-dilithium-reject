/**
 * REAL timing measurement — this is not a simulation.
 *
 * We call `@noble/post-quantum`'s actual ml_dsa65.sign many times and record
 * the wall-clock duration of each call with `performance.now()`. Because real
 * ML-DSA signing runs the Fiat-Shamir-with-Aborts loop a variable number of
 * times, the measured durations genuinely vary — that variability is the whole
 * point of the demo, observed here on real signatures rather than simulated.
 *
 * Caveat (surfaced in the UI): browser `performance.now()` resolution is
 * coarse and deliberately jittered for security, and JIT warm-up / GC add
 * noise. Treat the SHAPE (a right-skewed spread) as meaningful, not the
 * absolute milliseconds.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from './mldsa-primitives';

export interface MeasureOptions {
  message?: Uint8Array;
  warmup?: number;
  onProgress?: (done: number) => void;
}

const encoder = new TextEncoder();

/**
 * Measure `count` real signing durations (ms). Runs a warm-up phase first to
 * let the JIT stabilise, then times each randomized signature, yielding to the
 * event loop in chunks so a caller on the main thread stays responsive.
 */
export async function measureRealSigningTimes(count: number, options: MeasureOptions = {}): Promise<number[]> {
  const keypair = ml_dsa65.keygen();
  const message = options.message ?? encoder.encode('timing-benchmark-message');
  const warmup = options.warmup ?? 20;
  const chunkSize = 25;

  for (let i = 0; i < warmup; i += 1) {
    ml_dsa65.sign(message, keypair.secretKey, { extraEntropy: randomBytes(32) });
  }

  const times: number[] = [];
  for (let i = 0; i < count; i += 1) {
    const extraEntropy = randomBytes(32);
    const t0 = performance.now();
    ml_dsa65.sign(message, keypair.secretKey, { extraEntropy });
    const t1 = performance.now();
    times.push(Math.max(0, t1 - t0));

    if (options.onProgress && (i + 1) % chunkSize === 0) {
      options.onProgress(i + 1);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  options.onProgress?.(count);
  return times;
}
