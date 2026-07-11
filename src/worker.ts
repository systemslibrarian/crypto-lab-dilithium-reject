/**
 * Off-main-thread compute. Real instrumented signing (single traces, histogram
 * batches, KS populations, trace search), the exploratory simulation batches,
 * and the real signing-time measurement all run here so the UI thread stays at
 * 60fps even while thousands of signatures are produced.
 *
 * Protocol: the page posts `{ id, kind, ... }`; the worker replies with
 * `{ id, type: 'progress' | 'result' | 'error', ... }`.
 */
import { collectIterationStatistics, PRESETS, type PresetName } from './instrumented-sign';
import { measureRealSigningTimes } from './real-timing';
import { REAL_PRESETS, realInstrumentedSign, type MlDsaPresetName, type RealIterationRecord } from './real-sign';
import { distinguishabilityTest, type TimingObservation } from './timing-analysis';

type WorkerRequest =
  | {
      id: number;
      kind: 'sign';
      preset: MlDsaPresetName;
      message: Uint8Array;
      secretKey: Uint8Array;
      extraEntropy?: Uint8Array;
    }
  | { id: number; kind: 'histogram'; count: number; preset: MlDsaPresetName }
  | { id: number; kind: 'histogram-sim'; count: number; preset: PresetName; acceptance: number }
  | { id: number; kind: 'find-trace'; preset: MlDsaPresetName; target: number; maxAttempts: number }
  | { id: number; kind: 'ks'; n: number; preset: MlDsaPresetName }
  | { id: number; kind: 'ks-leaky'; n: number; preset: PresetName; leakDelta: number }
  | { id: number; kind: 'realtiming'; count: number };

// Avoid pulling in the WebWorker lib (which conflicts with DOM `self`); a
// minimal structural cast is enough for postMessage/onmessage.
const ctx = self as unknown as {
  postMessage: (message: unknown) => void;
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
};

const yieldLoop = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

/** One cached keypair per preset, so batches don't pay keygen per signature. */
const keyCache = new Map<MlDsaPresetName, { secretKey: Uint8Array; publicKey: Uint8Array }>();
function presetKeypair(preset: MlDsaPresetName): { secretKey: Uint8Array; publicKey: Uint8Array } {
  let kp = keyCache.get(preset);
  if (!kp) {
    kp = REAL_PRESETS[preset].noble.keygen();
    keyCache.set(preset, kp);
  }
  return kp;
}

const encoder = new TextEncoder();

function quantileSorted(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  const low = sorted[lo] ?? 0;
  if (lo === hi) return low;
  return low + ((sorted[hi] ?? 0) - low) * (pos - lo);
}

/** Batch of REAL instrumented signatures: iteration counts + real reasons. */
async function realHistogramBatch(
  preset: MlDsaPresetName,
  count: number,
  onProgress: (done: number) => void,
): Promise<{
  iterationCounts: number[];
  reasonBreakdown: [string, number][];
  mean: number;
  median: number;
  p90: number;
  p99: number;
  max: number;
  measuredAcceptance: number;
}> {
  const kp = presetKeypair(preset);
  const msg = encoder.encode('histogram-batch');
  const iterationCounts: number[] = [];
  const reasons = new Map<string, number>();
  let totalIterations = 0;
  for (let i = 0; i < count; i += 1) {
    const res = realInstrumentedSign(preset, msg, kp.secretKey);
    iterationCounts.push(res.acceptedIteration);
    totalIterations += res.acceptedIteration;
    for (const rec of res.iterations) {
      if (rec.rejectionReason) reasons.set(rec.rejectionReason, (reasons.get(rec.rejectionReason) ?? 0) + 1);
    }
    if ((i + 1) % 10 === 0) {
      onProgress(i + 1);
      await yieldLoop();
    }
  }
  onProgress(count);
  const sorted = [...iterationCounts].sort((a, b) => a - b);
  const sum = iterationCounts.reduce((a, b) => a + b, 0);
  return {
    iterationCounts,
    reasonBreakdown: [...reasons.entries()],
    mean: count > 0 ? sum / count : 0,
    median: quantileSorted(sorted, 0.5),
    p90: quantileSorted(sorted, 0.9),
    p99: quantileSorted(sorted, 0.99),
    max: sorted.at(-1) ?? 0,
    measuredAcceptance: totalIterations > 0 ? count / totalIterations : 0,
  };
}

/** Real iteration counts for one fresh keypair (one KS population). */
async function realIterationPopulation(
  preset: MlDsaPresetName,
  n: number,
  onProgress: (done: number) => void,
): Promise<number[]> {
  const kp = REAL_PRESETS[preset].noble.keygen(); // fresh key per population — that's the point
  const msg = encoder.encode('ks-population');
  const counts: number[] = [];
  for (let i = 0; i < n; i += 1) {
    counts.push(realInstrumentedSign(preset, msg, kp.secretKey).acceptedIteration);
    if ((i + 1) % 10 === 0) {
      onProgress(i + 1);
      await yieldLoop();
    }
  }
  onProgress(n);
  return counts;
}

const asObservations = (counts: number[]): TimingObservation[] =>
  counts.map((c, i) => ({ signatureIndex: i, observedTimeMs: 0, inferredIterations: c }));

/** Simulated geometric population at acceptance probability p. */
async function simulatedPopulation(p: number, n: number, onProgress: (done: number) => void): Promise<number[]> {
  const counts: number[] = [];
  for (let i = 0; i < n; i += 1) {
    let k = 1;
    // Direct geometric draw — same model as simulateRejectionTrace, minus the
    // per-iteration record cost, so leak-mode populations build instantly.
    const buf = new Uint32Array(1);
    for (;;) {
      crypto.getRandomValues(buf);
      if ((buf[0] ?? 0) / 0x100000000 < p) break;
      k += 1;
    }
    counts.push(k);
    if ((i + 1) % 200 === 0) {
      onProgress(i + 1);
      await yieldLoop();
    }
  }
  onProgress(n);
  return counts;
}

ctx.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data;
  try {
    if (msg.kind === 'sign') {
      const iterations: RealIterationRecord[] = [];
      const res = realInstrumentedSign(msg.preset, msg.message, msg.secretKey, {
        detail: true,
        extraEntropy: msg.extraEntropy,
        onIteration: (r) => iterations.push(r),
      });
      ctx.postMessage({
        id: msg.id,
        type: 'result',
        payload: {
          signature: res.signature,
          iterations,
          acceptedIteration: res.acceptedIteration,
          totalTimeMs: res.totalTimeMs,
        },
      });
    } else if (msg.kind === 'histogram') {
      const payload = await realHistogramBatch(msg.preset, msg.count, (done) =>
        ctx.postMessage({ id: msg.id, type: 'progress', done }),
      );
      ctx.postMessage({ id: msg.id, type: 'result', payload });
    } else if (msg.kind === 'histogram-sim') {
      const stats = await collectIterationStatistics(msg.count, {
        preset: msg.preset,
        acceptance: msg.acceptance,
        onProgress: (done) => ctx.postMessage({ id: msg.id, type: 'progress', done }),
      });
      ctx.postMessage({
        id: msg.id,
        type: 'result',
        payload: {
          iterationCounts: stats.iterationCounts,
          reasonBreakdown: [...stats.rejectionReasonBreakdown.entries()],
          mean: stats.mean,
          median: stats.median,
          p90: stats.p90,
          p99: stats.p99,
          max: stats.max,
          measuredAcceptance: 0,
        },
      });
    } else if (msg.kind === 'find-trace') {
      // Search for a REAL trace of exactly `target` iterations: light-mode
      // signs with recorded entropy until one matches, then one detail-mode
      // re-sign with that entropy reproduces it with all four checks filled.
      const kp = presetKeypair(msg.preset);
      const message = encoder.encode('histogram-batch');
      let found: Uint8Array | null = null;
      let attempts = 0;
      while (attempts < msg.maxAttempts && found === null) {
        const entropy = new Uint8Array(32);
        crypto.getRandomValues(entropy);
        const res = realInstrumentedSign(msg.preset, message, kp.secretKey, { extraEntropy: entropy });
        attempts += 1;
        if (res.acceptedIteration === msg.target) found = entropy;
        if (attempts % 20 === 0) {
          ctx.postMessage({ id: msg.id, type: 'progress', done: attempts });
          await yieldLoop();
        }
      }
      if (found === null) {
        ctx.postMessage({ id: msg.id, type: 'result', payload: { found: false, attempts } });
      } else {
        const res = realInstrumentedSign(msg.preset, message, kp.secretKey, {
          extraEntropy: found,
          detail: true,
        });
        ctx.postMessage({
          id: msg.id,
          type: 'result',
          payload: { found: true, attempts, iterations: res.iterations },
        });
      }
    } else if (msg.kind === 'ks') {
      let a = 0;
      let b = 0;
      const obs1 = await realIterationPopulation(msg.preset, msg.n, (d) => {
        a = d;
        ctx.postMessage({ id: msg.id, type: 'progress', a, b });
      });
      const obs2 = await realIterationPopulation(msg.preset, msg.n, (d) => {
        b = d;
        ctx.postMessage({ id: msg.id, type: 'progress', a, b });
      });
      ctx.postMessage({
        id: msg.id,
        type: 'result',
        payload: {
          a: obs1,
          b: obs2,
          verdict: distinguishabilityTest(asObservations(obs1), asObservations(obs2)),
        },
      });
    } else if (msg.kind === 'ks-leaky') {
      // Positive control: population from a HYPOTHETICAL broken implementation
      // whose acceptance probability depends on the secret key. Which of A/B
      // is leaky is randomized here and only revealed after the user guesses.
      const honestP = PRESETS[msg.preset].acceptance;
      const leakyP = Math.max(0.05, honestP - msg.leakDelta);
      const coin = new Uint8Array(1);
      crypto.getRandomValues(coin);
      const leakyIsA = ((coin[0] ?? 0) & 1) === 1;
      let a = 0;
      let b = 0;
      const popA = await simulatedPopulation(leakyIsA ? leakyP : honestP, msg.n, (d) => {
        a = d;
        ctx.postMessage({ id: msg.id, type: 'progress', a, b });
      });
      const popB = await simulatedPopulation(leakyIsA ? honestP : leakyP, msg.n, (d) => {
        b = d;
        ctx.postMessage({ id: msg.id, type: 'progress', a, b });
      });
      ctx.postMessage({
        id: msg.id,
        type: 'result',
        payload: {
          a: popA,
          b: popB,
          leakyIs: leakyIsA ? 'a' : 'b',
          honestP,
          leakyP,
          verdict: distinguishabilityTest(asObservations(popA), asObservations(popB)),
        },
      });
    } else if (msg.kind === 'realtiming') {
      const times = await measureRealSigningTimes(msg.count, {
        onProgress: (done) => ctx.postMessage({ id: msg.id, type: 'progress', done }),
      });
      ctx.postMessage({ id: msg.id, type: 'result', payload: { times } });
    }
  } catch (err) {
    ctx.postMessage({ id: msg.id, type: 'error', error: String((err as Error)?.message ?? err) });
  }
};
