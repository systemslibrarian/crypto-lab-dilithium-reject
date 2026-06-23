/**
 * Off-main-thread compute. The simulated histogram batches, the KS
 * two-population collection, and the REAL signing-time measurement all run
 * here so the UI thread stays at 60fps (animations, theme toggles, scrolling)
 * even while thousands of signatures are produced.
 *
 * Protocol: the page posts `{ id, kind, ... }`; the worker replies with
 * `{ id, type: 'progress' | 'result' | 'error', ... }`.
 */
import { collectIterationStatistics, type PresetName } from './instrumented-sign';
import { measureRealSigningTimes } from './real-timing';
import { collectTimingObservations, distinguishabilityTest } from './timing-analysis';

type WorkerRequest =
  | { id: number; kind: 'histogram'; count: number; preset: PresetName; acceptance?: number }
  | { id: number; kind: 'ks'; n: number; preset: PresetName }
  | { id: number; kind: 'realtiming'; count: number };

// Avoid pulling in the WebWorker lib (which conflicts with DOM `self`); a
// minimal structural cast is enough for postMessage/onmessage.
const ctx = self as unknown as {
  postMessage: (message: unknown) => void;
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
};

ctx.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data;
  try {
    if (msg.kind === 'histogram') {
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
        },
      });
    } else if (msg.kind === 'ks') {
      let a = 0;
      let b = 0;
      const [obs1, obs2] = await Promise.all([
        collectTimingObservations(msg.n, {
          preset: msg.preset,
          onProgress: (d) => {
            a = d;
            ctx.postMessage({ id: msg.id, type: 'progress', a, b });
          },
        }),
        collectTimingObservations(msg.n, {
          preset: msg.preset,
          onProgress: (d) => {
            b = d;
            ctx.postMessage({ id: msg.id, type: 'progress', a, b });
          },
        }),
      ]);
      ctx.postMessage({
        id: msg.id,
        type: 'result',
        payload: {
          a: obs1.map((o) => o.inferredIterations),
          b: obs2.map((o) => o.inferredIterations),
          verdict: distinguishabilityTest(obs1, obs2),
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
