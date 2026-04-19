import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import './style.css';
import {
  collectIterationStatistics,
  type IterationRecord,
  instrumentedSign,
} from './instrumented-sign';
import { ML_DSA_65, expandMask, lowBits, randomBytes, sampleInBall } from './mldsa-primitives';
import { collectTimingObservations, distinguishabilityTest } from './timing-analysis';

type ParamPreset = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

interface AppState {
  keypair: { secretKey: Uint8Array; publicKey: Uint8Array };
  currentMessage: string;
  iterationHistory: number[];
  histogramRuns: number;
  runningHistogram: boolean;
  currentPreset: ParamPreset;
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('Missing #app container');

const encoder = new TextEncoder();
const fmt = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 });

const state: AppState = {
  keypair: ml_dsa65.keygen(),
  currentMessage: 'Transfer $1000 to Bob',
  iterationHistory: [],
  histogramRuns: 0,
  runningHistogram: false,
  currentPreset: 'ML-DSA-65',
};

app.innerHTML = `
<main class="lab">
  <header class="hero card">
    <p class="eyebrow">crypto-lab-dilithium-reject</p>
    <h1>ML-DSA Rejection Sampling Explorer</h1>
    <p class="lede">Fiat-Shamir with Aborts is visible iteration-by-iteration: each candidate signature is accepted or rejected with explicit norm bounds.</p>
    <div class="hero-tags">
      <span>FIPS 204 (ML-DSA-65)</span>
      <span>Signing is loop + abort</span>
      <span>Security through rejection</span>
    </div>
  </header>

  <section class="card">
    <h2>Exhibit 1: Watch the Loop</h2>
    <div class="controls">
      <label>Message <input id="message-input" value="Transfer $1000 to Bob" /></label>
      <button id="sign-once">Sign Once</button>
      <button id="regen-key">Regenerate Key</button>
    </div>
    <p class="meta">Secret key: <span class="secret">██████████████████████████████</span></p>
    <div id="sign-summary" class="summary"></div>
    <div id="iteration-feed" class="iteration-feed"></div>
  </section>

  <section class="card">
    <h2>Exhibit 2: Histogram of Iterations</h2>
    <div class="controls">
      <label>Preset
        <select id="preset-select">
          <option>ML-DSA-44</option>
          <option selected>ML-DSA-65</option>
          <option>ML-DSA-87</option>
        </select>
      </label>
      <button id="run-100">Run 100</button>
      <button id="run-1000">Run 1000</button>
      <button id="reset-hist">Reset</button>
    </div>
    <div id="histogram" class="histogram"></div>
    <div id="stats" class="stats-grid"></div>
  </section>

  <section class="card deep-dive">
    <h2>Exhibit 3: Why Each Check Exists</h2>
    <div class="check-grid" id="check-grid"></div>
  </section>

  <section class="card">
    <h2>Exhibit 4: Comparing Signature Schemes</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Algorithm</th><th>Sig size</th><th>Signing</th><th>Verification</th><th>Timing var?</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Ed25519</td><td>64B</td><td>50 us</td><td>65 us</td><td>No</td></tr>
          <tr><td>ECDSA</td><td>64B</td><td>80 us</td><td>85 us</td><td>No</td></tr>
          <tr><td>ML-DSA-65</td><td>3309B</td><td>Varies</td><td>95 us</td><td class="warn">Yes (reject loop)</td></tr>
          <tr><td>SLH-DSA</td><td>8-49KB</td><td>Slow</td><td>Fast</td><td>Yes (trees)</td></tr>
          <tr><td>FALCON-512</td><td>666B</td><td>200 us</td><td>45 us</td><td>Yes (Gaussian)</td></tr>
          <tr><td>LMS_H10</td><td>1452B</td><td>30 us</td><td>50 us</td><td>No (stateful)</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <section class="card">
    <h2>Exhibit 5: Production Mitigations</h2>
    <ul class="notes">
      <li>Bound iterations: FIPS 204 allows bailing out after a configured ceiling.</li>
      <li>Use hedged randomness for every signature (default randomized mode).</li>
      <li>Isolate signing in HSM/TEE where timing leakage is harder to exploit.</li>
      <li>Deterministic mode is reproducible but can amplify timing correlation by message.</li>
    </ul>
    <button id="run-distinguishability">Run Key Distinguishability Test (N=1000)</button>
    <pre id="distinguishability-output" class="dist-output"></pre>
  </section>
</main>
`;

const messageInput = document.querySelector<HTMLInputElement>('#message-input')!;
const signOnceButton = document.querySelector<HTMLButtonElement>('#sign-once')!;
const regenKeyButton = document.querySelector<HTMLButtonElement>('#regen-key')!;
const signSummary = document.querySelector<HTMLDivElement>('#sign-summary')!;
const iterationFeed = document.querySelector<HTMLDivElement>('#iteration-feed')!;
const histogramRoot = document.querySelector<HTMLDivElement>('#histogram')!;
const statsRoot = document.querySelector<HTMLDivElement>('#stats')!;
const run100 = document.querySelector<HTMLButtonElement>('#run-100')!;
const run1000 = document.querySelector<HTMLButtonElement>('#run-1000')!;
const resetHist = document.querySelector<HTMLButtonElement>('#reset-hist')!;
const presetSelect = document.querySelector<HTMLSelectElement>('#preset-select')!;
const checkGrid = document.querySelector<HTMLDivElement>('#check-grid')!;
const runDistinguishabilityButton = document.querySelector<HTMLButtonElement>('#run-distinguishability')!;
const distinguishabilityOutput = document.querySelector<HTMLPreElement>('#distinguishability-output')!;

if (
  !messageInput ||
  !signOnceButton ||
  !regenKeyButton ||
  !signSummary ||
  !iterationFeed ||
  !histogramRoot ||
  !statsRoot ||
  !run100 ||
  !run1000 ||
  !resetHist ||
  !presetSelect ||
  !checkGrid ||
  !runDistinguishabilityButton ||
  !distinguishabilityOutput
) {
  throw new Error('Missing required UI elements');
}

function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function paramAcceptanceHint(preset: ParamPreset): number {
  if (preset === 'ML-DSA-44') return 0.31;
  if (preset === 'ML-DSA-87') return 0.22;
  return 0.26;
}

function quantile(values: number[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  if (lo === hi) return sorted[lo] ?? 0;
  const weight = pos - lo;
  const low = sorted[lo] ?? 0;
  const high = sorted[hi] ?? 0;
  return low + (high - low) * weight;
}

function renderIteration(record: IterationRecord, idx: number): void {
  const row = document.createElement('article');
  row.className = `iteration ${record.result === 'ACCEPTED' ? 'accepted' : 'rejected'} reason-${record.rejectionReason ?? 'accepted'}`;

  const zLine = record.zStats
    ? `||z||∞ = ${record.zStats.infNorm} | threshold ${record.zStats.checkThreshold} | ${record.zStats.passesCheck ? 'PASS' : 'FAIL'}`
    : 'z check unavailable';
  const r0Line = record.r0Stats
    ? `||r0||∞ = ${record.r0Stats.infNorm} | threshold ${record.r0Stats.checkThreshold} | ${record.r0Stats.passesCheck ? 'PASS' : 'FAIL'}`
    : 'r0 check unavailable';
  const ct0Line = record.ct0Stats
    ? `||c·t0||∞ = ${record.ct0Stats.infNorm} | threshold ${record.ct0Stats.checkThreshold} | ${record.ct0Stats.passesCheck ? 'PASS' : 'FAIL'}`
    : 'ct0 check unavailable';

  row.innerHTML = `
    <h3>Iteration ${idx + 1} (kappa = ${record.kappa})</h3>
    <p>y-range: [${record.yStats.minCoefficient}, ${record.yStats.maxCoefficient}] | ||y||∞ = ${record.yStats.infNorm}</p>
    <p>c-tilde fingerprint: <strong>${record.cTildeFingerprint}</strong> | challenge weight = ${record.sampleInBall.nonzeroPositions.length}</p>
    <p>${zLine}</p>
    <p>${r0Line}</p>
    <p>${ct0Line}</p>
    <p>hint weight = ${record.hintWeight ?? 0} / ${record.hintThreshold}</p>
    <p class="result-line">${record.result}${record.rejectionReason ? `: ${record.rejectionReason}` : ''}</p>
  `;
  iterationFeed.prepend(row);
}

function renderHistogram(): void {
  const counts = new Map<number, number>();
  for (const v of state.iterationHistory) {
    counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  const maxBucket = Math.max(1, ...counts.values());

  const lines: string[] = [];
  const keys = [...counts.keys()].sort((a, b) => a - b);
  for (const key of keys) {
    const c = counts.get(key) ?? 0;
    const pct = state.iterationHistory.length > 0 ? (100 * c) / state.iterationHistory.length : 0;
    const bars = '█'.repeat(Math.max(1, Math.round((c / maxBucket) * 22)));
    lines.push(`<div class="hist-row"><span>${key.toString().padStart(2, ' ')}</span><span>${bars}</span><span>${pct.toFixed(1)}%</span></div>`);
  }
  histogramRoot.innerHTML = lines.join('');

  const mean =
    state.iterationHistory.length > 0
      ? state.iterationHistory.reduce((a, b) => a + b, 0) / state.iterationHistory.length
      : 0;
  const median = quantile(state.iterationHistory, 0.5);
  const p90 = quantile(state.iterationHistory, 0.9);
  const p99 = quantile(state.iterationHistory, 0.99);
  const max = state.iterationHistory.length > 0 ? Math.max(...state.iterationHistory) : 0;

  statsRoot.innerHTML = `
    <div><span class="k">Runs</span><span class="v">${state.histogramRuns}</span></div>
    <div><span class="k">Mean</span><span class="v">${fmt.format(mean)}</span></div>
    <div><span class="k">Median</span><span class="v">${fmt.format(median)}</span></div>
    <div><span class="k">P90</span><span class="v">${fmt.format(p90)}</span></div>
    <div><span class="k">P99</span><span class="v">${fmt.format(p99)}</span></div>
    <div><span class="k">Max</span><span class="v">${fmt.format(max)}</span></div>
    <div><span class="k">P(accept)</span><span class="v">~${paramAcceptanceHint(state.currentPreset)}</span></div>
  `;
}

function renderCheckExplanations(): void {
  checkGrid.innerHTML = `
    <article class="check-box">
      <h3>Check 1: ||z||∞ &lt; gamma1 - beta</h3>
      <p>z = y + c*s1. Large z can correlate challenge and secret signs. Rejecting out-of-range z keeps signatures statistically independent of s1.</p>
      <button data-check="z">Show example</button>
      <pre id="ex-z"></pre>
    </article>
    <article class="check-box">
      <h3>Check 2: ||r0||∞ &lt; gamma2 - beta</h3>
      <p>r0 carries low bits from w - c*s2. If r0 is too large, low-bit leakage can reveal information about s2.</p>
      <button data-check="r0">Show example</button>
      <pre id="ex-r0"></pre>
    </article>
    <article class="check-box">
      <h3>Check 3: ||c*t0||∞ &lt; gamma2</h3>
      <p>This keeps hint construction unambiguous and verification-correct. Oversized c*t0 risks malformed hint behavior.</p>
      <button data-check="ct0">Show example</button>
      <pre id="ex-ct0"></pre>
    </article>
    <article class="check-box">
      <h3>Check 4: ||h||wt <= omega</h3>
      <p>Hint density is capped (omega = 55). Dense hints increase signature size and can bias leakage.</p>
      <button data-check="hint">Show example</button>
      <pre id="ex-hint"></pre>
    </article>
  `;

  checkGrid.querySelectorAll<HTMLButtonElement>('button[data-check]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const kind = btn.dataset.check;
      if (!kind) return;

      if (kind === 'z') {
        const y = expandMask(randomBytes(64), 0, ML_DSA_65.gamma1, ML_DSA_65.n);
        const sample = y[0] ?? 0;
        (document.querySelector('#ex-z') as HTMLPreElement).textContent = `Example coefficient in y: ${sample}\nBound: ${ML_DSA_65.gamma1 - ML_DSA_65.beta}`;
      }
      if (kind === 'r0') {
        const sample = lowBits(ML_DSA_65.gamma2 + 133, 2 * ML_DSA_65.gamma2);
        (document.querySelector('#ex-r0') as HTMLPreElement).textContent = `lowBits(gamma2 + 133) = ${sample}\nCheck threshold: ${ML_DSA_65.gamma2 - ML_DSA_65.beta}`;
      }
      if (kind === 'ct0') {
        const c = await sampleInBall(randomBytes(32), ML_DSA_65.tau, ML_DSA_65.n);
        const nonzero = c.reduce((acc, cur) => acc + (cur !== 0 ? 1 : 0), 0);
        (document.querySelector('#ex-ct0') as HTMLPreElement).textContent = `SampleInBall nonzero positions: ${nonzero}\nct0 bound: ${ML_DSA_65.gamma2}`;
      }
      if (kind === 'hint') {
        const simulatedWeight = 58;
        (document.querySelector('#ex-hint') as HTMLPreElement).textContent = `Simulated hint weight: ${simulatedWeight}\nomega: ${ML_DSA_65.omega}\nResult: REJECT`;
      }
    });
  });
}

async function signOnce(): Promise<void> {
  const msg = encoder.encode(state.currentMessage);
  iterationFeed.innerHTML = '';
  signSummary.innerHTML = '<p>Signing...</p>';

  const result = await instrumentedSign(msg, state.keypair.secretKey, (record) => {
    renderIteration(record, iterationFeed.childElementCount);
  });

  const verified = ml_dsa65.verify(result.signature, msg, state.keypair.publicKey);
  state.iterationHistory.push(result.acceptedIteration);
  state.histogramRuns += 1;
  renderHistogram();

  signSummary.innerHTML = `
    <p>Message: ${escapeHtml(state.currentMessage)}</p>
    <p>Accepted iteration: <strong>${result.acceptedIteration}</strong> | Total time: <strong>${result.totalTimeMs.toFixed(3)} ms</strong></p>
    <p>Signature valid via noble verify: <strong>${verified ? 'yes' : 'no'}</strong></p>
  `;
}

async function runHistogramBatch(count: number): Promise<void> {
  if (state.runningHistogram) return;
  state.runningHistogram = true;
  run100.disabled = true;
  run1000.disabled = true;

  const msg = encoder.encode(state.currentMessage);
  const stats = await collectIterationStatistics(count, state.keypair.secretKey, msg);
  for (const c of stats.iterationCounts) {
    state.iterationHistory.push(c);
    state.histogramRuns += 1;
  }
  renderHistogram();

  const totalRejections = Array.from(stats.rejectionReasonBreakdown.values()).reduce((a, b) => a + b, 0);
  const breakdown = ['z_too_large', 'r0_too_large', 'ct0_too_large', 'hint_too_dense']
    .map((k) => {
      const v = stats.rejectionReasonBreakdown.get(k) ?? 0;
      const pct = totalRejections > 0 ? (100 * v) / totalRejections : 0;
      return `${k}: ${pct.toFixed(1)}%`;
    })
    .join(' | ');

  signSummary.innerHTML = `
    <p>Histogram batch complete (${count} signatures).</p>
    <p>Mean: ${stats.mean.toFixed(2)} | Median: ${stats.median.toFixed(2)} | P90: ${stats.p90.toFixed(2)} | P99: ${stats.p99.toFixed(2)} | Max: ${stats.max}</p>
    <p>${breakdown}</p>
  `;

  run100.disabled = false;
  run1000.disabled = false;
  state.runningHistogram = false;
}

async function runDistinguishabilityTestAction(): Promise<void> {
  runDistinguishabilityButton.disabled = true;
  distinguishabilityOutput.textContent = 'Running 2 x 1000 signatures...';

  const kp2 = ml_dsa65.keygen();
  const messages = Array.from({ length: 16 }, (_, i) => encoder.encode(`message-${i}`));
  const [obs1, obs2] = await Promise.all([
    collectTimingObservations(1000, state.keypair.secretKey, messages),
    collectTimingObservations(1000, kp2.secretKey, messages),
  ]);

  const verdict = distinguishabilityTest(obs1, obs2);
  distinguishabilityOutput.textContent = [
    `KS statistic: ${verdict.ksStatistic.toFixed(4)}`,
    `Distinguishable: ${verdict.distinguishable ? 'yes' : 'no'}`,
    `Confidence: ${Math.round(verdict.confidenceLevel * 100)}%`,
    verdict.note,
  ].join('\n');
  runDistinguishabilityButton.disabled = false;
}

messageInput.addEventListener('input', () => {
  state.currentMessage = messageInput.value;
});

signOnceButton.addEventListener('click', async () => {
  signOnceButton.disabled = true;
  await signOnce();
  signOnceButton.disabled = false;
});

regenKeyButton.addEventListener('click', () => {
  state.keypair = ml_dsa65.keygen();
  signSummary.innerHTML = '<p>New ML-DSA-65 keypair generated.</p>';
});

run100.addEventListener('click', async () => {
  await runHistogramBatch(100);
});

run1000.addEventListener('click', async () => {
  await runHistogramBatch(1000);
});

resetHist.addEventListener('click', () => {
  state.iterationHistory = [];
  state.histogramRuns = 0;
  renderHistogram();
});

presetSelect.addEventListener('change', () => {
  const value = presetSelect.value as ParamPreset;
  state.currentPreset = value;
  renderHistogram();
});

runDistinguishabilityButton.addEventListener('click', async () => {
  await runDistinguishabilityTestAction();
});

renderHistogram();
renderCheckExplanations();
