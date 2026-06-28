import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import './style.css';
import pkg from '../package.json';
import {
  PRESETS,
  type IterationRecord,
  type PresetName,
  type SigningResult,
  instrumentedSign,
  simulateTraceOfLength,
} from './instrumented-sign';
import { ML_DSA_65, expandMask, lowBits, randomBytes, randomInt, sampleInBall, setSeed } from './mldsa-primitives';
import {
  type Bin,
  type CdfPoint,
  type HistogramBucket,
  binValues,
  empiricalCdf,
  geometricMean,
  geometricPmf,
  histogramBuckets,
  ksMaxGap,
  mean as sampleMean,
  quantile,
} from './distributions';

interface KsVerdict {
  exceedsCritical: boolean;
  ksStatistic: number;
  criticalValue: number;
  alpha: number;
  note: string;
}

interface AppState {
  keypair: { secretKey: Uint8Array; publicKey: Uint8Array };
  currentMessage: string;
  iterationHistory: number[];
  histogramRuns: number;
  busy: boolean;
  currentPreset: PresetName;
  reasonBreakdown: Map<string, number>;
  customAcceptance: number | null;
  deterministic: boolean;
  seed: number;
  lastSig: { signature: Uint8Array; message: Uint8Array } | null;
  step: { trace: SigningResult; index: number; verified: boolean } | null;
  realTimes: number[];
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('Missing #app container');

const encoder = new TextEncoder();
const fmt = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 });
const intFmt = new Intl.NumberFormat('en-US');
const nobleVersion = (pkg.dependencies?.['@noble/post-quantum'] ?? '').replace(/[^0-9.]/g, '');

const state: AppState = {
  keypair: ml_dsa65.keygen(),
  currentMessage: 'Transfer $1000 to Bob',
  iterationHistory: [],
  histogramRuns: 0,
  busy: false,
  currentPreset: 'ML-DSA-65',
  reasonBreakdown: new Map(),
  customAcceptance: null,
  deterministic: false,
  seed: 42,
  lastSig: null,
  step: null,
  realTimes: [],
};

const REASONS = [
  { key: 'z_too_large', label: '‖z‖∞ too large', cls: 'z' },
  { key: 'r0_too_large', label: '‖r₀‖∞ too large', cls: 'r0' },
  { key: 'ct0_too_large', label: '‖c·t₀‖∞ too large', cls: 'ct0' },
  { key: 'hint_too_dense', label: 'hint too dense', cls: 'hint' },
] as const;

app.innerHTML = `
<main class="lab" id="main-content">
  <header class="hero card">
    <p class="eyebrow">crypto-lab-dilithium-reject</p>
    <h1>ML-DSA Rejection Sampling Explorer</h1>
    <p class="lede">Fiat-Shamir with Aborts visualized iteration-by-iteration: each candidate is accepted or rejected against four explicit norm bounds. Variable signing time is the security feature — watch it happen.</p>
    <div class="hero-tags">
      <span>FIPS 204 (ML-DSA-65)</span>
      <span>Signing is loop + abort</span>
      <span>Security through rejection</span>
    </div>
    <p class="sim-note" role="note">
      <strong>Didactic simulation.</strong>
      The iteration trace and histograms in Exhibits 1–2 are calibrated to ML-DSA's published acceptance distribution; they are not a fork of the production signing loop. The valid signature, the <strong>tamper test</strong>, and the <strong>measured timings in Exhibit 3</strong> use <code>@noble/post-quantum</code>'s real ML-DSA-65. See the
      <a href="https://github.com/systemslibrarian/crypto-lab-dilithium-reject#how-this-demo-works-important">README</a> for the exact boundary.
    </p>
  </header>

  <section class="card">
    <h2>Exhibit 1: Watch the Loop</h2>
    <p class="meta">Fixed at ML-DSA-65. Each run streams one didactic trace (candidates drawn until one passes all four checks) and produces one real noble signature you can then tamper with.</p>
    <div class="controls">
      <label for="message-input">Message</label>
      <input id="message-input" value="Transfer $1000 to Bob" aria-describedby="message-help" />
      <span id="message-help" class="sr-only">Message content used for demo signing. Press Enter to sign.</span>
      <button id="sign-once" type="button">Sign Once</button>
      <button id="step" type="button">Step ▶</button>
      <button id="regen-key" type="button">Regenerate Key</button>
    </div>
    <div class="controls subtle">
      <label class="inline-check" for="deterministic"><input type="checkbox" id="deterministic" /> Reproducible (seeded)</label>
      <label class="inline-check seed-field" for="seed" hidden>seed <input type="number" id="seed" value="42" min="0" step="1" /></label>
      <span class="meta det-note" hidden>Same seed reproduces the exact trace and signature — the idea behind FIPS 204 deterministic mode.</span>
    </div>
    <p class="meta">Secret key: <span class="secret" aria-hidden="true">██████████████████████████████</span></p>
    <div id="sign-summary" class="summary" role="status" aria-live="polite"></div>
    <div id="tamper-panel" class="tamper" hidden>
      <span class="tamper-title">Tamper test:</span>
      <button id="tamper-flip" type="button">Flip a byte &amp; re-verify</button>
      <button id="tamper-restore" type="button">Restore original</button>
      <span id="tamper-result" class="tamper-result" role="status" aria-live="polite"></span>
    </div>
    <div id="iteration-feed" class="iteration-feed" role="log" aria-label="Signing iteration records"></div>
  </section>

  <section class="card">
    <h2>Exhibit 2: Histogram of Iterations</h2>
    <p class="meta">Iteration count until acceptance is a <strong>geometric random variable</strong>: each draw is an independent coin flip with the same accept probability. The bars are the empirical distribution; the dotted line is the theoretical geometric PMF. They should track each other, with the mean at 1/p. Tip: click a bar to see an example trace of that length.</p>
    <div class="controls">
      <label for="preset-select">Preset</label>
        <select id="preset-select" aria-label="ML-DSA parameter preset">
          <option>ML-DSA-44</option>
          <option selected>ML-DSA-65</option>
          <option>ML-DSA-87</option>
        </select>
      <button id="run-100" type="button">Run 100</button>
      <button id="run-1000" type="button">Run 1000</button>
      <button id="reset-hist" type="button">Reset</button>
    </div>
    <div class="controls subtle">
      <label class="inline-check" for="custom-p"><input type="checkbox" id="custom-p" /> Custom p (exploratory)</label>
      <input type="range" id="p-slider" min="0.05" max="0.6" step="0.01" value="0.26" disabled aria-label="Exploratory acceptance probability" />
      <span id="p-readout" class="p-readout meta"></span>
    </div>
    <div class="chart-legend" aria-hidden="true">
      <span><span class="lg-swatch lg-bar"></span>observed</span>
      <span><span class="lg-swatch lg-pmf"></span>theoretical geometric PMF</span>
      <span><span class="lg-swatch lg-mean"></span>mean (1/p)</span>
    </div>
    <div id="histogram" class="histogram" role="group" aria-live="polite" aria-label="Histogram of iterations until acceptance"></div>
    <div id="stats" class="stats-grid" role="group" aria-label="Histogram summary statistics"></div>
    <div id="reason-breakdown" class="reason-breakdown"></div>
  </section>

  <section class="card">
    <h2>Exhibit 3: Real Signing Times (Measured)</h2>
    <p class="meta"><strong>This one is not simulated.</strong> It calls <code>@noble/post-quantum</code>'s actual <code>ml_dsa65.sign</code> thousands of times and records each call's duration with <code>performance.now()</code>. The right-skewed spread is genuine variable-time signing — longer signatures took more rejection-loop iterations. <em>Caveat:</em> browser timer resolution is coarse and deliberately jittered, and JIT/GC add noise, so read the <strong>shape</strong>, not the absolute milliseconds.</p>
    <div class="controls">
      <button id="measure-times" type="button">Measure 2000 real signatures</button>
      <span id="measure-progress" class="meta" role="status" aria-live="polite"></span>
    </div>
    <div id="realtime-hist" class="histogram"></div>
    <div id="realtime-stats" class="stats-grid" role="group" aria-label="Real timing summary statistics"></div>
  </section>

  <section class="card deep-dive">
    <h2>Exhibit 4: Why Each Check Exists</h2>
    <p class="meta">Each rejection condition removes signatures that would leak information about the secret key or break verification. Click a check for a freshly sampled example.</p>
    <div class="check-grid" id="check-grid"></div>
  </section>

  <section class="card">
    <h2>Exhibit 5: Comparing Signature Schemes</h2>
    <div class="table-wrap">
      <table>
        <caption>Signing characteristics across classical and post-quantum signature schemes. Timing figures are order-of-magnitude estimates for laptop-class hardware; consult library benchmarks for current values.</caption>
        <thead>
          <tr>
            <th scope="col">Algorithm</th><th scope="col">Sig size</th><th scope="col">Signing</th><th scope="col">Verification</th><th scope="col">Timing var?</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Ed25519</td><td>64 B</td><td>~50 us</td><td>~65 us</td><td>No</td></tr>
          <tr><td>ECDSA P-256</td><td>64 B</td><td>~80 us</td><td>~85 us</td><td>No</td></tr>
          <tr><td>ML-DSA-65</td><td>3309 B</td><td>Varies (reject loop)</td><td>~95 us</td><td class="warn">Yes (by design)</td></tr>
          <tr><td>SLH-DSA-128s</td><td>8 KB</td><td>Slow (hash trees)</td><td>Fast</td><td>Yes (trees)</td></tr>
          <tr><td>FALCON-512</td><td>666 B</td><td>~200 us</td><td>~45 us</td><td>Yes (Gaussian)</td></tr>
          <tr><td>LMS H10/W4</td><td>1452 B</td><td>~30 us</td><td>~50 us</td><td>No (stateful)</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <section class="card">
    <h2>Exhibit 6: Is Iteration Count Distinguishable?</h2>
    <p class="meta">The design intent of FIPS 204 is that the acceptance distribution does not depend on the secret key. This test draws two independent populations from the same calibrated simulation — think of them as timing traces from two different signers — and overlays their empirical CDFs. Under H0 they should coincide; the largest vertical gap is the Kolmogorov–Smirnov statistic.</p>
    <button id="run-distinguishability" type="button">Run KS Distinguishability Test (2 × N=1000)</button>
    <div id="ks-chart" class="ks-chart"></div>
    <pre id="distinguishability-output" class="dist-output" role="status" aria-live="polite"></pre>
    <h3 class="mini-h">Production mitigations</h3>
    <ul class="notes">
      <li>Bound iterations: FIPS 204 allows bailing out after a configured ceiling.</li>
      <li>Use hedged randomness for every signature (default randomized mode).</li>
      <li>Isolate signing in HSM/TEE where timing leakage is harder to exploit.</li>
      <li>Deterministic mode is reproducible but can amplify timing correlation by message.</li>
    </ul>
  </section>

  <section class="card">
    <h2>Exhibit 7: Symbols &amp; Further Reading</h2>
    <div class="glossary-grid">
      <div class="table-wrap">
        <table>
          <caption>Key symbols, with ML-DSA-65 values per FIPS 204 Table 1.</caption>
          <thead><tr><th scope="col">Symbol</th><th scope="col">Meaning</th><th scope="col">ML-DSA-65</th></tr></thead>
          <tbody>
            <tr><td>q</td><td>Prime modulus of the ring</td><td>${intFmt.format(ML_DSA_65.q)}</td></tr>
            <tr><td>n</td><td>Polynomial degree</td><td>${ML_DSA_65.n}</td></tr>
            <tr><td>(k, ℓ)</td><td>Matrix dimensions</td><td>(${ML_DSA_65.k}, ${ML_DSA_65.l})</td></tr>
            <tr><td>γ₁</td><td>Mask coefficient range</td><td>${intFmt.format(ML_DSA_65.gamma1)}</td></tr>
            <tr><td>γ₂</td><td>Low-order rounding range</td><td>${intFmt.format(ML_DSA_65.gamma2)}</td></tr>
            <tr><td>β</td><td>Norm-bound slack (τ·η)</td><td>${ML_DSA_65.beta}</td></tr>
            <tr><td>τ</td><td>Challenge Hamming weight</td><td>${ML_DSA_65.tau}</td></tr>
            <tr><td>ω</td><td>Max hint weight</td><td>${ML_DSA_65.omega}</td></tr>
            <tr><td>κ</td><td>Iteration / mask nonce counter</td><td>increments by ℓ</td></tr>
          </tbody>
        </table>
      </div>
      <div class="reading">
        <h3 class="mini-h">Further reading</h3>
        <ul class="notes">
          <li><a href="https://csrc.nist.gov/pubs/fips/204/final" target="_blank" rel="noopener">FIPS 204</a> — Module-Lattice-Based Digital Signature Standard (§ 6 signing, § 7.3 ExpandMask, § 8.5.3 SampleInBall).</li>
          <li><a href="https://eprint.iacr.org/2009/285" target="_blank" rel="noopener">Lyubashevsky (ASIACRYPT 2009)</a> — Fiat-Shamir with Aborts, the origin of the rejection loop.</li>
          <li><a href="https://pq-crystals.org/dilithium/" target="_blank" rel="noopener">CRYSTALS-Dilithium</a> — the design ML-DSA standardizes.</li>
          <li><a href="https://github.com/paulmillr/noble-post-quantum" target="_blank" rel="noopener">@noble/post-quantum</a> — the audited library that produces the real signatures here.</li>
        </ul>
      </div>
    </div>
  </section>

  <footer class="site-footer">
    Real signatures &amp; tamper test by <a href="https://github.com/paulmillr/noble-post-quantum" target="_blank" rel="noopener">@noble/post-quantum</a>${nobleVersion ? ` v${nobleVersion}` : ''}
    · <a href="https://github.com/systemslibrarian/crypto-lab-dilithium-reject/blob/main/LICENSE" target="_blank" rel="noopener">MIT</a>
    · <a href="https://github.com/systemslibrarian/crypto-lab-dilithium-reject" target="_blank" rel="noopener">source</a>
    <br>Related demos:
    <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noopener">crypto-lab-dilithium-seal</a>
    · <a href="https://systemslibrarian.github.io/crypto-lab-falcon-seal/" target="_blank" rel="noopener">crypto-lab-falcon-seal</a>
    · <a href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" target="_blank" rel="noopener">crypto-lab-sphincs-ledger</a>
    · <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-sign/" target="_blank" rel="noopener">crypto-lab-hybrid-sign</a>
    · <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noopener">crypto-lab-kyber-vault</a>
  </footer>
</main>
`;

// --- element refs ---
const $ = <T extends Element>(sel: string): T => {
  const el = document.querySelector<T>(sel);
  if (!el) throw new Error(`Missing element: ${sel}`);
  return el;
};

const messageInput = $<HTMLInputElement>('#message-input');
const signOnceButton = $<HTMLButtonElement>('#sign-once');
const stepButton = $<HTMLButtonElement>('#step');
const regenKeyButton = $<HTMLButtonElement>('#regen-key');
const deterministicCheck = $<HTMLInputElement>('#deterministic');
const seedField = $<HTMLLabelElement>('.seed-field');
const seedInput = $<HTMLInputElement>('#seed');
const detNote = $<HTMLSpanElement>('.det-note');
const signSummary = $<HTMLDivElement>('#sign-summary');
const tamperPanel = $<HTMLDivElement>('#tamper-panel');
const tamperFlip = $<HTMLButtonElement>('#tamper-flip');
const tamperRestore = $<HTMLButtonElement>('#tamper-restore');
const tamperResult = $<HTMLSpanElement>('#tamper-result');
const iterationFeed = $<HTMLDivElement>('#iteration-feed');
const histogramRoot = $<HTMLDivElement>('#histogram');
const statsRoot = $<HTMLDivElement>('#stats');
const reasonRoot = $<HTMLDivElement>('#reason-breakdown');
const run100 = $<HTMLButtonElement>('#run-100');
const run1000 = $<HTMLButtonElement>('#run-1000');
const resetHist = $<HTMLButtonElement>('#reset-hist');
const presetSelect = $<HTMLSelectElement>('#preset-select');
const customPCheck = $<HTMLInputElement>('#custom-p');
const pSlider = $<HTMLInputElement>('#p-slider');
const pReadout = $<HTMLSpanElement>('#p-readout');
const measureButton = $<HTMLButtonElement>('#measure-times');
const measureProgress = $<HTMLSpanElement>('#measure-progress');
const realtimeHist = $<HTMLDivElement>('#realtime-hist');
const realtimeStats = $<HTMLDivElement>('#realtime-stats');
const checkGrid = $<HTMLDivElement>('#check-grid');
const runDistinguishabilityButton = $<HTMLButtonElement>('#run-distinguishability');
const distinguishabilityOutput = $<HTMLPreElement>('#distinguishability-output');
const ksChart = $<HTMLDivElement>('#ks-chart');
const exhibit1 = $<HTMLElement>('.lab > section.card:nth-of-type(1)');

// --- worker client ---
let worker: Worker | null = null;
function getWorker(): Worker {
  worker ??= new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
  return worker;
}
let reqId = 0;
interface ProgressMsg {
  done?: number;
  a?: number;
  b?: number;
}
function runJob<T>(req: Record<string, unknown>, onProgress?: (m: ProgressMsg) => void): Promise<T> {
  const w = getWorker();
  const id = (reqId += 1);
  return new Promise<T>((resolve, reject) => {
    const handler = (e: MessageEvent): void => {
      const m = e.data as { id: number; type: string; payload?: T; error?: string } & ProgressMsg;
      if (m?.id !== id) return;
      if (m.type === 'progress') onProgress?.(m);
      else if (m.type === 'result') {
        w.removeEventListener('message', handler);
        resolve(m.payload as T);
      } else if (m.type === 'error') {
        w.removeEventListener('message', handler);
        reject(new Error(m.error ?? 'worker error'));
      }
    };
    w.addEventListener('message', handler);
    w.postMessage({ ...req, id });
  });
}

// --- helpers ---
function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
function prefersReducedMotion(): boolean {
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function activeAcceptance(): number {
  return state.customAcceptance ?? PRESETS[state.currentPreset].acceptance;
}
async function withSeedMaybe<T>(fn: () => Promise<T>): Promise<T> {
  if (state.deterministic) setSeed(state.seed);
  try {
    return await fn();
  } finally {
    if (state.deterministic) setSeed(null);
  }
}

// ---------------------------------------------------------------------------
// Exhibit 1 — iteration cards, reveal, step, tamper
// ---------------------------------------------------------------------------

function checkRow(label: string, value: string, pass: boolean, cls: string): string {
  return `
    <li class="check ${pass ? 'pass' : 'fail'} check-${cls}">
      <span class="check-name">${label}</span>
      <span class="check-val">${value}</span>
      <span class="check-pill">${pass ? 'PASS' : 'FAIL'}</span>
    </li>`;
}

function renderIteration(record: IterationRecord, idx: number): void {
  const row = document.createElement('article');
  row.className = `iteration ${record.result === 'ACCEPTED' ? 'accepted' : 'rejected'} reason-${record.rejectionReason ?? 'accepted'}`;

  const statusLabel = record.result === 'ACCEPTED' ? 'ACCEPTED' : `REJECTED · ${record.rejectionReason ?? ''}`;
  const zPass = record.zStats?.passesCheck ?? true;
  const r0Pass = record.r0Stats?.passesCheck ?? true;
  const ct0Pass = record.ct0Stats?.passesCheck ?? true;
  const hintPass = (record.hintWeight ?? 0) <= record.hintThreshold;

  const checks = [
    record.zStats
      ? checkRow(
          '‖z‖∞ &lt; γ₁ − β',
          `${intFmt.format(record.zStats.infNorm)} / ${intFmt.format(record.zStats.checkThreshold)}`,
          zPass,
          'z',
        )
      : '',
    record.r0Stats
      ? checkRow(
          '‖r₀‖∞ &lt; γ₂ − β',
          `${intFmt.format(record.r0Stats.infNorm)} / ${intFmt.format(record.r0Stats.checkThreshold)}`,
          r0Pass,
          'r0',
        )
      : '',
    record.ct0Stats
      ? checkRow(
          '‖c·t₀‖∞ &lt; γ₂',
          `${intFmt.format(record.ct0Stats.infNorm)} / ${intFmt.format(record.ct0Stats.checkThreshold)}`,
          ct0Pass,
          'ct0',
        )
      : '',
    checkRow('wt(h) ≤ ω', `${record.hintWeight ?? 0} / ${record.hintThreshold}`, hintPass, 'hint'),
  ].join('');

  row.innerHTML = `
    <div class="iter-head">
      <h3>Iteration ${idx + 1}</h3>
      <span class="status-pill status-${record.result === 'ACCEPTED' ? 'accepted' : 'rejected'}">${statusLabel}</span>
    </div>
    <p class="iter-sub">κ = ${record.kappa} · challenge weight ${record.sampleInBall.nonzeroPositions.length} · c̃ ${record.cTildeFingerprint} · ‖y‖∞ = ${intFmt.format(record.yStats.infNorm)}</p>
    <ul class="checks">${checks}</ul>
  `;
  iterationFeed.append(row);
}

async function revealIterations(records: IterationRecord[]): Promise<void> {
  iterationFeed.innerHTML = '';
  const reduce = prefersReducedMotion();
  const perStep = records.length > 14 ? 55 : 220;
  for (let i = 0; i < records.length; i += 1) {
    const record = records[i];
    if (!record) continue;
    renderIteration(record, i);
    iterationFeed.scrollTop = iterationFeed.scrollHeight;
    if (!reduce && i < records.length - 1) await sleep(perStep);
  }
}

function setLastSignature(signature: Uint8Array, message: Uint8Array, verified: boolean): void {
  state.lastSig = { signature, message };
  tamperPanel.hidden = false;
  tamperResult.textContent = verified ? 'original signature verifies ✓' : 'original verifies ✗';
  tamperResult.className = `tamper-result ${verified ? 'ok' : 'bad'}`;
}

async function signOnce(): Promise<void> {
  state.step = null;
  stepButton.textContent = 'Step ▶';
  const msg = encoder.encode(state.currentMessage);
  iterationFeed.innerHTML = '';
  signSummary.innerHTML = '<p>Signing… drawing candidates until one passes all four checks.</p>';

  const result = await withSeedMaybe(() =>
    instrumentedSign(msg, state.keypair.secretKey, undefined, { preset: 'ML-DSA-65' }),
  );
  const verified = ml_dsa65.verify(result.signature, msg, state.keypair.publicKey);

  await revealIterations(result.iterations);

  const rejections = result.acceptedIteration - 1;
  const seedNote = state.deterministic ? ` · seed ${state.seed}` : '';
  signSummary.innerHTML = `
    <p>Message: ${escapeHtml(state.currentMessage)}${seedNote}</p>
    <p>Accepted on iteration <strong>${result.acceptedIteration}</strong> after <strong>${rejections}</strong> rejection${rejections === 1 ? '' : 's'} · simulated trace time <strong>${result.totalTimeMs.toFixed(3)} ms</strong></p>
    <p>Signature verifies via noble ML-DSA-65: <strong>${verified ? 'yes' : 'no'}</strong></p>
  `;
  setLastSignature(result.signature, msg, verified);
}

async function stepOnce(): Promise<void> {
  // Start a new trace if none active or the previous one finished.
  if (!state.step || state.step.index >= state.step.trace.iterations.length) {
    const msg = encoder.encode(state.currentMessage);
    const result = await withSeedMaybe(() =>
      instrumentedSign(msg, state.keypair.secretKey, undefined, { preset: 'ML-DSA-65' }),
    );
    const verified = ml_dsa65.verify(result.signature, msg, state.keypair.publicKey);
    state.step = { trace: result, index: 0, verified };
    iterationFeed.innerHTML = '';
    tamperPanel.hidden = true;
  }

  const { trace, index } = state.step;
  const record = trace.iterations[index];
  if (record) renderIteration(record, index);
  iterationFeed.scrollTop = iterationFeed.scrollHeight;
  state.step.index = index + 1;

  if (state.step.index >= trace.iterations.length) {
    const rejections = trace.acceptedIteration - 1;
    const msg = encoder.encode(state.currentMessage);
    signSummary.innerHTML = `
      <p>Stepped through ${trace.acceptedIteration} iteration${trace.acceptedIteration === 1 ? '' : 's'} (${rejections} rejection${rejections === 1 ? '' : 's'}).</p>
      <p>Signature verifies via noble ML-DSA-65: <strong>${state.step.verified ? 'yes' : 'no'}</strong></p>
    `;
    setLastSignature(trace.signature, msg, state.step.verified);
    stepButton.textContent = 'Step ▶ (new trace)';
  } else {
    signSummary.innerHTML = `<p>Step ${state.step.index}: ${record?.result === 'REJECTED' ? `rejected (${record.rejectionReason}) — drawing again…` : 'accepted.'}</p>`;
    stepButton.textContent = 'Next step ▶';
  }
}

async function showExampleTrace(k: number): Promise<void> {
  if (state.busy) return;
  setBusy(true);
  try {
    state.step = null;
    stepButton.textContent = 'Step ▶';
    const trace = simulateTraceOfLength(k, {
      preset: state.currentPreset,
      acceptance: state.customAcceptance ?? undefined,
    });
    signSummary.innerHTML = `<p>Example trace of length <strong>${k}</strong> (illustrative — constructed to accept on iteration ${k}, no real signature).</p>`;
    tamperPanel.hidden = true;
    exhibit1.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
    await revealIterations(trace.iterations);
  } finally {
    setBusy(false);
  }
}

// ---------------------------------------------------------------------------
// Exhibit 2 — SVG histogram with geometric overlay
// ---------------------------------------------------------------------------

function histogramSvg(buckets: HistogramBucket[], p: number, total: number): string {
  const W = 760;
  const H = 340;
  const padL = 52;
  const padR = 18;
  const padT = 20;
  const padB = 48;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;
  const baseY = padT + plotH;
  const n = buckets.length;
  const slot = plotW / n;

  const pmf = buckets.map((b) => geometricPmf(p, b.iteration));
  const maxObs = Math.max(0, ...buckets.map((b) => b.proportion));
  const maxPmf = Math.max(0, ...pmf);
  const yMax = Math.max(maxObs, maxPmf, 0.04) * 1.15;

  const sy = (v: number): number => padT + plotH * (1 - v / yMax);
  const cx = (i: number): number => padL + slot * (i + 0.5);

  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * yMax);
  const grid = ticks
    .map((t) => {
      const y = sy(t);
      return (
        `<line class="grid" x1="${padL}" y1="${y.toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${y.toFixed(1)}"/>` +
        `<text class="axis-label" x="${padL - 8}" y="${(y + 3.5).toFixed(1)}" text-anchor="end">${(t * 100).toFixed(t < 0.1 ? 1 : 0)}%</text>`
      );
    })
    .join('');

  const axes =
    `<line class="axis" x1="${padL}" y1="${padT}" x2="${padL}" y2="${baseY}"/>` +
    `<line class="axis" x1="${padL}" y1="${baseY}" x2="${W - padR}" y2="${baseY}"/>`;

  const barW = Math.min(slot * 0.72, 48);
  const hasData = total > 0;
  const bars = buckets
    .map((b, i) => {
      const x = cx(i) - barW / 2;
      const y = sy(b.proportion);
      const h = Math.max(0, baseY - y);
      const delay = Math.min(i * 26, 700);
      const title = hasData
        ? `${intFmt.format(b.count)} of ${intFmt.format(total)} signatures took ${b.iteration} iteration${b.iteration === 1 ? '' : 's'} (${(b.proportion * 100).toFixed(1)}%) — click for an example`
        : `iteration ${b.iteration} — click for an example trace`;
      return `<g class="bar-g" data-iter="${b.iteration}" tabindex="0" role="button" aria-label="${title}"><title>${title}</title><rect class="hbar" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" rx="2" style="animation-delay:${delay}ms"/></g>`;
    })
    .join('');

  const linePts = buckets.map((_b, i) => `${cx(i).toFixed(1)},${sy(pmf[i] ?? 0).toFixed(1)}`).join(' ');
  const pmfLine = `<polyline class="pmf-line" points="${linePts}"/>`;
  const pmfDots = buckets
    .map(
      (_b, i) =>
        `<circle class="pmf-dot" cx="${cx(i).toFixed(1)}" cy="${sy(pmf[i] ?? 0).toFixed(1)}" r="3"><title>theoretical ${((pmf[i] ?? 0) * 100).toFixed(1)}%</title></circle>`,
    )
    .join('');

  const m = geometricMean(p);
  const mx = padL + slot * (m - 0.5);
  const meanLine =
    m >= 1 && m <= n
      ? `<line class="mean-line" x1="${mx.toFixed(1)}" y1="${padT}" x2="${mx.toFixed(1)}" y2="${baseY}"/>` +
        `<text class="mean-tag" x="${mx.toFixed(1)}" y="${(padT - 6).toFixed(1)}" text-anchor="middle">mean ≈ ${m.toFixed(1)}</text>`
      : '';

  const step = Math.max(1, Math.ceil(n / 16));
  const xLabels = buckets
    .map((b, i) => {
      if (i % step !== 0 && i !== n - 1) return '';
      return `<text class="axis-label" x="${cx(i).toFixed(1)}" y="${(baseY + 18).toFixed(1)}" text-anchor="middle">${b.iteration}</text>`;
    })
    .join('');

  const titles =
    `<text class="axis-title" x="${(padL + plotW / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">iterations until acceptance</text>` +
    `<text class="axis-title" transform="translate(15 ${(padT + plotH / 2).toFixed(1)}) rotate(-90)" text-anchor="middle">share of signatures</text>`;

  return `<svg viewBox="0 0 ${W} ${H}" class="hist-svg" role="img" aria-label="Histogram of iterations until acceptance. Mean about ${m.toFixed(1)} iterations. Bars track a theoretical geometric distribution.">${grid}${axes}${bars}${pmfLine}${pmfDots}${meanLine}${xLabels}${titles}</svg>`;
}

function histogramTable(buckets: HistogramBucket[]): string {
  const rows = buckets
    .map(
      (b) =>
        `<tr><td>${b.iteration}</td><td>${intFmt.format(b.count)}</td><td>${(b.proportion * 100).toFixed(1)}%</td></tr>`,
    )
    .join('');
  return `<table class="sr-only"><caption>Histogram data: iterations until acceptance</caption><thead><tr><th>Iterations</th><th>Count</th><th>Share</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderHistogram(): void {
  const p = activeAcceptance();
  const data = state.iterationHistory;

  if (data.length > 0) {
    const buckets = histogramBuckets(data);
    histogramRoot.innerHTML = histogramSvg(buckets, p, data.length) + histogramTable(buckets);
  } else if (state.customAcceptance !== null) {
    // Exploratory mode with no data yet: show the theoretical curve alone so
    // dragging the slider animates the geometric distribution and mean.
    const span = Math.min(40, Math.max(8, Math.ceil(geometricMean(p) * 4)));
    const buckets: HistogramBucket[] = Array.from({ length: span }, (_v, i) => ({
      iteration: i + 1,
      count: 0,
      proportion: 0,
    }));
    histogramRoot.innerHTML = histogramSvg(buckets, p, 0);
  } else {
    histogramRoot.innerHTML =
      '<p class="meta hist-empty">No data yet. Click Run 100 or Run 1000 to build the distribution.</p>';
  }

  const observedMean = sampleMean(data);
  const theoreticalMean = geometricMean(p);
  statsRoot.innerHTML = `
    <div><span class="k">Preset</span><span class="v">${state.currentPreset}${state.customAcceptance !== null ? ' (custom p)' : ''}</span></div>
    <div><span class="k">Runs</span><span class="v">${intFmt.format(state.histogramRuns)}</span></div>
    <div><span class="k">Observed mean</span><span class="v">${fmt.format(observedMean)}</span></div>
    <div><span class="k">Theory mean (1/p)</span><span class="v">${fmt.format(theoreticalMean)}</span></div>
    <div><span class="k">Median</span><span class="v">${fmt.format(quantile(data, 0.5))}</span></div>
    <div><span class="k">P90</span><span class="v">${fmt.format(quantile(data, 0.9))}</span></div>
    <div><span class="k">P99</span><span class="v">${fmt.format(quantile(data, 0.99))}</span></div>
    <div><span class="k">Max</span><span class="v">${fmt.format(data.reduce((m, v) => (v > m ? v : m), 0))}</span></div>
  `;
}

function renderReasonBreakdown(): void {
  const breakdown = state.reasonBreakdown;
  const total = [...breakdown.values()].reduce((a, b) => a + b, 0);
  if (total === 0) {
    reasonRoot.innerHTML = '';
    return;
  }
  const segs = REASONS.map((r) => {
    const v = breakdown.get(r.key) ?? 0;
    return { ...r, v, pct: (100 * v) / total };
  });
  const bar = segs
    .filter((s) => s.pct > 0)
    .map(
      (s) =>
        `<span class="seg seg-${s.cls}" style="width:${s.pct.toFixed(2)}%" title="${s.label}: ${s.pct.toFixed(1)}%"></span>`,
    )
    .join('');
  const legend = segs
    .map((s) => `<li><span class="swatch sw-${s.cls}"></span>${s.label} <strong>${s.pct.toFixed(1)}%</strong></li>`)
    .join('');
  const aria = `Rejection reasons: ${segs.map((s) => `${s.label} ${s.pct.toFixed(0)} percent`).join(', ')}`;
  reasonRoot.innerHTML = `
    <h3 class="mini-h">Why candidates were rejected (${intFmt.format(total)} rejections)</h3>
    <div class="reason-bar" role="img" aria-label="${aria}">${bar}</div>
    <ul class="reason-legend">${legend}</ul>
  `;
}

// ---------------------------------------------------------------------------
// Exhibit 3 — real measured timings
// ---------------------------------------------------------------------------

function realTimingSvg(bins: Bin[], meanV: number, medianV: number): string {
  const W = 760;
  const H = 320;
  const padL = 44;
  const padR = 18;
  const padT = 18;
  const padB = 46;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;
  const baseY = padT + plotH;
  const n = bins.length;
  const slot = plotW / n;
  const minX = bins[0]?.start ?? 0;
  const maxX = bins.at(-1)?.end ?? 1;
  const range = Math.max(1e-9, maxX - minX);

  const maxProp = Math.max(0.01, ...bins.map((b) => b.proportion));
  const yMax = maxProp * 1.15;
  const sy = (v: number): number => padT + plotH * (1 - v / yMax);
  const sxVal = (v: number): number => padL + plotW * ((v - minX) / range);

  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map((f) => {
      const y = sy(f * yMax);
      return (
        `<line class="grid" x1="${padL}" y1="${y.toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${y.toFixed(1)}"/>` +
        `<text class="axis-label" x="${padL - 8}" y="${(y + 3.5).toFixed(1)}" text-anchor="end">${(f * yMax * 100).toFixed(0)}%</text>`
      );
    })
    .join('');

  const axes =
    `<line class="axis" x1="${padL}" y1="${padT}" x2="${padL}" y2="${baseY}"/>` +
    `<line class="axis" x1="${padL}" y1="${baseY}" x2="${W - padR}" y2="${baseY}"/>`;

  const barW = slot * 0.92;
  const bars = bins
    .map((b, i) => {
      const x = padL + slot * i + (slot - barW) / 2;
      const y = sy(b.proportion);
      const h = Math.max(0, baseY - y);
      const delay = Math.min(i * 18, 500);
      const title = `${b.start.toFixed(3)}–${b.end.toFixed(3)} ms: ${intFmt.format(b.count)} (${(b.proportion * 100).toFixed(1)}%)`;
      return `<g><title>${title}</title><rect class="hbar rt-bar" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" rx="1.5" style="animation-delay:${delay}ms"/></g>`;
    })
    .join('');

  const marker = (v: number, lineCls: string, label: string, labelCls: string, labelY: number): string => {
    if (v < minX || v > maxX) return '';
    const x = sxVal(v);
    return (
      `<line class="${lineCls}" x1="${x.toFixed(1)}" y1="${padT}" x2="${x.toFixed(1)}" y2="${baseY}"/>` +
      `<text class="${labelCls}" x="${(x + 4).toFixed(1)}" y="${labelY.toFixed(1)}" text-anchor="start">${label}</text>`
    );
  };

  const xStep = Math.max(1, Math.ceil(n / 8));
  const xLabels = bins
    .map((b, i) => {
      if (i % xStep !== 0 && i !== n - 1) return '';
      return `<text class="axis-label" x="${sxVal(b.start).toFixed(1)}" y="${(baseY + 18).toFixed(1)}" text-anchor="middle">${b.start.toFixed(2)}</text>`;
    })
    .join('');

  const titles =
    `<text class="axis-title" x="${(padL + plotW / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">signing time (ms)</text>` +
    `<text class="axis-title" transform="translate(13 ${(padT + plotH / 2).toFixed(1)}) rotate(-90)" text-anchor="middle">share of signatures</text>`;

  return `<svg viewBox="0 0 ${W} ${H}" class="hist-svg" role="img" aria-label="Histogram of ${intFmt.format(bins.reduce((a, b) => a + b.count, 0))} real signing times. Mean ${meanV.toFixed(3)} milliseconds.">${grid}${axes}${bars}${marker(medianV, 'mean-line median-line', 'median', 'mean-tag median-tag', padT + 12)}${marker(meanV, 'mean-line', 'mean', 'mean-tag', padT - 5)}${xLabels}${titles}</svg>`;
}

function renderRealTiming(): void {
  const times = state.realTimes;
  if (times.length === 0) {
    realtimeHist.innerHTML =
      '<p class="meta hist-empty">No measurements yet. Click “Measure 2000 real signatures”.</p>';
    realtimeStats.innerHTML = '';
    return;
  }
  const meanV = sampleMean(times);
  const medianV = quantile(times, 0.5);
  const bins = binValues(times, Math.min(28, Math.max(8, Math.round(Math.sqrt(times.length)))));
  realtimeHist.innerHTML = realTimingSvg(bins, meanV, medianV);
  realtimeStats.innerHTML = `
    <div><span class="k">Signatures</span><span class="v">${intFmt.format(times.length)}</span></div>
    <div><span class="k">Mean</span><span class="v">${meanV.toFixed(3)} ms</span></div>
    <div><span class="k">Median</span><span class="v">${medianV.toFixed(3)} ms</span></div>
    <div><span class="k">P90</span><span class="v">${quantile(times, 0.9).toFixed(3)} ms</span></div>
    <div><span class="k">P99</span><span class="v">${quantile(times, 0.99).toFixed(3)} ms</span></div>
    <div><span class="k">Min</span><span class="v">${Math.min(...times).toFixed(3)} ms</span></div>
    <div><span class="k">Max</span><span class="v">${Math.max(...times).toFixed(3)} ms</span></div>
    <div><span class="k">Spread</span><span class="v">${(Math.max(...times) - Math.min(...times)).toFixed(3)} ms</span></div>
  `;
}

// ---------------------------------------------------------------------------
// Exhibit 4 — per-check explanations
// ---------------------------------------------------------------------------

function renderCheckExplanations(): void {
  checkGrid.innerHTML = `
    <article class="check-box">
      <h3>Check 1: ‖z‖∞ &lt; γ₁ − β</h3>
      <p>z = y + c·s₁. Large z can correlate the challenge with the secret signs. Rejecting out-of-range z keeps signatures statistically independent of s₁.</p>
      <button data-check="z" type="button">Show example</button>
      <pre id="ex-z"></pre>
    </article>
    <article class="check-box">
      <h3>Check 2: ‖r₀‖∞ &lt; γ₂ − β</h3>
      <p>r₀ carries low bits from w − c·s₂. If r₀ is too large, low-bit leakage can reveal information about s₂.</p>
      <button data-check="r0" type="button">Show example</button>
      <pre id="ex-r0"></pre>
    </article>
    <article class="check-box">
      <h3>Check 3: ‖c·t₀‖∞ &lt; γ₂</h3>
      <p>This keeps hint construction unambiguous and verification correct. Oversized c·t₀ risks malformed hint behavior.</p>
      <button data-check="ct0" type="button">Show example</button>
      <pre id="ex-ct0"></pre>
    </article>
    <article class="check-box">
      <h3>Check 4: wt(h) ≤ ω</h3>
      <p>Hint density is capped (ω = ${ML_DSA_65.omega} for ML-DSA-65). Dense hints increase signature size and can bias leakage.</p>
      <button data-check="hint" type="button">Show example</button>
      <pre id="ex-hint"></pre>
    </article>
  `;

  checkGrid.querySelectorAll<HTMLButtonElement>('button[data-check]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const kind = btn.dataset.check;
      if (!kind) return;
      if (kind === 'z') {
        const y = expandMask(randomBytes(64), 0, ML_DSA_65.gamma1, ML_DSA_65.n);
        const sample = y[0] ?? 0;
        $<HTMLPreElement>('#ex-z').textContent =
          `Example coefficient in y: ${sample}\nBound: ${ML_DSA_65.gamma1 - ML_DSA_65.beta}`;
      }
      if (kind === 'r0') {
        const sample = lowBits(ML_DSA_65.gamma2 + 133, 2 * ML_DSA_65.gamma2);
        $<HTMLPreElement>('#ex-r0').textContent =
          `lowBits(gamma2 + 133) = ${sample}\nCheck threshold: ${ML_DSA_65.gamma2 - ML_DSA_65.beta}`;
      }
      if (kind === 'ct0') {
        const c = sampleInBall(randomBytes(32), ML_DSA_65.tau, ML_DSA_65.n);
        const nonzero = c.reduce((acc, cur) => acc + (cur !== 0 ? 1 : 0), 0);
        $<HTMLPreElement>('#ex-ct0').textContent =
          `SampleInBall nonzero positions: ${nonzero}\nct0 bound: ${ML_DSA_65.gamma2}`;
      }
      if (kind === 'hint') {
        const simulatedWeight = ML_DSA_65.omega + 3;
        $<HTMLPreElement>('#ex-hint').textContent =
          `Simulated hint weight: ${simulatedWeight}\nomega: ${ML_DSA_65.omega}\nResult: REJECT`;
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Exhibit 6 — KS CDF overlay
// ---------------------------------------------------------------------------

function cdfOverlaySvg(a: number[], b: number[]): string {
  const ca = empiricalCdf(a);
  const cb = empiricalCdf(b);
  const xMax = Math.max(ca.at(-1)?.x ?? 1, cb.at(-1)?.x ?? 1, 2);
  const W = 760;
  const H = 300;
  const padL = 48;
  const padR = 18;
  const padT = 18;
  const padB = 42;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;
  const baseY = padT + plotH;

  const sx = (x: number): number => padL + plotW * ((x - 1) / Math.max(1, xMax - 1));
  const sy = (prob: number): number => padT + plotH * (1 - prob);

  const stepPath = (pts: CdfPoint[]): string => {
    if (pts.length === 0) return '';
    let d = `M ${sx(pts[0]!.x).toFixed(1)} ${sy(0).toFixed(1)}`;
    let prev = 0;
    for (const pt of pts) {
      const x = sx(pt.x);
      d += ` L ${x.toFixed(1)} ${sy(prev).toFixed(1)} L ${x.toFixed(1)} ${sy(pt.p).toFixed(1)}`;
      prev = pt.p;
    }
    d += ` L ${sx(xMax).toFixed(1)} ${sy(prev).toFixed(1)}`;
    return d;
  };

  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map((t) => {
      const y = sy(t);
      return (
        `<line class="grid" x1="${padL}" y1="${y.toFixed(1)}" x2="${(W - padR).toFixed(1)}" y2="${y.toFixed(1)}"/>` +
        `<text class="axis-label" x="${padL - 8}" y="${(y + 3.5).toFixed(1)}" text-anchor="end">${(t * 100).toFixed(0)}%</text>`
      );
    })
    .join('');

  const axes =
    `<line class="axis" x1="${padL}" y1="${padT}" x2="${padL}" y2="${baseY}"/>` +
    `<line class="axis" x1="${padL}" y1="${baseY}" x2="${W - padR}" y2="${baseY}"/>`;

  const xStep = Math.max(1, Math.ceil(xMax / 16));
  const xLabels: string[] = [];
  for (let k = 1; k <= xMax; k += xStep) {
    xLabels.push(
      `<text class="axis-label" x="${sx(k).toFixed(1)}" y="${(baseY + 18).toFixed(1)}" text-anchor="middle">${k}</text>`,
    );
  }

  const { statistic, x: gapX } = ksMaxGap(a, b);
  const fa = a.filter((v) => v <= gapX).length / Math.max(1, a.length);
  const fb = b.filter((v) => v <= gapX).length / Math.max(1, b.length);
  const gapMarker =
    `<line class="ks-gap" x1="${sx(gapX).toFixed(1)}" y1="${sy(fa).toFixed(1)}" x2="${sx(gapX).toFixed(1)}" y2="${sy(fb).toFixed(1)}"/>` +
    `<text class="ks-gap-label" x="${(sx(gapX) + 6).toFixed(1)}" y="${(sy(Math.max(fa, fb)) - 6).toFixed(1)}">KS = ${statistic.toFixed(3)}</text>`;

  const titles =
    `<text class="axis-title" x="${(padL + plotW / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">iterations until acceptance</text>` +
    `<text class="axis-title" transform="translate(13 ${(padT + plotH / 2).toFixed(1)}) rotate(-90)" text-anchor="middle">cumulative probability</text>`;

  return `<svg viewBox="0 0 ${W} ${H}" class="cdf-svg" role="img" aria-label="Overlaid empirical CDFs of two populations. KS statistic ${statistic.toFixed(3)}.">${grid}${axes}<path class="cdf-line cdf-a" d="${stepPath(ca)}"/><path class="cdf-line cdf-b" d="${stepPath(cb)}"/>${gapMarker}${xLabels.join('')}${titles}</svg>`;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

function setBusy(busy: boolean): void {
  state.busy = busy;
  for (const el of [
    signOnceButton,
    stepButton,
    regenKeyButton,
    run100,
    run1000,
    resetHist,
    presetSelect,
    runDistinguishabilityButton,
    measureButton,
    customPCheck,
    deterministicCheck,
  ]) {
    el.disabled = busy;
  }
  // These two are only interactive when their toggle is on, so don't let
  // setBusy(false) re-enable them unconditionally.
  pSlider.disabled = busy || !customPCheck.checked;
  seedInput.disabled = busy || !deterministicCheck.checked;
}

async function runHistogramBatch(count: number): Promise<void> {
  if (state.busy) return;
  setBusy(true);
  try {
    signSummary.innerHTML = `<p>Running ${intFmt.format(count)} signatures at ${state.currentPreset}…</p>`;
    const payload = await runJob<{
      iterationCounts: number[];
      reasonBreakdown: [string, number][];
      mean: number;
      median: number;
      p90: number;
      p99: number;
      max: number;
    }>(
      { kind: 'histogram', count, preset: state.currentPreset, acceptance: state.customAcceptance ?? undefined },
      (m) => {
        if ((m.done ?? 0) < count)
          signSummary.innerHTML = `<p>Running ${state.currentPreset} batch: ${intFmt.format(m.done ?? 0)} / ${intFmt.format(count)}…</p>`;
      },
    );
    for (const c of payload.iterationCounts) {
      state.iterationHistory.push(c);
      state.histogramRuns += 1;
    }
    for (const [reason, n] of payload.reasonBreakdown) {
      state.reasonBreakdown.set(reason, (state.reasonBreakdown.get(reason) ?? 0) + n);
    }
    renderHistogram();
    renderReasonBreakdown();
    signSummary.innerHTML = `
      <p>Batch complete: ${intFmt.format(count)} signatures at <strong>${state.currentPreset}${state.customAcceptance !== null ? ` (p=${activeAcceptance().toFixed(2)})` : ''}</strong> (${intFmt.format(state.histogramRuns)} total).</p>
      <p>Mean: ${payload.mean.toFixed(2)} · Median: ${payload.median.toFixed(2)} · P90: ${payload.p90.toFixed(2)} · P99: ${payload.p99.toFixed(2)} · Max: ${payload.max}</p>
    `;
  } catch (err) {
    signSummary.innerHTML = `<p>Batch failed: ${escapeHtml(String((err as Error)?.message ?? err))}</p>`;
  } finally {
    setBusy(false);
  }
}

async function measureRealTimes(): Promise<void> {
  if (state.busy) return;
  setBusy(true);
  measureProgress.textContent = 'Warming up…';
  realtimeHist.innerHTML = '<p class="meta hist-empty">Measuring real signatures…</p>';
  try {
    const payload = await runJob<{ times: number[] }>({ kind: 'realtiming', count: 2000 }, (m) => {
      measureProgress.textContent = `Measured ${intFmt.format(m.done ?? 0)} / 2,000…`;
    });
    state.realTimes = payload.times;
    measureProgress.textContent = `Done: ${intFmt.format(payload.times.length)} real signatures timed.`;
    renderRealTiming();
  } catch (err) {
    measureProgress.textContent = '';
    realtimeHist.innerHTML = `<p class="meta">Measurement failed: ${escapeHtml(String((err as Error)?.message ?? err))}</p>`;
  } finally {
    setBusy(false);
  }
}

async function runDistinguishabilityTestAction(): Promise<void> {
  if (state.busy) return;
  setBusy(true);
  distinguishabilityOutput.textContent = 'Running 2 × 1000 simulated signatures at ML-DSA-65…';
  ksChart.innerHTML = '';
  try {
    const payload = await runJob<{ a: number[]; b: number[]; verdict: KsVerdict }>(
      { kind: 'ks', n: 1000, preset: 'ML-DSA-65' },
      (m) => {
        distinguishabilityOutput.textContent = `Running 2 × 1000 simulated signatures at ML-DSA-65…\npopulation A: ${m.a ?? 0} / 1000\npopulation B: ${m.b ?? 0} / 1000`;
      },
    );
    const { a, b, verdict } = payload;
    ksChart.innerHTML =
      cdfOverlaySvg(a, b) +
      `<div class="chart-legend" aria-hidden="true"><span><span class="lg-swatch lg-cdf-a"></span>population A</span><span><span class="lg-swatch lg-cdf-b"></span>population B</span><span><span class="lg-swatch lg-mean"></span>KS gap</span></div>`;
    distinguishabilityOutput.textContent = [
      'Both populations are drawn from the same simulated acceptance distribution,',
      `so under H0 we expect ~${Math.round(verdict.alpha * 100)}% of runs to cross the threshold by chance.`,
      '',
      `KS statistic:    ${verdict.ksStatistic.toFixed(4)}`,
      `alpha=${verdict.alpha} threshold: ${verdict.criticalValue.toFixed(4)}`,
      `Result:          ${verdict.exceedsCritical ? 'exceeds threshold' : 'below threshold'}`,
      '',
      verdict.note,
      '',
      'This illustrates the FIPS 204 design intent (sk-independent',
      'acceptance) — not a measurement of real noble signing times.',
    ].join('\n');
  } catch (err) {
    distinguishabilityOutput.textContent = `Test failed: ${(err as Error)?.message ?? err}`;
  } finally {
    setBusy(false);
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

messageInput.addEventListener('input', () => {
  state.currentMessage = messageInput.value;
});

async function triggerSignOnce(): Promise<void> {
  if (state.busy) return;
  setBusy(true);
  try {
    await signOnce();
  } catch (err) {
    signSummary.innerHTML = `<p>Sign failed: ${escapeHtml(String((err as Error)?.message ?? err))}</p>`;
  } finally {
    setBusy(false);
  }
}

messageInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    void triggerSignOnce();
  }
});
signOnceButton.addEventListener('click', () => void triggerSignOnce());

stepButton.addEventListener('click', async () => {
  if (state.busy) return;
  setBusy(true);
  try {
    await stepOnce();
  } catch (err) {
    signSummary.innerHTML = `<p>Step failed: ${escapeHtml(String((err as Error)?.message ?? err))}</p>`;
  } finally {
    setBusy(false);
  }
});

regenKeyButton.addEventListener('click', () => {
  if (state.busy) return;
  state.keypair = ml_dsa65.keygen();
  state.step = null;
  state.lastSig = null;
  tamperPanel.hidden = true;
  iterationFeed.innerHTML = '';
  stepButton.textContent = 'Step ▶';
  signSummary.innerHTML = '<p>New ML-DSA-65 keypair generated. Click Sign Once or Step to produce a fresh trace.</p>';
});

deterministicCheck.addEventListener('change', () => {
  state.deterministic = deterministicCheck.checked;
  seedField.hidden = !state.deterministic;
  detNote.hidden = !state.deterministic;
});
seedInput.addEventListener('input', () => {
  const v = Number.parseInt(seedInput.value, 10);
  state.seed = Number.isFinite(v) ? v : 0;
});

tamperFlip.addEventListener('click', () => {
  if (!state.lastSig) return;
  const sig = Uint8Array.from(state.lastSig.signature);
  const i = randomInt(0, sig.length - 1);
  sig[i] = (sig[i] ?? 0) ^ 0x01;
  const ok = ml_dsa65.verify(sig, state.lastSig.message, state.keypair.publicKey);
  tamperResult.textContent = `flipped 1 bit of byte ${i} → verifies ${ok ? '✓ (!)' : '✗ no'}`;
  tamperResult.className = `tamper-result ${ok ? 'ok' : 'bad'}`;
});
tamperRestore.addEventListener('click', () => {
  if (!state.lastSig) return;
  const ok = ml_dsa65.verify(state.lastSig.signature, state.lastSig.message, state.keypair.publicKey);
  tamperResult.textContent = `original signature verifies ${ok ? '✓' : '✗'}`;
  tamperResult.className = `tamper-result ${ok ? 'ok' : 'bad'}`;
});

run100.addEventListener('click', () => void runHistogramBatch(100));
run1000.addEventListener('click', () => void runHistogramBatch(1000));
resetHist.addEventListener('click', () => {
  state.iterationHistory = [];
  state.histogramRuns = 0;
  state.reasonBreakdown = new Map();
  renderHistogram();
  renderReasonBreakdown();
});

presetSelect.addEventListener('change', () => {
  if (state.busy) {
    presetSelect.value = state.currentPreset;
    return;
  }
  state.currentPreset = presetSelect.value as PresetName;
  state.iterationHistory = [];
  state.histogramRuns = 0;
  state.reasonBreakdown = new Map();
  renderHistogram();
  renderReasonBreakdown();
});

function updateAcceptanceUi(): void {
  const p = activeAcceptance();
  pReadout.textContent =
    state.customAcceptance !== null ? `p = ${p.toFixed(2)} · expected mean 1/p = ${(1 / p).toFixed(2)}` : '';
}
customPCheck.addEventListener('change', () => {
  pSlider.disabled = !customPCheck.checked;
  state.customAcceptance = customPCheck.checked ? Number.parseFloat(pSlider.value) : null;
  state.iterationHistory = [];
  state.histogramRuns = 0;
  state.reasonBreakdown = new Map();
  updateAcceptanceUi();
  renderHistogram();
  renderReasonBreakdown();
});
pSlider.addEventListener('input', () => {
  state.customAcceptance = Number.parseFloat(pSlider.value);
  state.iterationHistory = [];
  state.histogramRuns = 0;
  state.reasonBreakdown = new Map();
  updateAcceptanceUi();
  renderHistogram();
  renderReasonBreakdown();
});

measureButton.addEventListener('click', () => void measureRealTimes());
runDistinguishabilityButton.addEventListener('click', () => void runDistinguishabilityTestAction());

histogramRoot.addEventListener('click', (e) => {
  const g = (e.target as Element).closest<SVGElement>('[data-iter]');
  if (!g) return;
  const k = Number(g.getAttribute('data-iter'));
  if (k > 0) void showExampleTrace(k);
});
histogramRoot.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  const g = (e.target as Element).closest<SVGElement>('[data-iter]');
  if (!g) return;
  e.preventDefault();
  const k = Number(g.getAttribute('data-iter'));
  if (k > 0) void showExampleTrace(k);
});

const themeToggleButton = document.querySelector<HTMLButtonElement>('#theme-toggle');
if (themeToggleButton) {
  const updateLabel = (): void => {
    const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    themeToggleButton.textContent = next === 'dark' ? 'Dark theme' : 'Light theme';
    themeToggleButton.setAttribute('aria-label', `Switch to ${next} theme`);
  };
  updateLabel();
  themeToggleButton.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateLabel();
  });
}

renderHistogram();
renderReasonBreakdown();
renderRealTiming();
renderCheckExplanations();
