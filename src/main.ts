import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import './style.css';
import pkg from '../package.json';
import { PRESETS, type IterationRecord, type PresetName, simulateTraceOfLength } from './instrumented-sign';
import { type MlDsaPresetName, type RealIterationRecord } from './real-sign';
import { downloadChartPng, downloadChartSvg, downloadCsv } from './chart-export';
import { buildShareUrl, parseUrlState } from './url-state';
import { createTour, type TourStep } from './tour';
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

/** What the worker returns for one real instrumented signing run. */
interface SignTracePayload {
  signature: Uint8Array;
  iterations: RealIterationRecord[];
  acceptedIteration: number;
  totalTimeMs: number;
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
  lastSig: { signature: Uint8Array; message: Uint8Array; publicKey: Uint8Array } | null;
  step: { trace: SignTracePayload; index: number; verified: boolean; publicKey: Uint8Array } | null;
  realTimes: number[];
  ksMode: 'real' | 'leaky';
  leakGame: { leakyIs: 'a' | 'b'; honestP: number; leakyP: number; verdict: KsVerdict } | null;
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('Missing #app container');

const encoder = new TextEncoder();
const fmt = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 });
const intFmt = new Intl.NumberFormat('en-US');
const nobleVersion = (pkg.dependencies?.['@noble/post-quantum'] ?? '').replace(/[^0-9.]/g, '');

// Shared links restore preset, seeded mode, message, and exploratory p.
const urlState = parseUrlState(window.location.search);

const state: AppState = {
  keypair: ml_dsa65.keygen(),
  currentMessage: urlState.message ?? 'Transfer $1000 to Bob',
  iterationHistory: [],
  histogramRuns: 0,
  busy: false,
  currentPreset: (urlState.preset as PresetName | undefined) ?? 'ML-DSA-65',
  reasonBreakdown: new Map(),
  customAcceptance: urlState.customAcceptance ?? null,
  deterministic: urlState.deterministic ?? false,
  seed: urlState.seed ?? 42,
  lastSig: null,
  step: null,
  realTimes: [],
  ksMode: 'real',
  leakGame: null,
};

const REASONS = [
  { key: 'z_too_large', label: '‖z‖∞ too large', cls: 'z' },
  { key: 'r0_too_large', label: '‖r₀‖∞ too large', cls: 'r0' },
  { key: 'ct0_too_large', label: '‖c·t₀‖∞ too large', cls: 'ct0' },
  { key: 'hint_too_dense', label: 'hint too dense', cls: 'hint' },
] as const;

app.innerHTML = `
<main class="lab" id="main-content">
  <div class="hero card">
    <header class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">ML-DSA Rejection Sampling</h1>
        <p class="cl-hero-sub">Fiat-Shamir with Aborts · FIPS 204 signing</p>
        <p class="cl-hero-desc">Watch ML-DSA-65 sign for real, iteration by iteration, as each candidate is accepted or rejected against the four norm-bound checks.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">Rejection is what keeps a signature statistically independent of the secret key, and it is why signing time varies. That variance is a deliberate safeguard, but it also opens a timing side-channel that implementations must manage.</p>
      </aside>
    </header>
    <div class="hero-tags">
      <span>FIPS 204 (ML-DSA-65)</span>
      <span>Signing is loop + abort</span>
      <span>Security through rejection</span>
    </div>
    <p class="sim-note" role="note">
      <strong>Real instrumented loop.</strong>
      The iteration trace, the histogram, and the KS test run the <em>actual</em> FIPS 204 signing loop — <code>@noble/post-quantum</code>'s implementation, vendored with a per-iteration probe. Every norm, rejection reason, and κ value is computed from the real y + c·s₁ arithmetic, and the test suite asserts the probed loop still produces <strong>byte-identical signatures</strong> to the untouched library. Only the clearly marked “exploratory p” slider and the “hypothetical leaky signer” scenario are simulations. See the
      <a href="https://github.com/systemslibrarian/crypto-lab-dilithium-reject#how-this-demo-works-important">README</a> for details.
    </p>
    <div class="controls hero-actions">
      <button id="tour-start" type="button">▶ Start guided tour</button>
    </div>
  </div>

  <section class="card">
    <h2>Exhibit 1: Watch the Loop</h2>
    <p class="meta">Fixed at ML-DSA-65. Each run executes the <strong>real</strong> FIPS 204 rejection loop and streams every iteration it actually performed — the norms shown are computed from the live y + c·s₁ arithmetic, and the signature is the loop's own output (verify and tamper with it below).</p>
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
      <span class="meta det-note" hidden>The seed derives both the keypair and the signing randomness, so the same seed replays the exact real trace and signature — shareable via the link button.</span>
      <button id="copy-link" type="button">Copy shareable link</button>
      <span id="copy-link-result" class="meta" role="status" aria-live="polite"></span>
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
    <p class="meta">Each bar counts <strong>real signatures</strong>: the batch runs the actual instrumented signing loop and records how many candidates each signature needed. Iteration count until acceptance behaves like a <strong>geometric random variable</strong> — each draw is (approximately) an independent trial with the same accept probability — so the bars should track the dotted geometric PMF with mean 1/p̂, where p̂ is <em>measured</em> from the batch. Tip: click a bar to hunt for a real trace of exactly that length.</p>
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
      <label class="inline-check" for="custom-p"><input type="checkbox" id="custom-p" /> Custom p (exploratory simulation)</label>
      <input type="range" id="p-slider" min="0.05" max="0.6" step="0.01" value="0.2" disabled aria-label="Exploratory acceptance probability" />
      <span id="p-readout" class="p-readout meta"></span>
      <label class="inline-check" for="overlay-presets"><input type="checkbox" id="overlay-presets" /> Compare presets (theory)</label>
    </div>
    <div class="chart-legend" aria-hidden="true">
      <span><span class="lg-swatch lg-bar"></span>observed</span>
      <span><span class="lg-swatch lg-pmf"></span>theoretical geometric PMF</span>
      <span><span class="lg-swatch lg-mean"></span>mean (1/p)</span>
    </div>
    <div id="histogram" class="histogram" role="group" aria-live="polite" aria-label="Histogram of iterations until acceptance"></div>
    <div id="stats" class="stats-grid" role="group" aria-label="Histogram summary statistics"></div>
    <p id="tail-note" class="meta tail-note"></p>
    <div class="controls subtle export-row">
      <span class="meta">Export:</span>
      <button id="export-hist-svg" type="button" class="mini-btn">SVG</button>
      <button id="export-hist-png" type="button" class="mini-btn">PNG</button>
      <button id="export-hist-csv" type="button" class="mini-btn">CSV</button>
    </div>
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
    <div class="controls subtle export-row">
      <span class="meta">Export:</span>
      <button id="export-times-svg" type="button" class="mini-btn">SVG</button>
      <button id="export-times-png" type="button" class="mini-btn">PNG</button>
      <button id="export-times-csv" type="button" class="mini-btn">CSV</button>
    </div>
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
    <p class="meta">The design intent of FIPS 204 is that the acceptance distribution does not depend on the secret key. The <strong>faithful scenario</strong> measures this on real data: two freshly generated ML-DSA-65 keys each produce a population of real signatures, and their iteration-count CDFs are overlaid — the largest vertical gap is the Kolmogorov–Smirnov statistic, which should stay below the threshold. The <strong>broken scenario</strong> is the positive control: a <em>hypothetical</em> (simulated) implementation whose acceptance probability depends on the secret key. One population comes from it — can you tell which, before the KS test does?</p>
    <div class="controls">
      <label for="ks-mode">Scenario</label>
      <select id="ks-mode" aria-label="Distinguishability scenario">
        <option value="real" selected>Faithful — two real ML-DSA-65 signers</option>
        <option value="leaky">Broken (hypothetical) — one signer leaks</option>
      </select>
      <button id="run-distinguishability" type="button">Run KS test</button>
    </div>
    <div id="ks-chart" class="ks-chart"></div>
    <div id="leak-game" class="leak-game" hidden>
      <p><strong>One of these populations came from the leaky implementation.</strong> Read the CDFs: which signer rejects more (takes more iterations)?</p>
      <div class="controls">
        <button id="guess-a" type="button">Population A is leaky</button>
        <button id="guess-b" type="button">Population B is leaky</button>
      </div>
      <p id="leak-reveal" class="meta" role="status" aria-live="polite"></p>
    </div>
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
const tourStartButton = $<HTMLButtonElement>('#tour-start');
const copyLinkButton = $<HTMLButtonElement>('#copy-link');
const copyLinkResult = $<HTMLSpanElement>('#copy-link-result');
const overlayPresetsCheck = $<HTMLInputElement>('#overlay-presets');
const tailNote = $<HTMLParagraphElement>('#tail-note');
const ksModeSelect = $<HTMLSelectElement>('#ks-mode');
const leakGamePanel = $<HTMLDivElement>('#leak-game');
const guessAButton = $<HTMLButtonElement>('#guess-a');
const guessBButton = $<HTMLButtonElement>('#guess-b');
const leakReveal = $<HTMLParagraphElement>('#leak-reveal');

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
/**
 * Acceptance probability measured from the accumulated real batch (signatures
 * per candidate drawn) — the per-iteration MLE. Null until data exists or in
 * exploratory simulation mode.
 */
function measuredAcceptance(): number | null {
  if (state.customAcceptance !== null) return null;
  const totalIterations = state.iterationHistory.reduce((a, b) => a + b, 0);
  return state.histogramRuns > 0 && totalIterations > 0 ? state.histogramRuns / totalIterations : null;
}
function activeAcceptance(): number {
  return state.customAcceptance ?? measuredAcceptance() ?? PRESETS[state.currentPreset].acceptance;
}

/**
 * Derive (keypair, extraEntropy) for one signing run. In seeded mode both come
 * from the demo PRNG, so the same seed replays the exact real trace and
 * signature; otherwise the session keypair and the CSPRNG are used. (Seeded
 * entropy is intentionally non-cryptographic — that IS the reproducibility
 * feature, never a pattern for production signing.)
 */
function signingInputs(): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  extraEntropy: Uint8Array | undefined;
} {
  if (!state.deterministic) {
    return { secretKey: state.keypair.secretKey, publicKey: state.keypair.publicKey, extraEntropy: undefined };
  }
  setSeed(state.seed);
  const keySeed = randomBytes(32);
  const extraEntropy = randomBytes(32);
  setSeed(null);
  const kp = ml_dsa65.keygen(keySeed);
  return { secretKey: kp.secretKey, publicKey: kp.publicKey, extraEntropy };
}

/** Run one real instrumented signature in the worker. */
async function runRealSign(): Promise<{
  payload: SignTracePayload;
  publicKey: Uint8Array;
  verified: boolean;
  msg: Uint8Array;
}> {
  const msg = encoder.encode(state.currentMessage);
  const { secretKey, publicKey, extraEntropy } = signingInputs();
  const payload = await runJob<SignTracePayload>({
    kind: 'sign',
    preset: 'ML-DSA-65' satisfies MlDsaPresetName,
    message: msg,
    secretKey,
    extraEntropy,
  });
  const verified = ml_dsa65.verify(payload.signature, msg, publicKey);
  return { payload, publicKey, verified, msg };
}

/** Adapt a simulated iteration record to the real-record shape the feed renders. */
function simToReal(rec: IterationRecord): RealIterationRecord {
  const toCheck = (s: { infNorm: number; checkThreshold: number; passesCheck: boolean } | null) =>
    s ? { value: s.infNorm, threshold: s.checkThreshold, pass: s.passesCheck } : null;
  return {
    kappa: rec.kappa,
    yInf: rec.yStats.infNorm,
    cTildeHex: rec.cTildeFingerprint,
    z: toCheck(rec.zStats),
    r0: toCheck(rec.r0Stats),
    ct0: toCheck(rec.ct0Stats),
    hint: {
      value: rec.hintWeight ?? 0,
      threshold: rec.hintThreshold,
      pass: (rec.hintWeight ?? 0) <= rec.hintThreshold,
    },
    result: rec.result,
    rejectionReason: rec.rejectionReason,
    timeMs: rec.timeMs,
  };
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

function renderIteration(record: RealIterationRecord, idx: number): void {
  const row = document.createElement('article');
  row.className = `iteration ${record.result === 'ACCEPTED' ? 'accepted' : 'rejected'} reason-${record.rejectionReason ?? 'accepted'}`;

  const statusLabel = record.result === 'ACCEPTED' ? 'ACCEPTED' : `REJECTED · ${record.rejectionReason ?? ''}`;
  const checkVal = (c: { value: number; threshold: number } | null): string =>
    c ? `${intFmt.format(c.value)} / ${intFmt.format(c.threshold)}` : '—';

  const checks = [
    record.z ? checkRow('‖z‖∞ &lt; γ₁ − β', checkVal(record.z), record.z.pass, 'z') : '',
    record.r0 ? checkRow('‖r₀‖∞ &lt; γ₂ − β', checkVal(record.r0), record.r0.pass, 'r0') : '',
    record.ct0 ? checkRow('‖c·t₀‖∞ &lt; γ₂', checkVal(record.ct0), record.ct0.pass, 'ct0') : '',
    record.hint ? checkRow('wt(h) ≤ ω', checkVal(record.hint), record.hint.pass, 'hint') : '',
  ].join('');

  row.innerHTML = `
    <div class="iter-head">
      <h3>Iteration ${idx + 1}</h3>
      <span class="status-pill status-${record.result === 'ACCEPTED' ? 'accepted' : 'rejected'}">${statusLabel}</span>
    </div>
    <p class="iter-sub">κ = ${record.kappa} · c̃ ${record.cTildeHex} · ‖y‖∞ = ${intFmt.format(record.yInf)}</p>
    <ul class="checks">${checks}</ul>
  `;
  iterationFeed.append(row);
}

async function revealIterations(records: RealIterationRecord[]): Promise<void> {
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

function setLastSignature(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array, verified: boolean): void {
  state.lastSig = { signature, message, publicKey };
  tamperPanel.hidden = false;
  tamperResult.textContent = verified ? 'original signature verifies ✓' : 'original verifies ✗';
  tamperResult.className = `tamper-result ${verified ? 'ok' : 'bad'}`;
}

async function signOnce(): Promise<void> {
  state.step = null;
  stepButton.textContent = 'Step ▶';
  iterationFeed.innerHTML = '';
  signSummary.innerHTML =
    '<p>Signing with the real ML-DSA-65 loop… drawing candidates until one passes all four checks.</p>';

  const { payload, publicKey, verified, msg } = await runRealSign();

  await revealIterations(payload.iterations);

  const rejections = payload.acceptedIteration - 1;
  const seedNote = state.deterministic ? ` · seed ${state.seed} (seeded keypair)` : '';
  signSummary.innerHTML = `
    <p>Message: ${escapeHtml(state.currentMessage)}${seedNote}</p>
    <p>Accepted on iteration <strong>${payload.acceptedIteration}</strong> after <strong>${rejections}</strong> rejection${rejections === 1 ? '' : 's'} · real loop time <strong>${payload.totalTimeMs.toFixed(2)} ms</strong> (measured in the worker)</p>
    <p>Signature produced by the instrumented loop verifies via untouched noble ML-DSA-65: <strong>${verified ? 'yes' : 'no'}</strong></p>
  `;
  setLastSignature(payload.signature, msg, publicKey, verified);
}

async function stepOnce(): Promise<void> {
  // Start a new trace if none active or the previous one finished.
  if (!state.step || state.step.index >= state.step.trace.iterations.length) {
    const { payload, publicKey, verified } = await runRealSign();
    state.step = { trace: payload, index: 0, verified, publicKey };
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
      <p>Stepped through ${trace.acceptedIteration} real iteration${trace.acceptedIteration === 1 ? '' : 's'} (${rejections} rejection${rejections === 1 ? '' : 's'}).</p>
      <p>Signature verifies via noble ML-DSA-65: <strong>${state.step.verified ? 'yes' : 'no'}</strong></p>
    `;
    setLastSignature(trace.signature, msg, state.step.publicKey, state.step.verified);
    stepButton.textContent = 'Step ▶ (new trace)';
  } else {
    signSummary.innerHTML = `<p>Step ${state.step.index}: ${record?.result === 'REJECTED' ? `rejected (${record.rejectionReason}) — drawing again…` : 'accepted.'}</p>`;
    stepButton.textContent = 'Next step ▶';
  }
}

const FIND_TRACE_MAX_ATTEMPTS = 400;

async function showExampleTrace(k: number): Promise<void> {
  if (state.busy) return;
  setBusy(true);
  try {
    state.step = null;
    stepButton.textContent = 'Step ▶';
    tamperPanel.hidden = true;
    exhibit1.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });

    if (state.customAcceptance !== null) {
      // Exploratory simulation mode: construct an illustrative trace directly.
      const trace = simulateTraceOfLength(k, { preset: state.currentPreset, acceptance: state.customAcceptance });
      signSummary.innerHTML = `<p>Example trace of length <strong>${k}</strong> (exploratory simulation at p = ${state.customAcceptance.toFixed(2)} — no real signature).</p>`;
      await revealIterations(trace.iterations.map(simToReal));
      return;
    }

    // Real mode: hunt for an actual signature that took exactly k iterations.
    iterationFeed.innerHTML = '';
    signSummary.innerHTML = `<p>Hunting for a real ${state.currentPreset} signature that takes exactly <strong>${k}</strong> iterations…</p>`;
    const res = await runJob<{ found: boolean; attempts: number; iterations?: RealIterationRecord[] }>(
      {
        kind: 'find-trace',
        preset: state.currentPreset,
        target: k,
        maxAttempts: FIND_TRACE_MAX_ATTEMPTS,
      },
      (m) => {
        signSummary.innerHTML = `<p>Hunting for a real ${k}-iteration trace… ${intFmt.format(m.done ?? 0)} real signatures tried.</p>`;
      },
    );
    if (res.found && res.iterations) {
      signSummary.innerHTML = `<p>Found a <strong>real</strong> trace with exactly <strong>${k}</strong> iterations after ${intFmt.format(res.attempts)} real signature${res.attempts === 1 ? '' : 's'}.</p>`;
      await revealIterations(res.iterations);
    } else {
      const trace = simulateTraceOfLength(k, { preset: state.currentPreset });
      signSummary.innerHTML = `<p>No real ${k}-iteration trace turned up within ${intFmt.format(res.attempts)} tries (long traces are rare — that's the geometric tail). Showing an <em>illustrative simulated</em> trace instead.</p>`;
      await revealIterations(trace.iterations.map(simToReal));
    }
  } finally {
    setBusy(false);
  }
}

// ---------------------------------------------------------------------------
// Exhibit 2 — SVG histogram with geometric overlay
// ---------------------------------------------------------------------------

interface PmfOverlay {
  label: string;
  p: number;
  cls: string;
}

function histogramSvg(buckets: HistogramBucket[], p: number, total: number, overlays: PmfOverlay[] = []): string {
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
  const overlayPmfs = overlays.map((o) => buckets.map((b) => geometricPmf(o.p, b.iteration)));
  const maxObs = Math.max(0, ...buckets.map((b) => b.proportion));
  const maxPmf = Math.max(0, ...pmf, ...overlayPmfs.flat());
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
  const overlayLines = overlays
    .map((o, oi) => {
      const pts = buckets.map((_b, i) => `${cx(i).toFixed(1)},${sy(overlayPmfs[oi]?.[i] ?? 0).toFixed(1)}`).join(' ');
      return `<polyline class="pmf-line pmf-overlay ${o.cls}" points="${pts}"><title>${o.label}: geometric PMF at p = ${o.p.toFixed(2)}</title></polyline>`;
    })
    .join('');
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

  // role="group" (not "img"): the bars inside are interactive buttons, and
  // nesting widgets inside an image role is an axe "nested-interactive" error.
  return `<svg viewBox="0 0 ${W} ${H}" class="hist-svg" role="group" aria-label="Histogram of iterations until acceptance. Mean about ${m.toFixed(1)} iterations. Bars track a theoretical geometric distribution.">${grid}${axes}${bars}${overlayLines}${pmfLine}${pmfDots}${meanLine}${xLabels}${titles}</svg>`;
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

const OVERLAY_STYLES: Record<PresetName, string> = {
  'ML-DSA-44': 'pmf-p44',
  'ML-DSA-65': 'pmf-p65',
  'ML-DSA-87': 'pmf-p87',
};

function presetOverlays(): PmfOverlay[] {
  if (!overlayPresetsCheck.checked) return [];
  return (Object.keys(PRESETS) as PresetName[])
    .filter((name) => name !== state.currentPreset || state.customAcceptance !== null)
    .map((name) => ({ label: name, p: PRESETS[name].acceptance, cls: OVERLAY_STYLES[name] }));
}

function renderHistogram(): void {
  const p = activeAcceptance();
  const data = state.iterationHistory;
  const overlays = presetOverlays();
  const overlayLegend = overlays
    .map((o) => `<span><span class="lg-swatch lg-pmf ${o.cls}"></span>${o.label} (p≈${o.p.toFixed(2)})</span>`)
    .join('');

  if (data.length > 0) {
    const buckets = histogramBuckets(data);
    histogramRoot.innerHTML =
      histogramSvg(buckets, p, data.length, overlays) +
      (overlayLegend ? `<div class="chart-legend" aria-hidden="true">${overlayLegend}</div>` : '') +
      histogramTable(buckets);
  } else {
    // No data yet: show the theoretical curve(s) alone so dragging the slider
    // or toggling overlays still animates the geometric distribution.
    const span = Math.min(40, Math.max(12, Math.ceil(geometricMean(p) * 4)));
    const buckets: HistogramBucket[] = Array.from({ length: span }, (_v, i) => ({
      iteration: i + 1,
      count: 0,
      proportion: 0,
    }));
    const emptyNote =
      state.customAcceptance === null && overlays.length === 0
        ? '<p class="meta hist-empty">No data yet. Click Run 100 or Run 1000 to sign for real and build the distribution.</p>'
        : '';
    histogramRoot.innerHTML =
      histogramSvg(buckets, p, 0, overlays) +
      (overlayLegend ? `<div class="chart-legend" aria-hidden="true">${overlayLegend}</div>` : '') +
      emptyNote;
  }

  const isSim = state.customAcceptance !== null;
  const pHat = measuredAcceptance();
  const observedMean = sampleMean(data);
  const theoreticalMean = geometricMean(p);
  const publishedP = PRESETS[state.currentPreset].acceptance;
  const tailK = 8;
  const tailTheory = (1 - p) ** tailK;
  const tailObserved = data.length > 0 ? data.filter((v) => v > tailK).length / data.length : null;
  statsRoot.innerHTML = `
    <div><span class="k">Source</span><span class="v">${isSim ? 'simulation (custom p)' : 'real signing loop'}</span></div>
    <div><span class="k">Preset</span><span class="v">${state.currentPreset}${isSim ? ' (custom p)' : ''}</span></div>
    <div><span class="k">Runs</span><span class="v">${intFmt.format(state.histogramRuns)}</span></div>
    <div><span class="k">${isSim ? 'p (slider)' : 'Measured p̂'}</span><span class="v">${isSim ? p.toFixed(2) : pHat !== null ? `${pHat.toFixed(3)} (ref ≈ ${publishedP.toFixed(2)})` : '—'}</span></div>
    <div><span class="k">Observed mean</span><span class="v">${fmt.format(observedMean)}</span></div>
    <div><span class="k">Mean 1/p${isSim ? '' : '̂'}</span><span class="v">${fmt.format(theoreticalMean)}</span></div>
    <div><span class="k">Median</span><span class="v">${fmt.format(quantile(data, 0.5))}</span></div>
    <div><span class="k">P90</span><span class="v">${fmt.format(quantile(data, 0.9))}</span></div>
    <div><span class="k">P99</span><span class="v">${fmt.format(quantile(data, 0.99))}</span></div>
    <div><span class="k">Max</span><span class="v">${fmt.format(data.reduce((m, v) => (v > m ? v : m), 0))}</span></div>
    <div><span class="k">P(&gt;${tailK}) observed</span><span class="v">${tailObserved !== null ? `${(tailObserved * 100).toFixed(2)}%` : '—'}</span></div>
    <div><span class="k">P(&gt;${tailK}) theory</span><span class="v">${(tailTheory * 100).toFixed(2)}%</span></div>
  `;
  tailNote.textContent =
    `Worst-case tail: with p ≈ ${p.toFixed(2)}, P(more than 20 draws) = (1−p)²⁰ ≈ ${((1 - p) ** 20 * 100).toPrecision(2)}%. ` +
    `The FIPS 204 loop is unbounded in the spec, but implementations may bound it and return failure — the tail is why that bound matters operationally.`;
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
    ksModeSelect,
    guessAButton,
    guessBButton,
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
    const isSim = state.customAcceptance !== null;
    const runningLabel = isSim
      ? `Simulating ${intFmt.format(count)} traces at p = ${state.customAcceptance?.toFixed(2)}`
      : `Signing ${intFmt.format(count)} real ${state.currentPreset} signatures in the worker`;
    signSummary.innerHTML = `<p>${runningLabel}…</p>`;
    const request = isSim
      ? { kind: 'histogram-sim', count, preset: state.currentPreset, acceptance: state.customAcceptance }
      : { kind: 'histogram', count, preset: state.currentPreset };
    const payload = await runJob<{
      iterationCounts: number[];
      reasonBreakdown: [string, number][];
      mean: number;
      median: number;
      p90: number;
      p99: number;
      max: number;
      measuredAcceptance: number;
    }>(request, (m) => {
      if ((m.done ?? 0) < count)
        signSummary.innerHTML = `<p>${runningLabel}: ${intFmt.format(m.done ?? 0)} / ${intFmt.format(count)}…</p>`;
    });
    for (const c of payload.iterationCounts) {
      state.iterationHistory.push(c);
      state.histogramRuns += 1;
    }
    for (const [reason, n] of payload.reasonBreakdown) {
      state.reasonBreakdown.set(reason, (state.reasonBreakdown.get(reason) ?? 0) + n);
    }
    renderHistogram();
    renderReasonBreakdown();
    const sourceNote = isSim
      ? `simulated at p = ${state.customAcceptance?.toFixed(2)}`
      : `real signatures · measured p̂ = ${payload.measuredAcceptance.toFixed(3)} this batch`;
    signSummary.innerHTML = `
      <p>Batch complete: ${intFmt.format(count)} ${isSim ? 'traces' : 'signatures'} at <strong>${state.currentPreset}</strong> (${sourceNote}; ${intFmt.format(state.histogramRuns)} total).</p>
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

const KS_REAL_N = 500;
const KS_LEAKY_N = 1000;
const LEAK_DELTA = 0.06;

function renderKsChart(a: number[], b: number[]): void {
  ksChart.innerHTML =
    cdfOverlaySvg(a, b) +
    `<div class="chart-legend" aria-hidden="true"><span><span class="lg-swatch lg-cdf-a"></span>population A</span><span><span class="lg-swatch lg-cdf-b"></span>population B</span><span><span class="lg-swatch lg-mean"></span>KS gap</span></div>`;
}

function verdictLines(verdict: KsVerdict): string[] {
  return [
    `KS statistic:    ${verdict.ksStatistic.toFixed(4)}`,
    `alpha=${verdict.alpha} threshold: ${verdict.criticalValue.toFixed(4)}`,
    `Result:          ${verdict.exceedsCritical ? 'exceeds threshold — distinguishable' : 'below threshold — indistinguishable'}`,
  ];
}

async function runDistinguishabilityTestAction(): Promise<void> {
  if (state.busy) return;
  setBusy(true);
  state.leakGame = null;
  leakGamePanel.hidden = true;
  leakReveal.textContent = '';
  ksChart.innerHTML = '';
  try {
    if (state.ksMode === 'real') {
      distinguishabilityOutput.textContent = `Signing 2 × ${KS_REAL_N} REAL ML-DSA-65 signatures with two fresh keypairs…`;
      const payload = await runJob<{ a: number[]; b: number[]; verdict: KsVerdict }>(
        { kind: 'ks', n: KS_REAL_N, preset: 'ML-DSA-65' },
        (m) => {
          distinguishabilityOutput.textContent = `Signing 2 × ${KS_REAL_N} REAL ML-DSA-65 signatures with two fresh keypairs…\nsigner A: ${m.a ?? 0} / ${KS_REAL_N}\nsigner B: ${m.b ?? 0} / ${KS_REAL_N}`;
        },
      );
      renderKsChart(payload.a, payload.b);
      distinguishabilityOutput.textContent = [
        'Both populations are REAL iteration counts from the instrumented FIPS 204',
        'loop, each with its own freshly generated secret key.',
        '',
        ...verdictLines(payload.verdict),
        '',
        payload.verdict.note,
        '',
        `Under H0 (same distribution) ~${Math.round(payload.verdict.alpha * 100)}% of runs cross the`,
        'threshold by chance — so an occasional red result here is expected noise,',
        'not a leak. The design intent of FIPS 204 is exactly this: iteration',
        'count carries no information about which secret key was used.',
      ].join('\n');
    } else {
      distinguishabilityOutput.textContent = `Building 2 × ${KS_LEAKY_N} traces — one signer is a HYPOTHETICAL leaky implementation…`;
      const payload = await runJob<{
        a: number[];
        b: number[];
        leakyIs: 'a' | 'b';
        honestP: number;
        leakyP: number;
        verdict: KsVerdict;
      }>({ kind: 'ks-leaky', n: KS_LEAKY_N, preset: 'ML-DSA-65', leakDelta: LEAK_DELTA }, (m) => {
        distinguishabilityOutput.textContent = `Building 2 × ${KS_LEAKY_N} traces…\npopulation A: ${m.a ?? 0} / ${KS_LEAKY_N}\npopulation B: ${m.b ?? 0} / ${KS_LEAKY_N}`;
      });
      state.leakGame = {
        leakyIs: payload.leakyIs,
        honestP: payload.honestP,
        leakyP: payload.leakyP,
        verdict: payload.verdict,
      };
      renderKsChart(payload.a, payload.b);
      leakGamePanel.hidden = false;
      distinguishabilityOutput.textContent = [
        'One population comes from a simulated BROKEN implementation whose',
        'acceptance probability depends on the secret key — the exact defect the',
        'real scheme is designed not to have. Make your guess above, then the',
        'KS verdict is revealed.',
      ].join('\n');
    }
  } catch (err) {
    distinguishabilityOutput.textContent = `Test failed: ${(err as Error)?.message ?? err}`;
  } finally {
    setBusy(false);
  }
}

function revealLeakGuess(guess: 'a' | 'b'): void {
  const game = state.leakGame;
  if (!game) return;
  const correct = guess === game.leakyIs;
  leakReveal.innerHTML = `${correct ? '✓ Correct' : '✗ Not this one'} — population <strong>${game.leakyIs.toUpperCase()}</strong> is the leaky signer (p = ${game.leakyP.toFixed(2)} vs the faithful ${game.honestP.toFixed(2)}). Its CDF climbs more slowly: more rejections, more iterations, more time.`;
  leakReveal.className = `meta ${correct ? 'ok' : 'bad'}`;
  distinguishabilityOutput.textContent = [
    'Positive control: the populations really do differ, and the KS test finds it.',
    '',
    ...verdictLines(game.verdict),
    '',
    game.verdict.note,
    '',
    'This is what a timing side channel looks like from the outside: an attacker',
    'never sees the secret key, only iteration counts — yet the distributions',
    'separate. FIPS 204 makes the acceptance probability key-independent',
    'precisely so this attack finds nothing (switch back to the faithful',
    'scenario to see the null result on real data).',
  ].join('\n');
  state.leakGame = null;
  leakGamePanel.hidden = true;
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
  // setBusy only reconciles this while a job runs; toggling while idle must
  // enable/disable the field directly.
  seedInput.disabled = !state.deterministic;
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
  const ok = ml_dsa65.verify(sig, state.lastSig.message, state.lastSig.publicKey);
  tamperResult.textContent = `flipped 1 bit of byte ${i} → verifies ${ok ? '✓ (!)' : '✗ no'}`;
  tamperResult.className = `tamper-result ${ok ? 'ok' : 'bad'}`;
});
tamperRestore.addEventListener('click', () => {
  if (!state.lastSig) return;
  const ok = ml_dsa65.verify(state.lastSig.signature, state.lastSig.message, state.lastSig.publicKey);
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
ksModeSelect.addEventListener('change', () => {
  state.ksMode = ksModeSelect.value === 'leaky' ? 'leaky' : 'real';
  state.leakGame = null;
  leakGamePanel.hidden = true;
  leakReveal.textContent = '';
});
guessAButton.addEventListener('click', () => revealLeakGuess('a'));
guessBButton.addEventListener('click', () => revealLeakGuess('b'));

overlayPresetsCheck.addEventListener('change', () => renderHistogram());

// --- chart exports ---
$<HTMLButtonElement>('#export-hist-svg').addEventListener('click', () => {
  downloadChartSvg(histogramRoot, 'mldsa-iteration-histogram.svg');
});
$<HTMLButtonElement>('#export-hist-png').addEventListener('click', () => {
  downloadChartPng(histogramRoot, 'mldsa-iteration-histogram.png');
});
$<HTMLButtonElement>('#export-hist-csv').addEventListener('click', () => {
  const rows: (string | number)[][] = [['iterations_until_acceptance', 'count', 'proportion']];
  for (const b of histogramBuckets(state.iterationHistory)) rows.push([b.iteration, b.count, b.proportion]);
  downloadCsv('mldsa-iteration-histogram.csv', rows);
});
$<HTMLButtonElement>('#export-times-svg').addEventListener('click', () => {
  downloadChartSvg(realtimeHist, 'mldsa-real-signing-times.svg');
});
$<HTMLButtonElement>('#export-times-png').addEventListener('click', () => {
  downloadChartPng(realtimeHist, 'mldsa-real-signing-times.png');
});
$<HTMLButtonElement>('#export-times-csv').addEventListener('click', () => {
  const rows: (string | number)[][] = [['signature_index', 'signing_time_ms']];
  state.realTimes.forEach((t, i) => rows.push([i, t]));
  downloadCsv('mldsa-real-signing-times.csv', rows);
});

// --- shareable link ---
copyLinkButton.addEventListener('click', () => {
  const url = buildShareUrl(window.location.origin + window.location.pathname, {
    preset: state.currentPreset,
    deterministic: state.deterministic,
    seed: state.seed,
    message: state.currentMessage,
    customAcceptance: state.customAcceptance,
    tour: false,
  });
  const report = (ok: boolean): void => {
    copyLinkResult.textContent = ok
      ? state.deterministic
        ? 'copied — link replays this exact seeded trace ✓'
        : 'copied ✓'
      : url;
  };
  navigator.clipboard
    ?.writeText(url)
    .then(() => report(true))
    .catch(() => report(false));
  if (!navigator.clipboard) report(false);
});

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

// ---------------------------------------------------------------------------
// Guided tour
// ---------------------------------------------------------------------------

const TOUR_STEPS: TourStep[] = [
  {
    target: '.hero',
    title: 'Why does ML-DSA signing take a variable amount of time?',
    body: `<p>Because the algorithm is a <strong>loop that aborts on purpose</strong>. Each attempt draws a random candidate signature and applies four norm checks; if any check fails, the candidate is thrown away and the loop retries. This tour walks the real loop — everything you'll see is computed by the actual FIPS 204 arithmetic.</p>`,
  },
  {
    target: '.lab > section.card:nth-of-type(1)',
    title: 'Exhibit 1 — watch the real loop run',
    body: `<p>Click the button below (or “Sign Once” in the exhibit) and watch the iterations stream in. Each card is one real candidate: its κ counter, its commitment hash c̃, and the four checks with the <em>actual norms</em> the algorithm computed. Red cards were rejected; the green card is the signature you get.</p>`,
    action: { label: 'Sign one now', run: () => void triggerSignOnce() },
  },
  {
    target: '.lab > section.card:nth-of-type(1)',
    title: 'Quick check: a candidate just failed ‖z‖∞ < γ₁ − β',
    body: `<p>Look at any red card above.</p>`,
    quiz: {
      question: 'What does the algorithm do next?',
      options: [
        'Abort signing and return an error',
        'Increment κ, draw a fresh y, and try again',
        'Shrink z until it fits the bound',
      ],
      answer: 1,
      explain:
        'rejection is not failure — the loop simply retries with fresh randomness. Shrinking or reusing a rejected candidate would leak information about the secret key s₁.',
    },
  },
  {
    target: '.lab > section.card:nth-of-type(2)',
    title: 'Exhibit 2 — the shape of retrying',
    body: `<p>Each iteration is (approximately) an independent trial with the same acceptance probability p, so the number of iterations until success follows a <strong>geometric distribution</strong>. Run a real batch and watch the bars settle onto the dotted theoretical curve — and note the measured p̂ in the stats.</p>`,
    action: { label: 'Run 100 real signatures', run: () => void runHistogramBatch(100) },
  },
  {
    target: '.lab > section.card:nth-of-type(2)',
    title: 'Quick check: expected number of iterations',
    body: `<p>ML-DSA-65 accepts each candidate with probability p ≈ 0.2 (the Dilithium spec's expected 5.1 repetitions — and what the real batch above measures).</p>`,
    quiz: {
      question: 'On average, how many iterations does one signature take?',
      options: ['About 1 — rejection is rare', 'About 5 (1/p)', 'About 20'],
      answer: 1,
      explain:
        'the mean of a geometric distribution is 1/p ≈ 1/0.196 ≈ 5.1 — and the histogram’s mean marker sits right there.',
    },
  },
  {
    target: '.lab > section.card:nth-of-type(3)',
    title: 'Exhibit 3 — the loop you can measure from outside',
    body: `<p>This exhibit times thousands of untouched <code>ml_dsa65.sign</code> calls with <code>performance.now()</code>. The right-skewed spread mirrors the iteration histogram: more rejections ⇒ more wall-clock time. This is exactly what an attacker could observe — which is why the next question matters.</p>`,
  },
  {
    target: '.lab > section.card:nth-of-type(6)',
    title: 'Exhibit 6 — can timing reveal the key?',
    body: `<p>The <strong>faithful scenario</strong> compares real iteration counts from two different secret keys: the KS test should find nothing, because acceptance is key-independent by design. The <strong>broken scenario</strong> injects a hypothetical implementation whose acceptance <em>does</em> depend on the key — try to spot it before the statistics do.</p>`,
    action: {
      label: 'Run the broken (leaky) scenario',
      run: () => {
        ksModeSelect.value = 'leaky';
        state.ksMode = 'leaky';
        void runDistinguishabilityTestAction();
      },
    },
  },
  {
    target: '.lab > section.card:nth-of-type(4)',
    title: 'Last check: why is rejection a security feature?',
    body: `<p>Exhibit 4 explains what each individual check protects. The big picture:</p>`,
    quiz: {
      question: 'Rejecting out-of-range candidates matters because…',
      options: [
        'It compresses signatures so they fit in 3,309 bytes',
        'It keeps published signatures statistically independent of the secret key',
        'It speeds signing up by skipping slow candidates',
      ],
      answer: 1,
      explain:
        'a z that escaped the γ₁ − β bound would be correlated with c·s₁ — collect enough of them and the secret key falls out. Rejection buys security with time, which is why variable signing time is a feature, not a bug.',
    },
  },
];

const tour = createTour(TOUR_STEPS);
tourStartButton.addEventListener('click', () => tour.start());

// ---------------------------------------------------------------------------
// Initial state sync (URL-restored values → controls) and first render
// ---------------------------------------------------------------------------

messageInput.value = state.currentMessage;
presetSelect.value = state.currentPreset;
deterministicCheck.checked = state.deterministic;
seedInput.value = String(state.seed);
seedField.hidden = !state.deterministic;
detNote.hidden = !state.deterministic;
seedInput.disabled = !state.deterministic;
if (state.customAcceptance !== null) {
  customPCheck.checked = true;
  pSlider.disabled = false;
  pSlider.value = state.customAcceptance.toFixed(2);
  updateAcceptanceUi();
}

renderHistogram();
renderReasonBreakdown();
renderRealTiming();
renderCheckExplanations();

if (urlState.tour) tour.start();
