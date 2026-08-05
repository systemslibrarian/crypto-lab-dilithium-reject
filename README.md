# crypto-lab-dilithium-reject

[![CI](https://github.com/systemslibrarian/crypto-lab-dilithium-reject/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-dilithium-reject/actions/workflows/ci.yml)

## What It Is

This project visualizes the signing rejection loop used by ML-DSA (FIPS 204, August 2024). It walks through what happens iteration by iteration: a candidate is drawn, four norm-bound checks are applied, and either the candidate is accepted or one specific check fails and the loop retries.

The demo targets ML-DSA-65 (NIST level 3) by default and uses strict TypeScript with a browser-only stack (Vite + vanilla CSS, no backend).

All signing runs in a **Web Worker** so the UI stays smooth.

Highlights — **real instrumented cryptography** (see [how it works](#how-this-demo-works-important)):

- **The actual FIPS 204 signing loop, instrumented.** `src/real-sign.ts` vendors [`@noble/post-quantum`](https://www.npmjs.com/package/@noble/post-quantum)'s ML-DSA signing internals with one change: a per-iteration probe. The test suite asserts the probed loop produces **byte-identical signatures** to the untouched library for all three parameter sets.
- **Streamed iteration feed** revealing each real candidate one-by-one: the real κ counter, the real commitment hash c̃, and four labelled PASS/FAIL checks (`‖z‖∞`, `‖r₀‖∞`, `‖c·t₀‖∞`, `wt(h)`) whose values are computed from the live `y + c·s₁` arithmetic — plus a **step-through mode**
- **SVG histogram of real iteration counts** with a geometric-PMF overlay whose `p̂` is **measured from the batch** (published estimates shown for reference), a `mean = 1/p̂` marker, worst-case tail stats, and a **rejection-reason breakdown measured from real rejections**. **Click any bar** to hunt for a real trace of exactly that length
- **KS distinguishability test on real data**: two freshly generated keys each sign hundreds of real signatures; their iteration-count CDFs overlay and the max gap is marked — demonstrating sk-independent acceptance on the real scheme
- **A positive control**: switch Exhibit 6 to the _broken (hypothetical)_ scenario and a simulated implementation whose acceptance depends on the secret key sneaks into one population. Guess which — then watch the KS test catch it
- **Exhibit 3 measures real signing times**: thousands of actual `ml_dsa65.sign` calls timed with `performance.now()`, plotting the genuine right-skewed wall-clock distribution (with an honest caveat about timer resolution)
- **Tamper test**: flip one bit of a produced signature and watch real `ml_dsa65.verify` reject it
- **Reproducible (seeded) mode** that derives both the keypair and the signing randomness from a seed, so the **exact real trace and signature replay** — and can be shared as a URL

Learning aids:

- **Guided tour** (`▶ Start guided tour`) that walks the exhibits with narrative and self-check quiz questions
- **Shareable links** encoding preset, seed, message, and exploratory settings (`?preset=…&seed=…`)
- **Chart exports**: SVG/PNG for slides, CSV of iteration counts and timing data
- An **exploratory `p` slider** (clearly labelled as simulation) to drag the acceptance probability and watch the geometric curve move, plus a **compare-presets overlay** of the three parameter sets' theoretical curves

Plus: comparison table across Ed25519/ECDSA/ML-DSA/SLH-DSA/FALCON/LMS, an exhibit explaining why each check exists in FIPS 204, a symbols glossary with further-reading links, dark/light themes (AA/AAA contrast), keyboard + screen-reader support (verified by an axe-core test), and `prefers-reduced-motion` handling.

## When to Use It

Use this demo when you need to:

- teach why ML-DSA signing time is variable by design
- explain Fiat-Shamir with Aborts in lattice signatures
- show that rejection is a security feature, not an implementation bug
- discuss timing side-channel risk tradeoffs in post-quantum signatures
- compare ML-DSA timing behavior with other signature families

Do not use this project as production signing code. For production, use maintained, hardened libraries and platform-specific side-channel countermeasures.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-dilithium-reject](https://systemslibrarian.github.io/crypto-lab-dilithium-reject/)**

The page streams the real ML-DSA signing rejection loop iteration by iteration, plots a histogram of real iterations-until-acceptance against the geometric distribution at the measured p̂, breaks down real rejection reasons, and runs a KS distinguishability test on real per-key populations (with a hypothetical leaky-signer scenario as the positive control). Exhibit 3 times thousands of real `ml_dsa65.sign` calls and a tamper test flips a bit so real `ml_dsa65.verify` rejects it.

![ML-DSA Rejection Sampling Explorer — dark theme, showing the per-check iteration trace and the histogram of iterations until acceptance with a theoretical geometric overlay](docs/screenshot.png)

<details>
<summary>Light theme</summary>

![Light theme: same layout, light palette](docs/screenshot-light.png)

</details>

## What Can Go Wrong

- Variable signing time can become a side-channel if deployment hardening is weak.
- Worst-case retries matter operationally; FIPS 204 permits bounded loops with failure return.
- Rejection-loop timing is not the only leak source; arithmetic and memory access patterns also matter.
- Deterministic mode has reproducibility benefits but different timing-privacy tradeoffs.
- Different ML-DSA parameter sets shift acceptance distributions; the histogram preset selector illustrates this.

## Real-World Usage

Fiat-Shamir with Aborts was introduced by Vadim Lyubashevsky (ASIACRYPT 2009) and is the core idea behind practical lattice signatures like CRYSTALS-Dilithium and standardized ML-DSA.

NIST selected Dilithium in 2022, then published FIPS 204 in 2024. The standardized ML-DSA design keeps rejection as a deliberate mechanism to preserve signature security, while implementations must manage the operational and side-channel consequences of variable-time signing loops.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-dilithium-reject
cd crypto-lab-dilithium-reject
npm install
npm run dev
```

## Related Demos

- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — the same ML-DSA primitive applied to signing and document sealing.
- [crypto-lab-falcon-seal](https://systemslibrarian.github.io/crypto-lab-falcon-seal/) — Falcon (FN-DSA), the other lattice signature standardized by NIST.
- [crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) — SLH-DSA (FIPS 205), the hash-based PQC signature alternative.
- [crypto-lab-hybrid-sign](https://systemslibrarian.github.io/crypto-lab-hybrid-sign/) — composite Ed25519 + ML-DSA-65 signatures for migration.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203), the lattice KEM companion to ML-DSA.

## How This Demo Works (Important)

**Exhibits 1–3 and the KS faithful scenario are real.** The core of the demo is `src/real-sign.ts`: [`@noble/post-quantum`](https://www.npmjs.com/package/@noble/post-quantum)'s ML-DSA signing internals (MIT), vendored with a per-iteration `onIteration` probe. Nothing that decides acceptance is changed — same SHAKE XOF streams, same NTT arithmetic, same coders, same check order — so the instrumented loop produces **byte-identical signatures** to the untouched library. That claim is enforced in CI: `src/real-sign.test.ts` signs with fixed entropy through both paths and compares the bytes, for ML-DSA-44, -65, and -87.

What that buys, concretely:

- **Exhibit 1's cards are real.** Each iteration record carries the real κ, the real c̃ commitment-hash prefix, and `‖z‖∞`, `‖r₀‖∞`, `‖c·t₀‖∞`, `wt(h)` computed from the live polynomials. One nuance: the production loop short-circuits at the first failing check; in the feed's detail mode the remaining checks are still evaluated (on the same real polynomials) so every card can show all four values. The reported rejection reason always follows the algorithm's own evaluation order.
- **Exhibit 2's histogram is real.** Batches run the instrumented loop (in its fast mode, which short-circuits exactly like production) and record how many candidates each real signature needed. The acceptance probability `p̂` in the stats is measured from the batch — the reference values (≈0.235 / ≈0.196 / ≈0.26 per preset, i.e. the Dilithium specification's expected 4.25 / 5.1 / 3.85 repetitions) are shown only for comparison. The rejection-reason breakdown counts real rejections; measured on real data, z and r₀ split the rejections roughly evenly while c·t₀ and the hint check almost never fire. (Making the loop real caught the demo's own earlier calibration being wrong — the previous "published" values overstated acceptance.)
- **Clicking a histogram bar hunts for a real trace** of exactly that length (searching by entropy, then replaying the match in detail mode). If the search budget runs out — long traces are geometrically rare — the demo falls back to an _explicitly labelled_ illustrative simulation.
- **Exhibit 6's faithful scenario is real**: two freshly generated keypairs each produce hundreds of real signatures, and the KS test compares their iteration-count distributions.
- **Seeded mode replays real traces.** The seed derives the ML-DSA keypair seed and the 32-byte signing entropy (FIPS 204 `rnd`), so the same seed — including via a shared link — reproduces the same real trace and the same signature bytes. The seeded entropy is intentionally non-cryptographic; that is the reproducibility feature, never a production pattern.

Two features are simulations, and say so in the UI:

- **The exploratory `p` slider** replaces the real batch with a calibrated coin-flip simulation so you can drag the acceptance probability freely. Its calibration is asserted by `src/instrumented-sign.test.ts` (±15% of `1/p`).
- **The broken (leaky) scenario in Exhibit 6** injects a _hypothetical_ implementation whose acceptance probability depends on the secret key — the defect the real scheme is designed not to have. It exists as a positive control: the KS test should (and does) catch it, which is what makes the null result on real data meaningful.

`src/mldsa-primitives.ts` remains a small didactic library (`infinityNorm`, `highBits`/`lowBits`, SampleInBall variant, seedable RNG) backing the per-check explanation exhibit and the simulation modes.

## Build & Scripts

```bash
npm install
npm run dev          # local dev server with hot reload
npm run build        # type-check + production build to ./dist
npm run preview      # serve the built bundle
npm test             # unit tests (vitest)
npm run lint         # eslint (typescript-eslint)
npm run format       # prettier --check
```

Requires Node 22+. The build is a static bundle; the GitHub Pages workflow (`.github/workflows/deploy.yml`) publishes `./dist` to `gh-pages` on each push to `main`, and `.github/workflows/ci.yml` lints, checks formatting, type-checks, builds, and tests every pull request.

## Testing

```bash
npm test
```

- `src/real-sign.test.ts` — **the correctness gate**: the instrumented loop must produce byte-identical signatures to untouched noble for all three parameter sets and several entropies; detail and fast modes must agree; iteration records must be internally consistent (stated reason's check actually fails, accepted record passes all four); measured acceptance lands in a sane band; the deterministic variant reproduces traces exactly.
- `src/distributions.test.ts` — the pure math behind the charts (geometric PMF/CDF/mean, histogram bucketing, continuous binning, empirical CDF, quantiles, KS max-gap).
- `src/instrumented-sign.test.ts` — **simulation calibration gate** for the exploratory mode: fails the build if mean iterations drift more than ±15% from `1/acceptance`, plus the rejection-reason mix, exact-length traces, and that the returned signature verifies under real noble ML-DSA-65.
- `src/timing-analysis.test.ts` — the KS distinguishability verdict, including the **leaky-signer positive control**: the demo's leak parameters must be detectable and two faithful populations must not be.
- `src/url-state.test.ts` — the shareable-link codec round-trips and rejects malformed input.
- `src/chart-export.test.ts` — CSV quoting and standalone-SVG serialization.
- `src/mldsa-primitives.test.ts` — `infinityNorm`, `highBits`/`lowBits` round-trip, `SampleInBall`, `expandMask` ranges, `hintWeight`, and the seedable RNG (same seed ⇒ identical trace).
- `src/real-timing.test.ts` — the real `ml_dsa65.sign` timing harness returns one non-negative duration per signature.
- `src/app.dom.test.ts` — renders the whole app in jsdom and asserts there are **no serious/critical accessibility violations** (axe-core), that every primary control is wired, and that the guided tour starts, advances, and exits.

## License

MIT — see [LICENSE](LICENSE).

---

_Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite._

_"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31_
