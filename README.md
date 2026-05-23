# crypto-lab-dilithium-reject

Browser-based explainer for ML-DSA rejection sampling: the Fiat-Shamir with Aborts loop that makes lattice signatures secure.

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
> 1 Corinthians 10:31

## What It Is

This project visualizes the signing rejection loop used by ML-DSA (FIPS 204, August 2024). It walks through what happens iteration by iteration: a candidate is drawn, four norm-bound checks are applied, and either the candidate is accepted or one specific check fails and the loop retries.

The demo targets ML-DSA-65 (NIST level 3) by default and uses strict TypeScript with a browser-only stack (Vite + vanilla CSS, no backend).

Highlights:
- Live iteration feed with explicit rejection reason (`z_too_large`, `r0_too_large`, `ct0_too_large`, `hint_too_dense`)
- Histogram of iterations-until-acceptance over many signatures, per parameter preset
- KS-style distinguishability test for the principle behind sk-independent timing
- Comparison table across Ed25519, ECDSA, ML-DSA, SLH-DSA, FALCON, LMS
- Exhibit explaining why each rejection check exists in FIPS 204

## How This Demo Works (Important)

The iteration feed in Exhibit 1 and the histogram in Exhibit 2 are a **didactic simulation calibrated to ML-DSA's published acceptance distribution**, not a fork of the real signing internals.

- Acceptance per iteration is a coin flip with `p(accept)` set per preset (~0.31 for ML-DSA-44, ~0.26 for ML-DSA-65, ~0.22 for ML-DSA-87). The mean number of iterations therefore matches what FIPS 204 implementations report in practice.
- When a candidate is rejected, the specific reason is sampled from the published mix (z dominates, r0 next, ct0 and hint rare). The displayed `||z||∞`, `||r0||∞`, `||c·t0||∞` values are positioned above/below their thresholds to be consistent with that reason; they are not computed from a live `y + c·s1` etc.
- The actual signature shown as "valid" is produced by [`@noble/post-quantum`](https://www.npmjs.com/package/@noble/post-quantum)'s real ML-DSA implementation. The verification check uses the same library. That part is real.
- `src/mldsa-primitives.ts` contains real implementations of `infinityNorm`, `highBits`/`lowBits`, `hintWeight`, and a SampleInBall variant; it is wired into the demo for the per-check explanation exhibit but does not drive the iteration feed.

This separation is deliberate: instrumenting `@noble/post-quantum`'s signing loop from outside the library would require patching internals, while the goal here is pedagogical clarity. The simulation is faithful to the *shape* and *reasons* — not the bit-exact arithmetic — of FIPS 204 § 6.

If you need bit-exact internal traces of real ML-DSA signing, use a reference implementation that exposes per-iteration hooks (e.g. NIST's C reference) rather than this demo.

## When to Use It

Use this demo when you need to:
- teach why ML-DSA signing time is variable by design
- explain Fiat-Shamir with Aborts in lattice signatures
- show that rejection is a security feature, not an implementation bug
- discuss timing side-channel risk tradeoffs in post-quantum signatures
- compare ML-DSA timing behavior with other signature families

Do not use this project as production signing code. For production, use maintained, hardened libraries and platform-specific side-channel countermeasures.

## Install and Run

```bash
npm install
npm run dev       # local dev server with hot reload
npm run build     # type-check + production build to ./dist
npm run preview   # serve the built bundle
```

Requires Node 22+. The build is a static bundle; the GitHub Pages workflow (`.github/workflows/deploy.yml`) publishes `./dist` to `gh-pages` on each push to `main`.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-dilithium-reject/

## What Can Go Wrong (in real deployments)

- Variable signing time can become a side-channel if deployment hardening is weak.
- Worst-case retries matter operationally; FIPS 204 permits bounded loops with failure return.
- Rejection-loop timing is not the only leak source; arithmetic and memory access patterns also matter.
- Deterministic mode has reproducibility benefits but different timing-privacy tradeoffs.
- Different ML-DSA parameter sets shift acceptance distributions; the histogram preset selector illustrates this.

## Real-World Usage

Fiat-Shamir with Aborts was introduced by Vadim Lyubashevsky (ASIACRYPT 2009) and is the core idea behind practical lattice signatures like CRYSTALS-Dilithium and standardized ML-DSA.

NIST selected Dilithium in 2022, then published FIPS 204 in 2024. The standardized ML-DSA design keeps rejection as a deliberate mechanism to preserve signature security, while implementations must manage the operational and side-channel consequences of variable-time signing loops.

## License

MIT — see [LICENSE](LICENSE).
