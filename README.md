# crypto-lab-dilithium-reject

Browser-based demo of ML-DSA rejection sampling: the Fiat-Shamir with Aborts loop that makes lattice signatures secure.

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."  
> 1 Corinthians 10:31

## What It Is

This project visualizes the signing rejection loop used by ML-DSA (FIPS 204, August 2024). Instead of showing only the final signature, it records each candidate iteration, marks every norm-bound check as pass/fail, and explains exactly why a candidate was rejected.

The demo targets ML-DSA-65 (NIST level 3) and uses strict TypeScript with a browser-only stack (Vite + vanilla CSS, no backend).

Highlights:
- Live iteration feed with explicit rejection reason (`z_too_large`, `r0_too_large`, `ct0_too_large`, `hint_too_dense`)
- Histogram of iterations-until-acceptance over many signatures
- Timing observation and secret-key distinguishability test
- Comparison table across Ed25519, ECDSA, ML-DSA, SLH-DSA, FALCON, LMS
- Exhibit section explaining why each rejection check exists

## When to Use It

Use this demo when you need to:
- teach why ML-DSA signing time is variable by design
- explain Fiat-Shamir with Aborts in lattice signatures
- show that rejection is a security feature, not an implementation bug
- discuss timing side-channel risk tradeoffs in post-quantum signatures
- compare ML-DSA timing behavior with other signature families

Do not use this project as production signing code. For production, use maintained, hardened libraries and platform-specific side-channel countermeasures.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-dilithium-reject/

## What Can Go Wrong

- Variable signing time can become a side-channel if deployment hardening is weak.
- Worst-case retries matter operationally; FIPS 204 permits bounded loops with failure return.
- Rejection-loop timing is not the only leak source; arithmetic and memory access patterns also matter.
- Deterministic mode has reproducibility benefits but different timing-privacy tradeoffs.
- Different ML-DSA parameter sets can shift acceptance distributions.

## Real-World Usage

Fiat-Shamir with Aborts was introduced by Vadim Lyubashevsky (ASIACRYPT 2009) and is the core idea behind practical lattice signatures like CRYSTALS-Dilithium and standardized ML-DSA.

NIST selected Dilithium in 2022, then published FIPS 204 in 2024. The standardized ML-DSA design keeps rejection as a deliberate mechanism to preserve signature security, while implementations must manage the operational and side-channel consequences of variable-time signing loops.
