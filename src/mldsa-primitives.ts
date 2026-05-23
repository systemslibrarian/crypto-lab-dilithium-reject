import { sha256 } from '@noble/hashes/sha2.js';

/**
 * ML-DSA-65 parameters per FIPS 204 Table 1.
 */
export const ML_DSA_65 = {
  n: 256,
  q: 8380417,
  d: 13,
  tau: 49,
  gamma1: 524288,
  gamma2: 261888,
  k: 6,
  l: 5,
  eta: 4,
  beta: 196,
  omega: 55,
} as const;

export type Polynomial = Int32Array;

function modQ(x: number, q: number): number {
  const r = x % q;
  return r < 0 ? r + q : r;
}

function centeredModQ(x: number, q: number): number {
  const r = modQ(x, q);
  const half = Math.floor(q / 2);
  return r > half ? r - q : r;
}

function randomUint32(): number {
  const out = new Uint32Array(1);
  crypto.getRandomValues(out);
  return out[0] ?? 0;
}

function randomIntInclusive(min: number, max: number): number {
  if (max < min) throw new Error('invalid random range');
  const span = max - min + 1;
  const lim = Math.floor(0x100000000 / span) * span;
  let x = randomUint32();
  while (x >= lim) {
    x = randomUint32();
  }
  return min + (x % span);
}

function digestSha256(data: Uint8Array): Uint8Array {
  return Uint8Array.from(sha256(data));
}

/**
 * Didactic counter-mode XOF over SHA-256. FIPS 204 specifies SHAKE-256;
 * we use SHA-256 here because the shape of the construction is what
 * matters pedagogically and SHA-256 is one less dependency to explain.
 */
class DeterministicStream {
  private seed: Uint8Array;

  private counter = 0;

  private buf: Uint8Array = new Uint8Array(0);

  private idx = 0;

  constructor(seed: Uint8Array) {
    this.seed = seed;
  }

  private refill(): void {
    const ctr = new Uint8Array(4);
    const dv = new DataView(ctr.buffer);
    dv.setUint32(0, this.counter, false);
    this.counter += 1;
    const input = new Uint8Array(this.seed.length + ctr.length);
    input.set(this.seed, 0);
    input.set(ctr, this.seed.length);
    this.buf = digestSha256(input);
    this.idx = 0;
  }

  takeByte(): number {
    if (this.idx >= this.buf.length) this.refill();
    const b = this.buf[this.idx] ?? 0;
    this.idx += 1;
    return b;
  }

  takeUint16(): number {
    const lo = this.takeByte();
    const hi = this.takeByte();
    return lo | (hi << 8);
  }
}

export function infinityNorm(p: Polynomial, q: number): number {
  let best = 0;
  for (let i = 0; i < p.length; i += 1) {
    const centered = centeredModQ(p[i] ?? 0, q);
    const abs = Math.abs(centered);
    if (abs > best) best = abs;
  }
  return best;
}

export function highBits(r: number, alpha: number): number {
  return Math.round(r / alpha);
}

export function lowBits(r: number, alpha: number): number {
  return r - highBits(r, alpha) * alpha;
}

/**
 * Real SampleInBall, structurally per FIPS 204 § 8.5.3.
 * Uses the didactic DeterministicStream above instead of SHAKE-256.
 */
export function sampleInBall(
  cTilde: Uint8Array,
  tau: number,
  n: number,
): Polynomial {
  const poly = new Int32Array(n);
  const stream = new DeterministicStream(cTilde);
  let placed = 0;
  while (placed < tau) {
    const pos = stream.takeUint16() % n;
    if (poly[pos] !== 0) continue;
    const sign = (stream.takeByte() & 1) === 0 ? 1 : -1;
    poly[pos] = sign;
    placed += 1;
  }
  return poly;
}

/**
 * Didactic mask sampler. The real ExpandMask in FIPS 204 § 7.3 derives
 * 256 coefficients in [-gamma1+1, gamma1] from SHAKE-256(rho' || kappa).
 * We approximate the *output distribution* using uniform random integers
 * so per-iteration y has realistic-looking range without dragging in a
 * full SHAKE implementation. The (rhoPrime, kappa) inputs are accepted
 * for API parity and folded in via XOR so changing them changes y.
 */
export function expandMask(
  rhoPrime: Uint8Array,
  kappa: number,
  gamma1: number,
  n: number,
): Polynomial {
  const poly = new Int32Array(n);
  const seed = new Uint8Array(rhoPrime.length + 4);
  seed.set(rhoPrime, 0);
  const dv = new DataView(seed.buffer);
  dv.setUint32(rhoPrime.length, kappa, false);

  let carry = 0;
  let carryBits = 0;
  const span = 2 * gamma1;

  for (let i = 0; i < n; i += 1) {
    while (carryBits < 24) {
      const seedByte = seed[(i + carryBits) % seed.length] ?? 0;
      const chunk = randomUint32() ^ seedByte;
      carry |= (chunk & 0xff) << carryBits;
      carryBits += 8;
    }
    const val = carry & 0xffffff;
    carry >>>= 24;
    carryBits -= 24;
    poly[i] = (val % span) - (gamma1 - 1);
  }
  return poly;
}

export function hintWeight(hints: Polynomial[]): number {
  let w = 0;
  for (const h of hints) {
    for (let i = 0; i < h.length; i += 1) {
      if ((h[i] ?? 0) !== 0) w += 1;
    }
  }
  return w;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export function randomInt(min: number, max: number): number {
  return randomIntInclusive(min, max);
}

export function uniform01(): number {
  return randomUint32() / 0x100000000;
}
