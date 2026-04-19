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

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function digestSha256(data: Uint8Array): Uint8Array {
  return Uint8Array.from(sha256(data));
}

class DeterministicStream {
  private seed: Uint8Array;

  private counter = 0;

  private buf = new Uint8Array(0);

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
    this.buf = new Uint8Array(digestSha256(input));
    this.idx = 0;
  }

  async takeByte(): Promise<number> {
    if (this.idx >= this.buf.length) this.refill();
    const b = this.buf[this.idx] ?? 0;
    this.idx += 1;
    return b;
  }

  async takeUint16(): Promise<number> {
    const lo = await this.takeByte();
    const hi = await this.takeByte();
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
  const rounded = Math.round(r / alpha);
  return rounded;
}

export function lowBits(r: number, alpha: number): number {
  return r - highBits(r, alpha) * alpha;
}

export async function sampleInBall(
  cTilde: Uint8Array,
  tau: number,
  n: number,
): Promise<Polynomial> {
  const poly = new Int32Array(n);
  const stream = new DeterministicStream(cTilde);
  let placed = 0;
  while (placed < tau) {
    const pos = (await stream.takeUint16()) % n;
    if (poly[pos] !== 0) continue;
    const sign = ((await stream.takeByte()) & 1) === 0 ? 1 : -1;
    poly[pos] = sign;
    placed += 1;
  }
  return poly;
}

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

  const xofSeed = bytesToHex(seed);
  let carry = 0;
  let carryBits = 0;

  for (let i = 0; i < n; i += 1) {
    while (carryBits < 24) {
      const chunk = randomUint32() ^ (xofSeed.charCodeAt((i + carryBits) % xofSeed.length) ?? 0);
      carry |= (chunk & 0xff) << carryBits;
      carryBits += 8;
    }
    const val = carry & 0xffffff;
    carry >>>= 24;
    carryBits -= 24;
    const span = 2 * gamma1;
    const centered = (val % span) - (gamma1 - 1);
    poly[i] = centered;
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
