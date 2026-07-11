/**
 * REAL instrumented ML-DSA signing — not a simulation.
 *
 * This is the FIPS 204 signing loop, vendored from `@noble/post-quantum`'s
 * `ml-dsa.ts` (MIT, (c) 2024 Paul Miller, paulmillr.com) with one change: the
 * rejection loop reports every iteration through an `onIteration` callback —
 * the real κ counter, the real ‖z‖∞ / ‖r₀‖∞ / ‖c·t₀‖∞ norms computed from the
 * actual y + c·s₁ arithmetic, the real hint weight, and the real first-failing
 * check per FIPS 204 § 6.2 order.
 *
 * Everything that decides acceptance (XOF streams, NTT arithmetic, coders,
 * check thresholds and their order) is unchanged, so for the same secret key
 * and the same 32-byte `extraEntropy` this produces a **byte-identical
 * signature** to noble's `ml_dsa*.sign`. `real-sign.test.ts` asserts exactly
 * that, for all three parameter sets — the correctness gate for this file.
 *
 * Two instrumentation modes:
 * - `detail: true` — evaluate all four norm checks every iteration so each
 *   card in the UI can show real values for every check (the real algorithm
 *   short-circuits at the first failure; the extra values are what it *would*
 *   have computed, from the same real polynomials). Slightly slower.
 * - `detail: false` — short-circuit exactly like the production loop; records
 *   carry only the rejection reason. Used for batch statistics.
 */
import { shake256 } from '@noble/hashes/sha3.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { genCrystals, XOF128, XOF256 } from '@noble/post-quantum/_crystals.js';
import { getMessage, randomBytes as nobleRandomBytes, splitCoder, vecCoder } from '@noble/post-quantum/utils.js';

export type MlDsaPresetName = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export type RejectionReason = 'z_too_large' | 'r0_too_large' | 'ct0_too_large' | 'hint_too_dense';

export interface RealCheck {
  /** Real infinity norm (or hint weight) computed from the live polynomials. */
  value: number;
  /** The FIPS 204 bound this value is compared against. */
  threshold: number;
  pass: boolean;
}

export interface RealIterationRecord {
  /** κ at the start of this iteration (increments by ℓ per attempt). */
  kappa: number;
  /** ‖y‖∞ of the freshly expanded mask vector. */
  yInf: number;
  /** First 8 hex chars of the real commitment hash c̃. */
  cTildeHex: string;
  /** ‖z‖∞ < γ₁ − β. Null only in light mode when unevaluated. */
  z: RealCheck | null;
  /** ‖r₀‖∞ < γ₂ − β. */
  r0: RealCheck | null;
  /** ‖c·t₀‖∞ < γ₂. */
  ct0: RealCheck | null;
  /** wt(h) ≤ ω. */
  hint: RealCheck | null;
  result: 'ACCEPTED' | 'REJECTED';
  /** First failing check in the algorithm's own evaluation order. */
  rejectionReason: RejectionReason | null;
  /** Real wall-clock duration of this iteration (performance.now). */
  timeMs: number;
}

export interface RealSignOptions {
  /**
   * 32 bytes of signing randomness (FIPS 204 `rnd`). `false` selects the
   * deterministic variant (rnd = 32 zero bytes); omitting it uses the CSPRNG.
   * The demo's "reproducible" mode passes seeded bytes here: same seed + same
   * key ⇒ the same real trace and the same real signature bytes.
   */
  extraEntropy?: Uint8Array | false;
  /** Evaluate all four checks per iteration (for the iteration feed). */
  detail?: boolean;
  onIteration?: (record: RealIterationRecord) => void;
  /**
   * Safety bound on loop attempts. FIPS 204 permits implementations to bound
   * the loop and return failure; at the real acceptance rates (~0.19–0.26) the
   * default is unreachable in practice (P ≈ (1-p)^768).
   */
  maxIterations?: number;
}

export interface RealSigningResult {
  signature: Uint8Array;
  iterations: RealIterationRecord[];
  acceptedIteration: number;
  totalTimeMs: number;
}

// --- constants shared by every ML-DSA parameter set (FIPS 204 Table 1) ---
const N = 256;
const Q = 8380417;
const ROOT_OF_UNITY = 1753;
const F = 8347681; // 256^-1 mod q
const D = 13;
const GAMMA2_1 = Math.floor((Q - 1) / 88) | 0;
const GAMMA2_2 = Math.floor((Q - 1) / 32) | 0;
const TR_BYTES = 64;
const CRH_BYTES = 64;

type Poly = Int32Array;

interface PolyBytesCoder {
  bytesLen: number;
  encode(p: Poly): Uint8Array;
  decode(b: Uint8Array): Poly;
}

interface CrystalsShape {
  mod(a: number, modulo?: number): number;
  smod(a: number, modulo?: number): number;
  NTT: { encode(r: Poly): Poly; decode(r: Poly): Poly };
  bitsCoder(d: number, c: { encode(i: number): number; decode(i: number): number }): PolyBytesCoder;
}

const crystals = genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly: (n: number) => new Int32Array(n),
  isKyber: false,
  brvBits: 8,
}) as unknown as CrystalsShape;

const newPoly = (n: number): Poly => new Int32Array(n);
const id = (n: number): number => n;

const polyCoder = (d: number, compress: (n: number) => number = id): PolyBytesCoder =>
  crystals.bitsCoder(d, { encode: compress, decode: compress });

const polyAdd = (a: Poly, b: Poly): Poly => {
  for (let i = 0; i < a.length; i++) a[i] = crystals.mod((a[i] ?? 0) + (b[i] ?? 0));
  return a;
};
const polySub = (a: Poly, b: Poly): Poly => {
  for (let i = 0; i < a.length; i++) a[i] = crystals.mod((a[i] ?? 0) - (b[i] ?? 0));
  return a;
};

/** Real centered infinity norm: max |coefficient mod± q|. */
const polyInfNorm = (p: Poly): number => {
  let best = 0;
  for (let i = 0; i < p.length; i++) {
    const abs = Math.abs(crystals.smod(p[i] ?? 0));
    if (abs > best) best = abs;
  }
  return best;
};

/** noble's polyChknorm: early-exit bound check, used on the fast (light) path. */
const polyChkNorm = (p: Poly, B: number): boolean => {
  for (let i = 0; i < p.length; i++) if (Math.abs(crystals.smod(p[i] ?? 0)) >= B) return true;
  return false;
};

const MultiplyNTTs = (a: Poly, b: Poly): Poly => {
  const c = newPoly(N);
  for (let i = 0; i < a.length; i++) c[i] = crystals.mod((a[i] ?? 0) * (b[i] ?? 0));
  return c;
};

/** Sample a polynomial in NTT form via rejection from an XOF block stream. */
function RejNTTPoly(xof: () => Uint8Array): Poly {
  const r = newPoly(N);
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3) throw new Error('RejNTTPoly: unaligned block');
    for (let i = 0; j < N && i <= b.length - 3; i += 3) {
      const t = ((b[i + 0] ?? 0) | ((b[i + 1] ?? 0) << 8) | ((b[i + 2] ?? 0) << 16)) & 0x7fffff;
      if (t < Q) r[j++] = t;
    }
  }
  return r;
}

interface InstrumentedParams {
  K: number;
  L: number;
  GAMMA1: number;
  GAMMA2: number;
  TAU: number;
  ETA: number;
  OMEGA: number;
  C_TILDE_BYTES: number;
}

interface SecretCoderShape {
  decode(sk: Uint8Array): [Uint8Array, Uint8Array, Uint8Array, Poly[], Poly[], Poly[]];
}
interface SigCoderShape {
  encode(parts: [Uint8Array, Poly[], Poly[]]): Uint8Array;
}
interface W1VecShape {
  encode(w1: Poly[]): Uint8Array;
}

type InstrumentedSignFn = (msg: Uint8Array, secretKey: Uint8Array, opts?: RealSignOptions) => RealSigningResult;

function createInstrumentedSigner(params: InstrumentedParams): InstrumentedSignFn {
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA, C_TILDE_BYTES } = params;
  const BETA = TAU * ETA;

  const decompose = (r: number): { r1: number; r0: number } => {
    const rPlus = crystals.mod(r);
    const r0 = crystals.smod(rPlus, 2 * GAMMA2) | 0;
    if (rPlus - r0 === Q - 1) return { r1: 0, r0: r0 - 1 };
    const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
    return { r1, r0 };
  };
  const HighBits = (r: number): number => decompose(r).r1;
  const LowBits = (r: number): number => decompose(r).r0;
  // Optimized round-3 Dilithium predicate over the transformed (r0+ct0, w1)
  // inputs used at this call site — see noble's ml-dsa.ts for the discussion.
  const MakeHint = (z: number, r: number): number =>
    z <= GAMMA2 || z > Q - GAMMA2 || (z === Q - GAMMA2 && r === 0) ? 0 : 1;

  const hintCoder = {
    bytesLen: OMEGA + K,
    encode: (h: Poly[]): Uint8Array => {
      const res = new Uint8Array(OMEGA + K);
      for (let i = 0, k = 0; i < K; i++) {
        const hi = h[i] ?? newPoly(N);
        for (let j = 0; j < N; j++) if ((hi[j] ?? 0) !== 0) res[k++] = j;
        res[OMEGA + i] = k;
      }
      return res;
    },
    decode: (buf: Uint8Array): Poly[] | false => {
      const h: Poly[] = [];
      let k = 0;
      for (let i = 0; i < K; i++) {
        const hi = newPoly(N);
        const bound = buf[OMEGA + i] ?? 0;
        if (bound < k || bound > OMEGA) return false;
        for (let j = k; j < bound; j++) {
          if (j > k && (buf[j] ?? 0) <= (buf[j - 1] ?? 0)) return false;
          hi[buf[j] ?? 0] = 1;
        }
        k = bound;
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++) if ((buf[j] ?? 0) !== 0) return false;
      return h;
    },
  };

  const ETACoder = polyCoder(ETA === 2 ? 3 : 4, (i) => ETA - i);
  const T0Coder = polyCoder(13, (i) => (1 << (D - 1)) - i);
  const ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i) => crystals.smod(GAMMA1 - i));
  const W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K) as unknown as W1VecShape;
  const secretCoder = splitCoder(
    'secretKey',
    32,
    32,
    TR_BYTES,
    vecCoder(ETACoder, L),
    vecCoder(ETACoder, K),
    vecCoder(T0Coder, K),
  ) as unknown as SecretCoderShape;
  const sigCoder = splitCoder('signature', C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder) as unknown as SigCoderShape;

  const SampleInBall = (seed: Uint8Array): Poly => {
    const pre = newPoly(N);
    const s = shake256.create({}).update(seed);
    const buf = new Uint8Array(shake256.blockLen);
    s.xofInto(buf);
    const masks = buf.slice(0, 8);
    for (let i = N - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N; i++) {
      let b = i + 1;
      for (; b > i; ) {
        b = buf[pos++] ?? 0;
        if (pos < shake256.blockLen) continue;
        s.xofInto(buf);
        pos = 0;
      }
      pre[i] = pre[b] ?? 0;
      pre[b] = 1 - ((((masks[maskPos] ?? 0) >> maskBit++) & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };

  const polyMakeHint = (a: Poly, b: Poly): { v: Poly; cnt: number } => {
    const v = newPoly(N);
    let cnt = 0;
    for (let i = 0; i < N; i++) {
      const h = MakeHint(a[i] ?? 0, b[i] ?? 0);
      v[i] = h;
      cnt += h;
    }
    return { v, cnt };
  };

  const bytesToHex = (bytes: Uint8Array, len: number): string => {
    let out = '';
    for (let i = 0; i < len && i < bytes.length; i++) out += (bytes[i] ?? 0).toString(16).padStart(2, '0');
    return out;
  };

  return (msg: Uint8Array, secretKey: Uint8Array, opts: RealSignOptions = {}): RealSigningResult => {
    const detail = opts.detail ?? false;
    const maxIterations = opts.maxIterations ?? 768;
    // Match noble's public sign(): wrap the message with the FIPS 204 pure-mode
    // domain separator (empty context) before the internal signing flow.
    const M = getMessage(msg) as Uint8Array;

    const [, K_, tr, s1, s2, t0] = secretCoder.decode(secretKey);
    const rho = secretKey.subarray(0, 32);

    // A ← ExpandA(ρ), cached across iterations exactly like noble.
    const A: Poly[][] = [];
    const xof = XOF128(rho);
    for (let i = 0; i < K; i++) {
      const pv: Poly[] = [];
      for (let j = 0; j < L; j++) pv.push(RejNTTPoly(xof.get(j, i)));
      A.push(pv);
    }
    xof.clean();
    for (let i = 0; i < L; i++) crystals.NTT.encode(s1[i] ?? newPoly(N));
    for (let i = 0; i < K; i++) {
      crystals.NTT.encode(s2[i] ?? newPoly(N));
      crystals.NTT.encode(t0[i] ?? newPoly(N));
    }

    const mu = shake256.create({ dkLen: CRH_BYTES }).update(tr).update(M).digest();
    const rnd =
      opts.extraEntropy === false
        ? new Uint8Array(32)
        : opts.extraEntropy === undefined
          ? (nobleRandomBytes(32) as Uint8Array)
          : opts.extraEntropy;
    if (rnd.length !== 32) throw new Error('extraEntropy must be 32 bytes');
    const rhoprime = shake256.create({ dkLen: CRH_BYTES }).update(K_).update(rnd).update(mu).digest();

    const x256 = XOF256(rhoprime, ZCoder.bytesLen);
    const iterations: RealIterationRecord[] = [];
    const started = performance.now();

    const zThreshold = GAMMA1 - BETA;
    const r0Threshold = GAMMA2 - BETA;
    const ct0Threshold = GAMMA2;

    main_loop: for (let kappa = 0; ; ) {
      if (iterations.length >= maxIterations) {
        x256.clean();
        throw new Error(`rejection loop exceeded ${maxIterations} iterations`);
      }
      const iterStart = performance.now();
      const kappaStart = kappa;

      const y: Poly[] = [];
      for (let i = 0; i < L; i++, kappa++) y.push(ZCoder.decode(x256.get(kappa & 0xff, kappa >> 8)()));
      const yInf = detail ? Math.max(...y.map(polyInfNorm)) : 0;

      const zNtt = y.map((p) => crystals.NTT.encode(p.slice()));
      const w: Poly[] = [];
      for (let i = 0; i < K; i++) {
        const wi = newPoly(N);
        for (let j = 0; j < L; j++) polyAdd(wi, MultiplyNTTs((A[i] ?? [])[j] ?? newPoly(N), zNtt[j] ?? newPoly(N)));
        crystals.NTT.decode(wi);
        w.push(wi);
      }
      const w1 = w.map((p) => p.map(HighBits));
      const cTilde = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(w1)).digest();
      const cTildeHex = bytesToHex(cTilde, 4);
      const cHat = crystals.NTT.encode(SampleInBall(cTilde));

      const emit = (record: RealIterationRecord): void => {
        iterations.push(record);
        opts.onIteration?.(record);
      };
      const rejected = (
        reason: RejectionReason,
        checks: Pick<RealIterationRecord, 'z' | 'r0' | 'ct0' | 'hint'>,
      ): void => {
        emit({
          kappa: kappaStart,
          yInf,
          cTildeHex,
          ...checks,
          result: 'REJECTED',
          rejectionReason: reason,
          timeMs: performance.now() - iterStart,
        });
      };

      // z ← y + ⟨⟨c·s1⟩⟩, per FIPS 204 Algorithm 7 lines 20–21.
      const cs1 = s1.map((p) => MultiplyNTTs(p, cHat));

      let checks: Pick<RealIterationRecord, 'z' | 'r0' | 'ct0' | 'hint'>;
      let reason: RejectionReason | null;
      const h: Poly[] = [];

      if (!detail) {
        // Fast path: noble's exact short-circuit structure and cost. Records
        // carry only the rejection reason — batch statistics need no norms.
        checks = { z: null, r0: null, ct0: null, hint: null };
        reason = null;
        for (let i = 0; i < L && reason === null; i++) {
          polyAdd(crystals.NTT.decode(cs1[i] ?? newPoly(N)), y[i] ?? newPoly(N));
          if (polyChkNorm(cs1[i] ?? newPoly(N), zThreshold)) reason = 'z_too_large';
        }
        let hintCnt = 0;
        for (let i = 0; i < K && reason === null; i++) {
          const cs2 = crystals.NTT.decode(MultiplyNTTs(s2[i] ?? newPoly(N), cHat));
          const r0 = polySub(w[i] ?? newPoly(N), cs2).map(LowBits);
          if (polyChkNorm(r0, r0Threshold)) {
            reason = 'r0_too_large';
            break;
          }
          const ct0 = crystals.NTT.decode(MultiplyNTTs(t0[i] ?? newPoly(N), cHat));
          if (polyChkNorm(ct0, ct0Threshold)) {
            reason = 'ct0_too_large';
            break;
          }
          polyAdd(r0, ct0);
          const hint = polyMakeHint(r0, w1[i] ?? newPoly(N));
          h.push(hint.v);
          hintCnt += hint.cnt;
        }
        if (reason === null && hintCnt > OMEGA) reason = 'hint_too_dense';
      } else {
        // Detail path: evaluate every check on the real polynomials so each
        // iteration card can show all four values (the production loop stops
        // at the first failure; acceptance semantics are identical).
        let zInf = 0;
        for (let i = 0; i < L; i++) {
          polyAdd(crystals.NTT.decode(cs1[i] ?? newPoly(N)), y[i] ?? newPoly(N));
          const norm = polyInfNorm(cs1[i] ?? newPoly(N));
          if (norm > zInf) zInf = norm;
        }
        // `firstKReason` preserves the algorithm's interleaved (r0_i, ct0_i)
        // evaluation order so the reported reason matches what the real
        // short-circuiting loop would have hit first.
        let r0Inf = 0;
        let ct0Inf = 0;
        let hintCnt = 0;
        let firstKReason: RejectionReason | null = null;
        for (let i = 0; i < K; i++) {
          const cs2 = crystals.NTT.decode(MultiplyNTTs(s2[i] ?? newPoly(N), cHat));
          const r0 = polySub(w[i] ?? newPoly(N), cs2).map(LowBits);
          const r0Norm = polyInfNorm(r0);
          if (r0Norm > r0Inf) r0Inf = r0Norm;
          if (r0Norm >= r0Threshold && firstKReason === null) firstKReason = 'r0_too_large';
          const ct0 = crystals.NTT.decode(MultiplyNTTs(t0[i] ?? newPoly(N), cHat));
          const ct0Norm = polyInfNorm(ct0);
          if (ct0Norm > ct0Inf) ct0Inf = ct0Norm;
          if (ct0Norm >= ct0Threshold && firstKReason === null) firstKReason = 'ct0_too_large';
          polyAdd(r0, ct0);
          const hint = polyMakeHint(r0, w1[i] ?? newPoly(N));
          h.push(hint.v);
          hintCnt += hint.cnt;
        }
        checks = {
          z: { value: zInf, threshold: zThreshold, pass: zInf < zThreshold },
          r0: { value: r0Inf, threshold: r0Threshold, pass: r0Inf < r0Threshold },
          ct0: { value: ct0Inf, threshold: ct0Threshold, pass: ct0Inf < ct0Threshold },
          hint: { value: hintCnt, threshold: OMEGA, pass: hintCnt <= OMEGA },
        };
        reason = zInf >= zThreshold ? 'z_too_large' : (firstKReason ?? (hintCnt > OMEGA ? 'hint_too_dense' : null));
      }

      if (reason !== null) {
        rejected(reason, checks);
        continue main_loop;
      }

      x256.clean();
      const signature = sigCoder.encode([cTilde, cs1, h]);
      emit({
        kappa: kappaStart,
        yInf,
        cTildeHex,
        ...checks,
        result: 'ACCEPTED',
        rejectionReason: null,
        timeMs: performance.now() - iterStart,
      });
      return {
        signature,
        iterations,
        acceptedIteration: iterations.length,
        totalTimeMs: performance.now() - started,
      };
    }
    throw new Error('unreachable');
  };
}

/** FIPS 204 Table 1 parameters exposed for the UI (thresholds, symbols table). */
export interface RealPresetParams {
  k: number;
  l: number;
  gamma1: number;
  gamma2: number;
  tau: number;
  eta: number;
  beta: number;
  omega: number;
}

interface NobleSigner {
  keygen: (seed?: Uint8Array) => { secretKey: Uint8Array; publicKey: Uint8Array };
  sign: (msg: Uint8Array, secretKey: Uint8Array, opts?: { extraEntropy?: Uint8Array | false }) => Uint8Array;
  verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean;
}

interface RealPreset {
  params: RealPresetParams;
  /** Untouched noble signer — keygen/sign/verify for cross-validation. */
  noble: NobleSigner;
  /** The instrumented (but bit-identical) signing loop. */
  sign: InstrumentedSignFn;
}

const P44: InstrumentedParams = {
  K: 4,
  L: 4,
  GAMMA1: 1 << 17,
  GAMMA2: GAMMA2_1,
  TAU: 39,
  ETA: 2,
  OMEGA: 80,
  C_TILDE_BYTES: 32,
};
const P65: InstrumentedParams = {
  K: 6,
  L: 5,
  GAMMA1: 1 << 19,
  GAMMA2: GAMMA2_2,
  TAU: 49,
  ETA: 4,
  OMEGA: 55,
  C_TILDE_BYTES: 48,
};
const P87: InstrumentedParams = {
  K: 8,
  L: 7,
  GAMMA1: 1 << 19,
  GAMMA2: GAMMA2_2,
  TAU: 60,
  ETA: 2,
  OMEGA: 75,
  C_TILDE_BYTES: 64,
};

const toParams = (p: InstrumentedParams): RealPresetParams => ({
  k: p.K,
  l: p.L,
  gamma1: p.GAMMA1,
  gamma2: p.GAMMA2,
  tau: p.TAU,
  eta: p.ETA,
  beta: p.TAU * p.ETA,
  omega: p.OMEGA,
});

export const REAL_PRESETS: Record<MlDsaPresetName, RealPreset> = {
  'ML-DSA-44': {
    params: toParams(P44),
    noble: ml_dsa44 as unknown as NobleSigner,
    sign: createInstrumentedSigner(P44),
  },
  'ML-DSA-65': {
    params: toParams(P65),
    noble: ml_dsa65 as unknown as NobleSigner,
    sign: createInstrumentedSigner(P65),
  },
  'ML-DSA-87': {
    params: toParams(P87),
    noble: ml_dsa87 as unknown as NobleSigner,
    sign: createInstrumentedSigner(P87),
  },
};

/** Real instrumented sign for a preset. See module docs for guarantees. */
export function realInstrumentedSign(
  preset: MlDsaPresetName,
  msg: Uint8Array,
  secretKey: Uint8Array,
  opts: RealSignOptions = {},
): RealSigningResult {
  return REAL_PRESETS[preset].sign(msg, secretKey, opts);
}
