/**
 * Shareable-state URL codec. A link encodes everything needed to reproduce a
 * demo configuration — and, in seeded mode, the exact real trace: the seed
 * derives both the ML-DSA keypair seed and the signing entropy, so the same
 * link replays the same real signature on any machine.
 */

export interface ShareableState {
  preset: string;
  deterministic: boolean;
  seed: number;
  message: string;
  customAcceptance: number | null;
  tour: boolean;
}

const PRESET_NAMES = new Set(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']);
const MAX_MESSAGE_LENGTH = 200;

export function parseUrlState(search: string): Partial<ShareableState> {
  const params = new URLSearchParams(search);
  const out: Partial<ShareableState> = {};

  const preset = params.get('preset');
  if (preset && PRESET_NAMES.has(preset)) out.preset = preset;

  if (params.get('det') === '1') out.deterministic = true;

  const seed = Number.parseInt(params.get('seed') ?? '', 10);
  if (Number.isFinite(seed) && seed >= 0) {
    out.seed = seed;
    // A seed only makes sense reproducibly; sharing one implies det mode.
    out.deterministic = true;
  }

  const msg = params.get('msg');
  if (msg !== null && msg.length > 0) out.message = msg.slice(0, MAX_MESSAGE_LENGTH);

  const p = Number.parseFloat(params.get('p') ?? '');
  if (Number.isFinite(p) && p >= 0.05 && p <= 0.6) out.customAcceptance = p;

  if (params.get('tour') === '1') out.tour = true;

  return out;
}

export function buildShareUrl(base: string, state: ShareableState): string {
  const params = new URLSearchParams();
  params.set('preset', state.preset);
  if (state.deterministic) {
    params.set('det', '1');
    params.set('seed', String(state.seed));
  }
  if (state.message.length > 0 && state.message.length <= MAX_MESSAGE_LENGTH) params.set('msg', state.message);
  if (state.customAcceptance !== null) params.set('p', state.customAcceptance.toFixed(2));
  if (state.tour) params.set('tour', '1');
  return `${base}?${params.toString()}`;
}
