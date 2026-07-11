import { describe, expect, it } from 'vitest';
import { buildShareUrl, parseUrlState, type ShareableState } from './url-state';

describe('parseUrlState', () => {
  it('parses a full parameter set', () => {
    const s = parseUrlState('?preset=ML-DSA-87&det=1&seed=1234&msg=hello%20world&p=0.35');
    expect(s.preset).toBe('ML-DSA-87');
    expect(s.deterministic).toBe(true);
    expect(s.seed).toBe(1234);
    expect(s.message).toBe('hello world');
    expect(s.customAcceptance).toBeCloseTo(0.35);
  });

  it('a seed alone implies deterministic mode', () => {
    const s = parseUrlState('?seed=7');
    expect(s.seed).toBe(7);
    expect(s.deterministic).toBe(true);
  });

  it('rejects unknown presets, out-of-range p, and negative seeds', () => {
    const s = parseUrlState('?preset=ML-DSA-9000&p=0.99&seed=-3');
    expect(s.preset).toBeUndefined();
    expect(s.customAcceptance).toBeUndefined();
    expect(s.seed).toBeUndefined();
    expect(s.deterministic).toBeUndefined();
  });

  it('caps overlong messages', () => {
    const s = parseUrlState(`?msg=${'a'.repeat(500)}`);
    expect(s.message).toHaveLength(200);
  });

  it('returns an empty object for an empty query', () => {
    expect(parseUrlState('')).toEqual({});
  });
});

describe('buildShareUrl / parseUrlState round-trip', () => {
  it('reproduces a seeded configuration exactly', () => {
    const original: ShareableState = {
      preset: 'ML-DSA-65',
      deterministic: true,
      seed: 42,
      message: 'Transfer $1000 to Bob',
      customAcceptance: null,
      tour: false,
    };
    const url = buildShareUrl('https://example.test/demo/', original);
    const parsed = parseUrlState(new URL(url).search);
    expect(parsed.preset).toBe(original.preset);
    expect(parsed.deterministic).toBe(true);
    expect(parsed.seed).toBe(original.seed);
    expect(parsed.message).toBe(original.message);
    expect(parsed.customAcceptance).toBeUndefined();
  });

  it('omits seed/det for non-deterministic state and carries exploratory p', () => {
    const url = buildShareUrl('https://example.test/', {
      preset: 'ML-DSA-44',
      deterministic: false,
      seed: 42,
      message: 'm',
      customAcceptance: 0.4,
      tour: true,
    });
    const parsed = parseUrlState(new URL(url).search);
    expect(parsed.deterministic).toBeUndefined();
    expect(parsed.seed).toBeUndefined();
    expect(parsed.customAcceptance).toBeCloseTo(0.4);
    expect(parsed.tour).toBe(true);
  });
});
