// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { serializeChartSvg, toCsv } from './chart-export';

describe('toCsv', () => {
  it('renders plain rows', () => {
    expect(
      toCsv([
        ['iterations', 'count'],
        [1, 260],
        [2, 190],
      ]),
    ).toBe('iterations,count\n1,260\n2,190');
  });

  it('quotes fields containing commas, quotes, and newlines', () => {
    expect(toCsv([['a,b', 'say "hi"', 'line\nbreak']])).toBe('"a,b","say ""hi""","line\nbreak"');
  });
});

describe('serializeChartSvg', () => {
  it('returns null when the container has no svg', () => {
    const div = document.createElement('div');
    expect(serializeChartSvg(div)).toBeNull();
  });

  it('produces a standalone svg document with xmlns and a background rect', () => {
    const div = document.createElement('div');
    div.innerHTML = '<svg viewBox="0 0 100 50"><rect class="hbar" x="1" y="2" width="3" height="4"/></svg>';
    document.body.append(div);
    const out = serializeChartSvg(div);
    expect(out).not.toBeNull();
    expect(out).toContain('xmlns="http://www.w3.org/2000/svg"');
    // Chart classes are stripped (styles inlined) and a solid background added.
    expect(out).not.toContain('class="hbar"');
    expect(out).toContain('<rect x="0" y="0" width="100" height="50"');
    div.remove();
  });
});
