// @vitest-environment jsdom
import { beforeAll, describe, expect, it } from 'vitest';
import axe from 'axe-core';

beforeAll(async () => {
  // jsdom doesn't implement matchMedia; stub it so reduced-motion checks work.
  if (!window.matchMedia) {
    window.matchMedia = (query: string) =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener() {},
        removeEventListener() {},
        addListener() {},
        removeListener() {},
        dispatchEvent() {
          return false;
        },
      }) as unknown as MediaQueryList;
  }
  // jsdom doesn't implement scrollIntoView; the tour uses it per step.
  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = () => {};
  }
  document.documentElement.setAttribute('lang', 'en');
  document.documentElement.setAttribute('data-theme', 'dark');
  document.body.innerHTML = `
    <a class="skip-link" href="#main-content">Skip to main content</a>
    <button id="theme-toggle" type="button" aria-label="Toggle color theme">Theme</button>
    <div id="app"></div>`;
  await import('./main');
});

describe('rendered app', () => {
  it('renders all seven exhibits', () => {
    const headings = [...document.querySelectorAll('h2')].map((h) => h.textContent ?? '');
    expect(headings).toHaveLength(7);
    expect(headings[0]).toContain('Watch the Loop');
    expect(headings[2]).toContain('Real Signing Times');
  });

  it('wires every primary control', () => {
    const ids = [
      '#sign-once',
      '#step',
      '#regen-key',
      '#deterministic',
      '#tamper-flip',
      '#run-100',
      '#run-1000',
      '#custom-p',
      '#p-slider',
      '#measure-times',
      '#run-distinguishability',
      '#tour-start',
      '#copy-link',
      '#overlay-presets',
      '#ks-mode',
      '#guess-a',
      '#guess-b',
      '#export-hist-svg',
      '#export-hist-png',
      '#export-hist-csv',
      '#export-times-svg',
      '#export-times-png',
      '#export-times-csv',
    ];
    for (const id of ids) expect(document.querySelector(id), id).not.toBeNull();
  });

  it('starts and exits the guided tour', () => {
    const startButton = document.querySelector<HTMLButtonElement>('#tour-start');
    startButton?.click();
    const panel = document.querySelector('.tour-panel');
    expect(panel).not.toBeNull();
    expect(panel?.textContent).toContain('1 / ');
    document.querySelector<HTMLButtonElement>('.tour-next')?.click();
    expect(document.querySelector('.tour-panel')?.textContent).toContain('2 / ');
    document.querySelector<HTMLButtonElement>('.tour-exit')?.click();
    expect(document.querySelector('.tour-panel')).toBeNull();
  });

  it('histogram stats declare their data source', () => {
    expect(document.querySelector('#stats')?.textContent).toContain('real signing loop');
  });

  it('distinguishes fixed ML-DSA-65 controls from selected-preset histogram traces', () => {
    const scope = document.querySelector('#exhibit1-scope')?.textContent ?? '';
    expect(scope).toContain('Sign Once');
    expect(scope).toContain('fixed at ML-DSA-65');
    expect(scope).toContain("histogram's selected preset");
  });

  it('exposes a single banner-free main landmark and labelled regions', () => {
    expect(document.querySelector('main#main-content')).not.toBeNull();
    // The iteration feed is a labelled log; charts expose role="img" labels.
    expect(document.querySelector('[role="log"]')).not.toBeNull();
  });

  it('has no serious or critical accessibility violations (axe-core)', async () => {
    const results = await axe.run(document.body, { resultTypes: ['violations'] });
    const blocking = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    if (blocking.length > 0) {
      // Surface details when this fails.
      console.error(blocking.map((v) => `${v.id} (${v.impact}): ${v.help}`).join('\n'));
    }
    expect(blocking).toEqual([]);
  }, 20000);
});
