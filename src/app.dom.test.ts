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
    <div id="app"></div>`;
  await import('./main');
});

describe('rendered app', () => {
  it('separates corrected references from the measured histogram and links the preprint', () => {
    const note = document.querySelector('#iteration-reference');
    expect(note?.textContent).toContain('4.36 / 5.14 / 3.91');
    expect(note?.textContent).toContain('potential updates');
    expect(note?.textContent).toContain('mean can differ');
    expect(note?.querySelector('a')?.href).toBe('https://eprint.iacr.org/2026/2456');
  });

  it('cites SampleInBall where FIPS 204 puts it, links the right Lyubashevsky paper, and does not call the signing library audited', () => {
    const reading = document.querySelector('.reading')?.textContent ?? '';

    // FIPS 204 defines SampleInBall as Algorithm 29 inside § 7.3 "Pseudorandom
    // Sampling", alongside ExpandMask (Algorithm 34). The standard has no § 8
    // at all — § 7.6 is the last section before the references.
    expect(reading).toContain('§ 7.3 ExpandMask (Algorithm 34) and SampleInBall (Algorithm 29)');
    expect(reading).not.toContain('8.5.3');

    // eprint.iacr.org/2009/285 is Stehlé et al., "Efficient Public Key Encryption
    // Based on Ideal Lattices" — a different paper. Fiat-Shamir with Aborts is
    // Lyubashevsky, ASIACRYPT 2009, LNCS 5912 pp. 598-616.
    const links = [...document.querySelectorAll<HTMLAnchorElement>('.reading a')].map((a) => a.href);
    expect(links).toContain('https://doi.org/10.1007/978-3-642-10366-7_35');
    expect(links.join(' ')).not.toContain('eprint.iacr.org/2009/285');

    // @noble/post-quantum's own README: "The library has not been independently
    // audited yet." Calling it "the audited library" overstated that.
    expect(reading).toContain('has not been independently audited');
    expect(reading).not.toContain('the audited library');
  });

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

  // Dark is the only theme, pinned by index.html before first paint. The
  // fixture used to ship a #theme-toggle button and this suite used to let it
  // through; the control is gone, so the assertion is inverted — the app
  // renders no theme control and owns no theme state.
  it('ships no theme control and never writes the theme', () => {
    expect(
      document.getElementById('theme-toggle'),
      'a #theme-toggle element reappeared in the app or in this fixture',
    ).toBeNull();
    expect(
      document.querySelectorAll('.theme-toggle, [data-theme-toggle], [aria-label="Toggle color theme"]').length,
      'a theme control reappeared (.theme-toggle, [data-theme-toggle], or aria-label="Toggle color theme")',
    ).toBe(0);
    // The pre-paint pinning stays put: main.ts must neither flip it nor
    // persist a preference of its own.
    expect(document.documentElement.getAttribute('data-theme'), 'main.ts moved the theme off the pinned dark').toBe(
      'dark',
    );
    expect(localStorage.getItem('theme'), 'main.ts wrote localStorage["theme"]').toBeNull();
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
