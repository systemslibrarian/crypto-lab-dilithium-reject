import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Four rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaces
 *     pushed `animation: none !important; transition: none !important` through
 *     `addStyleTag` before every scan, so that `.card`'s `rise-in` and the
 *     histogram bars' `barGrow` could not be caught mid-flight. It was right
 *     about the problem and wrong about the remedy: overriding from the test
 *     BYPASSES this lab's own `@media (prefers-reduced-motion: reduce)` block
 *     instead of exercising it, so it could not catch the defect where an
 *     element's only route to its painted state is an animation that the
 *     reduced-motion block cancels without restoring the end state. That defect
 *     is live in this stylesheet's shape: `rise-in` runs `opacity: 0 -> 1` with
 *     `both`, and `barGrow` runs `scaleY(0) -> scaleY(1)` with `both`, so a
 *     reduced-motion block that set `animation: none` on the wrong element
 *     would leave a card at zero opacity or a bar at zero height forever.
 *     `boot` asks for the preference, asserts it took effect, `settle` waits
 *     for the animations to drain and `expectNotBlank` asserts nothing landed
 *     invisible — the same guarantee, obtained honestly.
 *
 *  2. IT DROVE ALMOST NOTHING. Two scans per theme: one of the page as it
 *     loads, one after the guided tour opened. Everything this lab exists to
 *     show is behind a button — no iteration cards, no ACCEPTED or REJECTED
 *     pill, no failing `.check` row, no histogram bars, no rejection-reason
 *     breakdown, no measured signing times, no CDF overlay, no KS verdict, no
 *     leak-game guess, no tamper result. None of it had ever been measured.
 *
 *  3. IT REVEALED WHAT IT COULD NOT REACH. `revealHidden()` stripped the
 *     `hidden` attribute from every element and forced `display` back on, which
 *     assembles a document no visitor can load: the tamper panel with no
 *     signature behind it, the seed field with reproducible mode off, the
 *     leak-game guess buttons with no game running. States that only exist
 *     together were scanned side by side, and the states a visitor actually
 *     lands in — the locked ones, before the unlock — were never scanned at
 *     all. Every panel here is now reached by working the control that reveals
 *     it, and the pre-reveal state is scanned first.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' },
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab is
 * exactly the shape that fails that way: `.card` and `.tour-panel` both animate
 * `rise-in`, which starts at `opacity: 0`, and the reduced-motion block cancels
 * it with `animation: none !important` rather than collapsing its duration. The
 * cancellation is safe here only because `rise-in` uses `both` fill on a
 * keyframe set whose END state is the element's own resting style, so removing
 * the animation leaves the resting style behind — but "it happens to be safe"
 * is a measurement, not an assumption, and this is the assertion that makes it
 * one. It is checked in every state, because `.tour-panel` is created at runtime
 * and its animation only ever runs long after first paint.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: an emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to.
 *
 * The default assertions are not decoration. This page restores preset, seeded
 * mode, message and exploratory `p` FROM THE QUERY STRING (`parseUrlState`), so
 * a stray parameter — or a future change to the defaults in `state` — would
 * silently move the gate onto a different half of the lab: the exploratory
 * simulation instead of the real signing loop, or the broken KS scenario
 * instead of the faithful one. Asserting the shipped defaults is what makes
 * "the gate drove the real loop" a fact rather than a hope.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is built by `src/main.ts` into an empty `#app`, so a
  // navigation that resolves proves nothing.
  await expect(page.locator('main.lab')).toBeVisible();
  await expect(page.getByRole('heading', { level: 1, name: 'ML-DSA Rejection Sampling' })).toBeVisible();
  // Three renderers run at module scope after the markup lands. Wait for the
  // work of each rather than for a timeout.
  await expect(page.locator('#histogram .hist-svg')).toBeVisible();
  await expect(page.locator('#realtime-hist .hist-empty')).toBeVisible();
  await expect(page.locator('.check-box')).toHaveCount(4);

  // ── The shipped defaults ─────────────────────────────────────────────────
  // Exhibit 2 is showing the theoretical curve alone, with nothing measured.
  await expect(page.locator('#histogram .hist-empty')).toHaveText(/No data yet/);
  await expect(page.locator('#histogram .bar-g')).not.toHaveCount(0);
  await expect(page.locator('#reason-breakdown')).toBeEmpty();
  // The real signing loop, not the exploratory simulation; ML-DSA-65, not 44/87.
  await expect(page.locator('#preset-select')).toHaveValue('ML-DSA-65');
  await expect(page.locator('#custom-p')).not.toBeChecked();
  await expect(page.locator('#p-slider')).toBeDisabled();
  await expect(page.locator('#overlay-presets')).not.toBeChecked();
  // The faithful KS scenario, not the broken positive control.
  await expect(page.locator('#ks-mode')).toHaveValue('real');
  await expect(page.locator('#leak-game')).toBeHidden();
  // Randomised signing, not the seeded replay; and the three panels that are
  // locked until something unlocks them.
  await expect(page.locator('#deterministic')).not.toBeChecked();
  await expect(page.locator('.seed-field')).toBeHidden();
  await expect(page.locator('.det-note')).toBeHidden();
  await expect(page.locator('#seed')).toBeDisabled();
  await expect(page.locator('#tamper-panel')).toBeHidden();
  await expect(page.locator('#iteration-feed .iteration')).toHaveCount(0);
  await expect(page.locator('.tour-panel')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender at 380px: `.lab` is a single-column `display: grid` with
 * no `grid-template-columns`, which is an implicit `auto` track taking its
 * items' MIN-CONTENT as a floor, and the cards it holds contain a five-column
 * scheme-comparison table, a nine-row symbol glossary, a 760-unit-wide SVG for
 * each of the three charts, and monospace readouts of κ, a c̃ fingerprint and a
 * six-figure norm on one line.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has two such decoys: the
    // `.table-wrap`s around Exhibit 5 and the glossary both scroll sideways
    // inside their own container.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This is the oracle that only bites after a drive. `#iteration-feed` is a
 * `role="log"` capped at `max-height: 520px`, and it holds nothing focusable —
 * it starts empty and only overflows once a signature has needed enough
 * rejections to fill it, which is why a gate that never pressed "Sign Once"
 * could not see it. The two `.table-wrap`s are the same shape at 380px.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      );
  });
  expect(Array.from(new Set(unreachable)), `scrolling regions with no keyboard route in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set prints every finding as it happens
 * and then fails at the end, so a green collection run cannot be mistaken for a
 * green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * The 1.4.11 oracle, soft-wrapped like every other check in `scan`.
 *
 * This used to be called from inside `expectScrollersReachableSoft`, AFTER that
 * function's `if (!COLLECTING) return` early exit — so in a normal (strict) run
 * it never executed at all, and `nontext.ts` was dead code. Every "no new
 * non-text failures" claim made by a strict run of this gate was therefore
 * vacuous, and the baseline captured under it was empty because nothing had
 * ever looked. It is now called from `scan` itself, at every driven state.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label);
  try {
    await expectNoNewNonTextFailures(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    every tinted surface on the page is a `color-mix()` over a translucent
 *    panel over a gradient, and axe declines to resolve all three layers.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish — including `aria-prohibited-attr`, which is where an `aria-label`
 *    on a role-less element hides, a defect that never reaches the violations
 *    array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    including the SVG `<text>` labels on all three charts.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)',
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectNoNewNonTextFailuresSoft(page, label);
  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

/** The `#sign-summary` status line, which every Exhibit 1/2 action rewrites. */
const summaryReads = (page: Page, re: RegExp): Promise<void> =>
  expect(page.locator('#sign-summary')).toHaveText(re, { timeout: 120_000 });

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE REJECTED STATE IS THE LESSON. "Fiat-Shamir with Aborts" is a loop that
 *    throws candidates away, and `.iteration.rejected`, `.status-rejected`,
 *    `.check.fail` and the four `reason-*` rings exist nowhere else on the
 *    page. Acceptance is ~0.2 per candidate so a rejection is near-certain, but
 *    "near-certain" is not an oracle: the drive signs until a rejected card is
 *    on screen and asserts it, so the accepting and rejecting tones are always
 *    measured against each other.
 *
 *  - THE LOCKED STATES ARE SCANNED BEFORE THE UNLOCK. The tamper panel does not
 *    exist until a signature does, the seed field does not exist until
 *    reproducible mode is on, and the leak-game guess buttons do not exist
 *    until the broken scenario has produced two populations. `boot` asserts all
 *    three are shut, and each is reached by working its own control rather than
 *    by deleting the `hidden` attribute.
 *
 *  - BOTH SIDES OF EVERY FORK. Real signing loop and exploratory simulation;
 *    faithful KS scenario and broken positive control; a correct and an
 *    incorrect leak-game guess; a correct and an incorrect tour-quiz answer; a
 *    histogram bar that finds a real trace of that length and one deep enough
 *    in the geometric tail that the search gives up and falls back to an
 *    illustrative simulated trace; a verifying signature and a tampered one.
 *
 *  - EVERY RESET. `Regenerate Key`, `Reset` (histogram), unchecking custom-p,
 *    and exiting the tour each return a populated exhibit to an empty state,
 *    and an empty state has its own copy (`.hist-empty`) and its own layout.
 *
 *  - NO FIXED TIMEOUTS. Everything heavy runs in a worker and reports through
 *    `#sign-summary`, `#measure-progress` or `#distinguishability-output`; the
 *    drive waits on those strings, which are the page's own completion signals.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, both exhibits empty');

  // ── Both skip links, reached the way a keyboard reaches them ─────────────
  // The lab's own `.skip-link` reveals itself on `:focus-visible`, which a
  // scripted `.focus()` does not reliably set — so this walks the real tab
  // order and asserts where it landed.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared-header skip link focused');
  // Four, not five: the shared bar used to carry a theme toggle between the
  // brand and the lab's own skip link, and removing it removed a tab stop.
  for (let i = 0; i < 4; i++) await page.keyboard.press('Tab');
  await expect(page.locator('a.skip-link')).toBeFocused();
  await scanAt("lab's own skip link focused");

  // ── Exhibit 1: the real loop ─────────────────────────────────────────────
  // Sign until a candidate has actually been rejected, so the rejecting tone is
  // measured. p ~ 0.2, so this all but always ends on the first attempt.
  const signOnce = page.locator('#sign-once');
  for (let attempt = 0; attempt < 12; attempt++) {
    await signOnce.click();
    await summaryReads(page, /Accepted on iteration/);
    if ((await page.locator('.iteration.rejected').count()) > 0) break;
  }
  await expect(page.locator('.iteration.rejected').first()).toBeVisible();
  await expect(page.locator('.iteration.accepted')).toHaveCount(1);
  await expect(page.locator('.check.fail').first()).toBeVisible();
  await expect(page.locator('#tamper-panel')).toBeVisible();
  await scanAt('real signature accepted, rejected candidates on screen');

  // The tamper test — the claim of the exhibit, and its refusal.
  await page.locator('#tamper-flip').click();
  await expect(page.locator('#tamper-result.bad')).toHaveText(/verifies ✗ no/);
  await scanAt('one signature byte flipped, verification refuses it');

  await page.locator('#tamper-restore').click();
  await expect(page.locator('#tamper-result.ok')).toHaveText(/original signature verifies ✓/);
  await scanAt('original signature restored and verifying');

  // Stepping: a partial trace, then the same trace completed.
  const stepButton = page.locator('#step');
  await stepButton.click();
  await expect(stepButton).toHaveText(/Next step ▶|Step ▶ \(new trace\)/);
  await scanAt('stepping one candidate at a time');
  for (let i = 0; i < 60; i++) {
    if ((await stepButton.textContent()) === 'Step ▶ (new trace)') break;
    await stepButton.click();
  }
  await expect(stepButton).toHaveText('Step ▶ (new trace)');
  await expect(page.locator('#tamper-panel')).toBeVisible();
  await scanAt('stepped trace complete');

  // Reset #1: a new keypair clears the feed and re-locks the tamper panel.
  await page.locator('#regen-key').click();
  await expect(page.locator('#iteration-feed .iteration')).toHaveCount(0);
  await expect(page.locator('#tamper-panel')).toBeHidden();
  await summaryReads(page, /New ML-DSA-65 keypair generated/);
  await scanAt('key regenerated, feed emptied and tamper panel re-locked');

  // The seeded-replay fork, and the note and field it unlocks.
  await page.locator('#deterministic').check();
  await expect(page.locator('.seed-field')).toBeVisible();
  await expect(page.locator('.det-note')).toBeVisible();
  await expect(page.locator('#seed')).toBeEnabled();
  await scanAt('reproducible mode on, seed field and note revealed');

  await signOnce.click();
  await summaryReads(page, /seed 42 \(seeded keypair\)/);
  await scanAt('seeded trace signed');

  await page.locator('#copy-link').click();
  await expect(page.locator('#copy-link-result')).not.toBeEmpty();
  await scanAt('shareable link result reported');

  await page.locator('#deterministic').uncheck();
  await expect(page.locator('.seed-field')).toBeHidden();
  await scanAt('reproducible mode off again');

  // ── Exhibit 2: the histogram ─────────────────────────────────────────────
  await page.locator('#preset-select').selectOption('ML-DSA-44');
  await expect(page.locator('#histogram .hist-empty')).toHaveText(/No data yet/);
  await scanAt('preset switched to ML-DSA-44, histogram cleared');

  await page.locator('#run-100').click();
  await summaryReads(page, /Batch complete: 100 signatures/);
  await expect(page.locator('#reason-breakdown .reason-bar')).toBeVisible();
  await scanAt('histogram built from 100 real ML-DSA-44 signatures');

  await page.locator('#preset-select').selectOption('ML-DSA-65');
  await page.locator('#run-1000').click();
  await summaryReads(page, /Batch complete: 1,000 signatures/);
  await scanAt('histogram built from 1,000 real ML-DSA-65 signatures');

  await page.locator('#overlay-presets').check();
  await expect(page.locator('#histogram .pmf-overlay').first()).toBeVisible();
  await scanAt('theoretical preset overlays drawn over the measured bars');

  // A bar near the mode: the search finds a real trace of exactly that length.
  await page.locator('.bar-g[data-iter="2"]').click();
  await summaryReads(page, /exactly 2 iterations|2-iteration trace turned up/);
  await scanAt('example trace loaded from a histogram bar');

  // A bar deep in the geometric tail, reached from the KEYBOARD: 400 real
  // signatures will not reproduce the longest run in a batch of 1,000, so this
  // is the branch that gives up and falls back to an illustrative simulation.
  const tail = page.locator('.bar-g').last();
  const tailIter = await tail.getAttribute('data-iter');
  await tail.focus();
  await page.keyboard.press('Enter');
  await summaryReads(page, new RegExp(`exactly ${tailIter} iterations|${tailIter}-iteration trace turned up`));
  await scanAt(`histogram tail bar ${tailIter} activated by keyboard`);

  // The exploratory simulation fork.
  await page.locator('#custom-p').check();
  await expect(page.locator('#p-slider')).toBeEnabled();
  await expect(page.locator('#p-readout')).not.toBeEmpty();
  await scanAt('exploratory custom-p simulation mode');

  await page.locator('#p-slider').fill('0.55');
  await expect(page.locator('#p-readout')).toHaveText(/p = 0\.55/);
  await scanAt('exploratory p moved to 0.55');

  await page.locator('#run-100').click();
  await summaryReads(page, /Batch complete: 100 traces/);
  await scanAt('simulated batch at the exploratory p');

  await page.locator('.bar-g[data-iter="1"]').click();
  await summaryReads(page, /exploratory simulation at p = 0\.55/);
  await scanAt('simulated example trace from a histogram bar');

  await page.locator('#overlay-presets').uncheck();
  await expect(page.locator('#histogram .pmf-overlay')).toHaveCount(0);
  await scanAt('preset overlays removed again');

  // The empty note only returns once BOTH the exploratory p and the overlays
  // are off — with either on, the chart still has a curve to draw.
  await page.locator('#custom-p').uncheck();
  await expect(page.locator('#p-slider')).toBeDisabled();
  await expect(page.locator('#histogram .hist-empty')).toHaveText(/No data yet/);
  await scanAt('back on the real loop, histogram cleared');

  // Reset #2, with data present.
  await page.locator('#run-100').click();
  await summaryReads(page, /Batch complete: 100 signatures/);
  await page.locator('#reset-hist').click();
  await expect(page.locator('#histogram .hist-empty')).toHaveText(/No data yet/);
  await expect(page.locator('#reason-breakdown')).toBeEmpty();
  await scanAt('histogram reset back to its empty state');

  // ── Exhibit 3: measured signing times ────────────────────────────────────
  await page.locator('#measure-times').click();
  await expect(page.locator('#measure-progress')).toHaveText(/Done: 2,000 real signatures timed/, {
    timeout: 120_000,
  });
  await expect(page.locator('#realtime-hist .hist-svg')).toBeVisible();
  await scanAt('2,000 real signing times measured and binned');

  // ── Exhibit 4: one fresh real signature per check ────────────────────────
  for (const kind of ['z', 'r0', 'ct0', 'hint'] as const) {
    await page.locator(`button[data-check="${kind}"]`).click();
    await expect(page.locator(`#ex-${kind}`)).toHaveText(/Fresh real ML-DSA-65 signature/, {
      timeout: 120_000,
    });
    await scanAt(`check ${kind} example measured from a fresh real signature`);
  }

  // ── Exhibit 6: both scenarios, both guesses ──────────────────────────────
  await page.locator('#run-distinguishability').click();
  await expect(page.locator('#distinguishability-output')).toHaveText(/KS statistic/, {
    timeout: 120_000,
  });
  await expect(page.locator('#ks-chart .cdf-svg')).toBeVisible();
  await expect(page.locator('#leak-game')).toBeHidden();
  await scanAt('faithful KS scenario: two real signers compared');

  await page.locator('#ks-mode').selectOption('leaky');
  await scanAt('broken KS scenario selected, no game running yet');

  // The guess is right or wrong at random, and both verdicts have their own
  // tone (`.ok` / `.bad`). Re-run until each has been seen at least once; the
  // leaky scenario is simulated, so a re-run costs well under a second.
  const seen = { ok: false, bad: false };
  for (let attempt = 0; attempt < 12 && !(seen.ok && seen.bad); attempt++) {
    await page.locator('#run-distinguishability').click();
    await expect(page.locator('#leak-game')).toBeVisible({ timeout: 120_000 });
    if (attempt === 0) await scanAt('leak game awaiting a guess');
    await page.locator('#guess-a').click();
    const outcome = (await page.locator('#leak-reveal.ok').count()) > 0 ? 'ok' : 'bad';
    await expect(page.locator(`#leak-reveal.${outcome}`)).toBeVisible();
    await expect(page.locator('#leak-game')).toBeHidden();
    if (!seen[outcome]) {
      seen[outcome] = true;
      await scanAt(`leak-game guess revealed as ${outcome === 'ok' ? 'correct' : 'wrong'}`);
    }
  }
  expect(seen, 'both leak-game verdict tones must have been scanned').toEqual({ ok: true, bad: true });

  // ── The guided tour ──────────────────────────────────────────────────────
  await page.locator('#tour-start').click();
  const panel = page.locator('.tour-panel');
  await expect(panel).toBeVisible();
  await expect(panel.locator('.tour-progress')).toHaveText('1 / 8');
  await expect(panel.locator('.tour-prev')).toBeDisabled();
  await scanAt('guided tour opened at step 1');

  // Step 2 carries an action button; press it and scan what it produced.
  await panel.locator('.tour-next').click();
  await expect(panel.locator('.tour-progress')).toHaveText('2 / 8');
  await scanAt('tour step 2, action offered');
  await panel.getByRole('button', { name: 'Sign one now' }).click();
  await summaryReads(page, /Accepted on iteration/);
  await scanAt('tour action signed a real signature');

  // Step 3 is a quiz: answer it wrong, then right.
  await panel.locator('.tour-next').click();
  await expect(panel.locator('.tour-quiz')).toBeVisible();
  await scanAt('tour quiz unanswered');
  await panel.locator('.tour-quiz-option').first().click();
  await expect(panel.locator('.tour-quiz-feedback.bad')).toHaveText(/Not quite/);
  await expect(panel.locator('.tour-quiz-option.quiz-incorrect')).toHaveCount(1);
  await expect(panel.locator('.tour-quiz-option.quiz-correct')).toHaveCount(1);
  await scanAt('tour quiz answered incorrectly');
  await panel.locator('.tour-quiz-option.quiz-correct').click();
  await expect(panel.locator('.tour-quiz-feedback.ok')).toHaveText(/^Correct/);
  await scanAt('tour quiz answered correctly');

  // The remaining steps, each scanned as it is reached.
  for (let step = 4; step <= 8; step++) {
    await panel.locator('.tour-next').click();
    await expect(panel.locator('.tour-progress')).toHaveText(`${step} / 8`);
    await scanAt(`tour step ${step}`);
  }

  await panel.locator('.tour-prev').click();
  await expect(panel.locator('.tour-progress')).toHaveText('7 / 8');
  await scanAt('tour stepped back');

  // Reset #3: exiting removes the panel and the highlight ring it left behind.
  await panel.locator('.tour-exit').click();
  await expect(page.locator('.tour-panel')).toHaveCount(0);
  await expect(page.locator('.tour-highlight')).toHaveCount(0);
  await scanAt('tour exited');
}
