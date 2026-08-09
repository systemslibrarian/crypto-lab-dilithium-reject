import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW, reportCollected } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along the exhibits it teaches: both skip links focused
 * through the real tab order; a real ML-DSA-65 signature signed until a
 * candidate has actually been REJECTED, so the accepting and rejecting tones
 * and a failing `.check` row are all measured; the tamper test in both
 * directions; a trace stepped one candidate at a time and then to completion; a
 * regenerated key emptying the feed and re-locking the tamper panel; the seeded
 * replay revealed, signed and shared; the histogram built from 100 real
 * ML-DSA-44 and then 1,000 real ML-DSA-65 signatures with the preset overlays
 * on; a histogram bar that finds a real trace of exactly that length and a
 * tail bar, activated from the keyboard, deep enough that the search gives up;
 * the exploratory custom-p simulation and its own batch and example trace; the
 * histogram reset back to empty; 2,000 real signing times measured; one fresh
 * real signature per norm-bound check; the faithful KS scenario on two real
 * signers and the broken positive control with both a correct and an incorrect
 * guess; and the eight-step guided tour including a quiz answered wrong and
 * then right, a step walked back, and the tour exited. Every one of those
 * states is scanned, in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why each scan
 * asserts its content first, why the lab's defaults are asserted rather than
 * assumed, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    reportCollected();
  });
}
