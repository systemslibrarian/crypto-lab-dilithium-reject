import { expect, test, type Page } from '@playwright/test';

/**
 * Claims gate: every load-bearing number and verdict this lab renders is
 * asserted against the page's own arithmetic, not against a fixed string.
 *
 * The a11y spec proves the page can be read. This one proves it is telling
 * the truth: that the summary's iteration count matches the trace it drew,
 * that a rejected candidate really failed the check its label names, that the
 * histogram's stats are reconstructible from the histogram, that a tampered
 * signature really is rejected by untouched noble ML-DSA, and that both KS
 * verdicts follow from the statistic and threshold printed beside them.
 *
 * Nothing here hardcodes an expected iteration count or p̂ — the loop is
 * random by design, so the assertions are internal-consistency relations that
 * hold for every run and break the moment the underlying arithmetic does.
 */

const HEAVY = 180_000;

// ---------------------------------------------------------------------------
// helpers — read the page's rendered numbers back out
// ---------------------------------------------------------------------------

/** Parse the first number in a string, tolerating thousands separators. */
function firstNumber(text: string | null): number {
  const m = /-?[\d,]+(?:\.\d+)?/.exec(text ?? '');
  expect(m, `expected a number in ${JSON.stringify(text)}`).not.toBeNull();
  return Number(m![0].replaceAll(',', ''));
}

/** Any `.stats-grid` on the page, keyed by each cell's visible label. */
async function readGrid(page: Page, root: string): Promise<Map<string, string>> {
  return new Map(
    await page
      .locator(`${root} > div`)
      .evaluateAll((els) =>
        els.map((el): [string, string] => [
          el.querySelector('.k')?.textContent?.trim() ?? '',
          el.querySelector('.v')?.textContent?.trim() ?? '',
        ]),
      ),
  );
}

/** The Exhibit 2 stats grid, keyed by its visible label. */
async function readStats(page: Page): Promise<Map<string, string>> {
  return readGrid(page, '#stats');
}

/** The screen-reader histogram table: one row per iteration bucket. */
async function readHistogramTable(page: Page): Promise<{ iteration: number; count: number; share: number }[]> {
  return page.locator('#histogram table.sr-only tbody tr').evaluateAll((rows) =>
    rows.map((row) => {
      const cells = [...row.querySelectorAll('td')].map((c) => c.textContent?.trim() ?? '');
      return {
        iteration: Number(cells[0]?.replaceAll(',', '')),
        count: Number(cells[1]?.replaceAll(',', '')),
        share: Number.parseFloat(cells[2] ?? ''),
      };
    }),
  );
}

/** Same quantile definition the page uses (src/distributions.ts). */
function quantile(values: number[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  const low = sorted[lo] ?? 0;
  if (lo === hi) return low;
  return low + ((sorted[hi] ?? 0) - low) * (pos - lo);
}

/** Sign once and return the accepted-iteration / rejection counts it reported. */
async function signOnce(page: Page): Promise<{ accepted: number; rejections: number; summary: string }> {
  await page.locator('#sign-once').click();
  await expect(page.locator('#sign-summary')).toContainText('Accepted on iteration', { timeout: HEAVY });
  const summary = (await page.locator('#sign-summary').textContent()) ?? '';
  const m = /Accepted on iteration (\d+) after (\d+) rejection/.exec(summary);
  expect(m, `summary did not report an accepted iteration: ${summary}`).not.toBeNull();
  return { accepted: Number(m![1]), rejections: Number(m![2]), summary };
}

/** The c̃ commitment-hash prefix of every card currently in the feed. */
async function feedFingerprints(page: Page): Promise<string[]> {
  return page.locator('#iteration-feed .iter-sub').allTextContents();
}

/** Run one histogram batch and wait for it to land. */
async function runBatch(page: Page, button: '#run-100' | '#run-1000'): Promise<string> {
  await page.locator(button).click();
  await expect(page.locator('#sign-summary')).toContainText('Batch complete', { timeout: HEAVY });
  return (await page.locator('#sign-summary').textContent()) ?? '';
}

// ---------------------------------------------------------------------------
// Exhibit 1 — the signing trace
// ---------------------------------------------------------------------------

test('the summary’s accepted iteration equals the number of candidate cards it drew', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  const { accepted, rejections, summary } = await signOnce(page);

  // The headline is arithmetic on the trace, not a caption: one card per
  // candidate, the last accepted, every earlier one rejected.
  expect(rejections).toBe(accepted - 1);
  const cards = page.locator('#iteration-feed article.iteration');
  await expect(cards).toHaveCount(accepted, { timeout: HEAVY });
  await expect(cards.last()).toHaveClass(/(^|\s)accepted(\s|$)/);
  await expect(cards.last().locator('.status-pill')).toHaveText('ACCEPTED');
  for (let i = 0; i < accepted - 1; i += 1) {
    await expect(cards.nth(i)).toHaveClass(/(^|\s)rejected(\s|$)/);
    await expect(cards.nth(i).locator('.status-pill')).toHaveText(/^REJECTED · \S+/);
  }

  // The instrumented loop's output is checked by the untouched library.
  expect(summary).toContain('verifies via untouched noble ML-DSA-65: yes');

  // κ is the FIPS 204 mask nonce: it advances monotonically across the trace.
  const kappas = await page
    .locator('#iteration-feed .iter-sub')
    .evaluateAll((els) => els.map((el) => Number(/κ = (\d+)/.exec(el.textContent ?? '')?.[1])));
  expect(kappas).toHaveLength(accepted);
  for (let i = 1; i < kappas.length; i += 1) expect(kappas[i]!).toBeGreaterThan(kappas[i - 1]!);
});

test('every rejected candidate fails the specific check its stated reason names', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');

  const reasonToCheck: Record<string, string> = {
    z_too_large: 'check-z',
    r0_too_large: 'check-r0',
    ct0_too_large: 'check-ct0',
    hint_too_dense: 'check-hint',
  };

  // p ≈ 0.2, so a first-try acceptance happens sometimes; retry for a trace
  // that actually contains a rejection.
  let rejected = 0;
  for (let attempt = 0; attempt < 8 && rejected === 0; attempt += 1) {
    const { accepted } = await signOnce(page);
    await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(accepted, { timeout: HEAVY });
    rejected = await page.locator('#iteration-feed article.iteration.rejected').count();
  }
  expect(rejected, 'never observed a rejection in 8 real signatures').toBeGreaterThan(0);

  const cards = await page.locator('#iteration-feed article.iteration').evaluateAll((els) =>
    els.map((el) => ({
      classes: el.className,
      status: el.querySelector('.status-pill')?.textContent?.trim() ?? '',
      checks: [...el.querySelectorAll('li.check')].map((li) => ({
        classes: li.className,
        pill: li.querySelector('.check-pill')?.textContent?.trim() ?? '',
        value: li.querySelector('.check-val')?.textContent?.trim() ?? '',
      })),
    })),
  );

  for (const card of cards) {
    const accepted = card.classes.includes('accepted');
    if (accepted) {
      // An accepted candidate cleared all four FIPS 204 norm bounds.
      expect(card.checks).toHaveLength(4);
      for (const check of card.checks) {
        expect(check.pill, `accepted card had a failing check: ${check.classes}`).toBe('PASS');
        expect(check.classes).toContain('pass');
      }
      continue;
    }

    const reason = /reason-(\S+)/.exec(card.classes)?.[1] ?? '';
    const cls = reasonToCheck[reason];
    expect(cls, `unknown rejection reason ${reason}`).toBeTruthy();
    expect(card.status).toBe(`REJECTED · ${reason}`);

    // The named check must actually be the one marked FAIL, and its rendered
    // "measured / threshold" pair must genuinely violate the bound.
    const named = card.checks.find((c) => c.classes.includes(cls!));
    expect(named, `card claiming ${reason} has no ${cls} row`).toBeTruthy();
    expect(named!.pill).toBe('FAIL');
    expect(named!.classes).toContain('fail');
    const [measured, threshold] = named!.value.split('/').map((s) => Number(s.replaceAll(',', '').trim()));
    expect(measured, `${reason}: measured ${measured} should violate threshold ${threshold}`).toBeGreaterThanOrEqual(
      threshold!,
    );

    // Every check pill agrees with its own row styling.
    for (const check of card.checks) {
      expect(check.classes).toContain(check.pill === 'PASS' ? 'pass' : 'fail');
    }
  }
});

test('stepping through a trace ends on the same accepted iteration the feed shows', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');

  const step = page.locator('#step');
  await step.click();
  await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(1, { timeout: HEAVY });

  for (let i = 0; i < 60; i += 1) {
    if ((await step.textContent())?.includes('new trace')) break;
    // Mid-trace the summary must say the step was rejected and name a reason.
    await expect(page.locator('#sign-summary')).toContainText(
      /Step \d+: (rejected \(\S+\) — drawing again…|accepted\.)/,
    );
    await step.click();
    await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(i + 2, { timeout: HEAVY });
  }

  const summary = (await page.locator('#sign-summary').textContent()) ?? '';
  const m = /Stepped through (\d+) real iterations? \((\d+) rejections?\)/.exec(summary);
  expect(m, `step mode never completed a trace: ${summary}`).not.toBeNull();
  const total = Number(m![1]);
  expect(Number(m![2])).toBe(total - 1);
  await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(total);
  expect(summary).toContain('Signature verifies via noble ML-DSA-65: yes');
});

// ---------------------------------------------------------------------------
// Exhibit 1 — the tamper path
// ---------------------------------------------------------------------------

test('flipping one bit of a real signature makes untouched noble ML-DSA reject it', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await signOnce(page);

  const result = page.locator('#tamper-result');
  await expect(page.locator('#tamper-panel')).toBeVisible();
  await expect(result).toHaveText('original signature verifies ✓');
  await expect(result).toHaveClass(/(^|\s)ok(\s|$)/);

  // Repeat: a single flipped bit anywhere in the signature must fail, and the
  // page must say which byte it touched.
  const bytes = new Set<number>();
  for (let i = 0; i < 6; i += 1) {
    await page.locator('#tamper-flip').click();
    const text = (await result.textContent()) ?? '';
    const m = /flipped 1 bit of byte (\d+) → verifies (.+)$/.exec(text);
    expect(m, `tamper result did not report a flipped byte: ${text}`).not.toBeNull();
    expect(m![2], 'a tampered signature verified — the demo’s whole point').toBe('✗ no');
    await expect(result).toHaveClass(/(^|\s)bad(\s|$)/);
    bytes.add(Number(m![1]));

    // Restoring re-verifies the untouched bytes, so the failure was the flip.
    await page.locator('#tamper-restore').click();
    await expect(result).toHaveText('original signature verifies ✓');
    await expect(result).toHaveClass(/(^|\s)ok(\s|$)/);
  }
  expect(bytes.size, 'the flip position never varied').toBeGreaterThan(1);
});

// ---------------------------------------------------------------------------
// Exhibit 2 — the histogram, its stats and its rejection breakdown
// ---------------------------------------------------------------------------

test('the histogram stats are all reconstructible from the histogram itself', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  const batch = await runBatch(page, '#run-100');

  const rows = await readHistogramTable(page);
  const stats = await readStats(page);

  // Counts partition the batch.
  const totalRuns = rows.reduce((a, r) => a + r.count, 0);
  expect(totalRuns).toBe(100);
  expect(firstNumber(stats.get('Runs') ?? null)).toBe(totalRuns);

  // Shares partition 100%.
  const totalShare = rows.reduce((a, r) => a + r.share, 0);
  expect(totalShare).toBeGreaterThan(99.4);
  expect(totalShare).toBeLessThan(100.6);
  for (const r of rows) expect(r.share).toBeCloseTo((100 * r.count) / totalRuns, 1);

  // Rebuild the underlying sample and re-derive every summary statistic.
  const sample: number[] = [];
  for (const r of rows) for (let i = 0; i < r.count; i += 1) sample.push(r.iteration);
  const totalIterations = sample.reduce((a, b) => a + b, 0);
  const mean = totalIterations / sample.length;

  expect(firstNumber(stats.get('Observed mean') ?? null)).toBeCloseTo(mean, 2);
  expect(firstNumber(stats.get('Median') ?? null)).toBeCloseTo(quantile(sample, 0.5), 2);
  expect(firstNumber(stats.get('P90') ?? null)).toBeCloseTo(quantile(sample, 0.9), 2);
  expect(firstNumber(stats.get('P99') ?? null)).toBeCloseTo(quantile(sample, 0.99), 2);
  expect(firstNumber(stats.get('Max') ?? null)).toBe(Math.max(...sample));

  // p̂ is the per-iteration MLE: signatures ÷ candidates drawn. That is the
  // claim the README makes ("measured from the batch"), and 1/p̂ must be the
  // mean the same batch produced.
  const pHat = totalRuns / totalIterations;
  expect(firstNumber(stats.get('Measured p̂') ?? null)).toBeCloseTo(pHat, 3);
  expect(firstNumber(stats.get('Mean 1/p̂') ?? null)).toBeCloseTo(1 / pHat, 2);
  expect(stats.get('Source')).toBe('real signing loop');
  expect(stats.get('Preset')).toBe('ML-DSA-65');

  // Tail stats: observed is a share of the same sample, theory is (1−p̂)^8.
  const tailK = 8;
  const observedTail = (100 * sample.filter((v) => v > tailK).length) / sample.length;
  expect(firstNumber(stats.get(`P(>${tailK}) observed`) ?? null)).toBeCloseTo(observedTail, 2);
  expect(firstNumber(stats.get(`P(>${tailK}) theory`) ?? null)).toBeCloseTo(100 * (1 - pHat) ** tailK, 2);

  // The batch banner repeats the same numbers.
  const banner = /Mean: ([\d.]+) · Median: ([\d.]+) · P90: ([\d.]+) · P99: ([\d.]+) · Max: (\d+)/.exec(batch);
  expect(banner, `batch banner missing its stats: ${batch}`).not.toBeNull();
  expect(Number(banner![1])).toBeCloseTo(mean, 2);
  expect(Number(banner![2])).toBeCloseTo(quantile(sample, 0.5), 2);
  expect(Number(banner![5])).toBe(Math.max(...sample));
  expect(firstNumber(/measured p̂ = ([\d.]+) this batch/.exec(batch)?.[1] ?? null)).toBeCloseTo(pHat, 3);

  // The chart's own accessible name carries the mean the stats reported.
  const svgLabel = (await page.locator('#histogram svg').getAttribute('aria-label')) ?? '';
  expect(firstNumber(/Mean about ([\d.]+)/.exec(svgLabel)?.[1] ?? null)).toBeCloseTo(1 / pHat, 1);
});

test('the rejection breakdown accounts for exactly the rejections the histogram implies', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await runBatch(page, '#run-100');

  const rows = await readHistogramTable(page);
  // Every candidate but the accepted one was a rejection.
  const impliedRejections = rows.reduce((a, r) => a + r.count * (r.iteration - 1), 0);

  const heading = (await page.locator('#reason-breakdown .mini-h').textContent()) ?? '';
  expect(firstNumber(/\(([\d,]+) rejections\)/.exec(heading)?.[1] ?? null)).toBe(impliedRejections);

  const pcts = await page
    .locator('#reason-breakdown .reason-legend li strong')
    .evaluateAll((els) => els.map((el) => Number.parseFloat(el.textContent ?? '')));
  expect(pcts).toHaveLength(4);
  const total = pcts.reduce((a, b) => a + b, 0);
  expect(total, `reason shares summed to ${total}%`).toBeGreaterThan(99.4);
  expect(total).toBeLessThan(100.6);

  // The stacked bar's segment widths are the same percentages.
  const widths = await page
    .locator('#reason-breakdown .reason-bar .seg')
    .evaluateAll((els) => els.map((el) => Number.parseFloat((el as HTMLElement).style.width)));
  expect(widths.reduce((a, b) => a + b, 0)).toBeCloseTo(100, 0);

  // README: measured on real data, ‖z‖∞ and ‖r₀‖∞ carry the rejections.
  expect(pcts[0]! + pcts[1]!).toBeGreaterThan(90);
});

test('clicking a histogram bar loads a trace of exactly that many iterations', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await runBatch(page, '#run-100');

  const target = 3;
  await page.locator(`#histogram g.bar-g[data-iter="${target}"]`).click();
  await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(target, { timeout: HEAVY });

  // Either a real trace of that length was found, or the page says plainly it
  // fell back to a labelled simulation — never silently.
  const summary = (await page.locator('#sign-summary').textContent()) ?? '';
  expect(summary).toMatch(
    new RegExp(`(Found a real trace with exactly ${target} iterations|No real ${target}-iteration trace turned up)`),
  );
  if (summary.includes('No real')) expect(summary).toContain('illustrative simulated');

  const cards = page.locator('#iteration-feed article.iteration');
  await expect(cards.last()).toHaveClass(/(^|\s)accepted(\s|$)/);
  await expect(cards.first()).toHaveClass(/(^|\s)rejected(\s|$)/);
});

test('the exploratory slider drives the geometric arithmetic the page displays', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await page.locator('#custom-p').check();

  for (const p of [0.4, 0.25]) {
    await page.locator('#p-slider').fill(String(p));
    await page.locator('#p-slider').dispatchEvent('input');
    await expect(page.locator('#p-readout')).toHaveText(
      `p = ${p.toFixed(2)} · expected mean 1/p = ${(1 / p).toFixed(2)}`,
    );
    const stats = await readStats(page);
    // Switching to the slider is labelled as simulation and clears real data.
    expect(stats.get('Source')).toBe('simulation (custom p)');
    expect(firstNumber(stats.get('Runs') ?? null)).toBe(0);
    expect(firstNumber(stats.get('p (slider)') ?? null)).toBeCloseTo(p, 2);
    expect(firstNumber(stats.get('Mean 1/p') ?? null)).toBeCloseTo(1 / p, 2);
    expect(firstNumber(stats.get('P(>8) theory') ?? null)).toBeCloseTo(100 * (1 - p) ** 8, 2);
    await expect(page.locator('#tail-note')).toContainText(
      `with p ≈ ${p.toFixed(2)}, P(more than 20 draws) = (1−p)²⁰ ≈ ${((1 - p) ** 20 * 100).toPrecision(2)}%`,
    );
  }
});

test('switching preset discards the previous preset’s sample', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await runBatch(page, '#run-100');
  expect(firstNumber((await readStats(page)).get('Runs') ?? null)).toBe(100);

  await page.locator('#preset-select').selectOption('ML-DSA-87');
  const stats = await readStats(page);
  expect(stats.get('Preset')).toBe('ML-DSA-87');
  expect(firstNumber(stats.get('Runs') ?? null)).toBe(0);
  expect(await page.locator('#reason-breakdown').textContent()).toBe('');

  await runBatch(page, '#run-100');
  const rows = await readHistogramTable(page);
  expect(rows.reduce((a, r) => a + r.count, 0)).toBe(100);
  expect((await readStats(page)).get('Preset')).toBe('ML-DSA-87');
});

// ---------------------------------------------------------------------------
// Exhibit 3 — real measured signing times
// ---------------------------------------------------------------------------

test('the measured timing stats are ordered and the spread is max − min', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await page.locator('#measure-times').click();
  await expect(page.locator('#measure-progress')).toContainText('Done:', { timeout: HEAVY });
  await expect(page.locator('#measure-progress')).toHaveText('Done: 2,000 real signatures timed.');

  const grid = await readGrid(page, '#realtime-stats');
  const v = (k: string): number => firstNumber(grid.get(k) ?? null);
  expect(v('Signatures')).toBe(2000);
  expect(v('Min')).toBeLessThanOrEqual(v('Median'));
  expect(v('Median')).toBeLessThanOrEqual(v('P90'));
  expect(v('P90')).toBeLessThanOrEqual(v('P99'));
  expect(v('P99')).toBeLessThanOrEqual(v('Max'));
  expect(v('Mean')).toBeGreaterThanOrEqual(v('Min'));
  expect(v('Mean')).toBeLessThanOrEqual(v('Max'));
  expect(v('Spread')).toBeCloseTo(v('Max') - v('Min'), 2);

  // README: the distribution is genuinely right-skewed — the rejection loop
  // makes the mean sit above the median.
  expect(v('Mean')).toBeGreaterThan(v('Median'));

  // The chart's accessible name reports the same count and mean.
  const label = (await page.locator('#realtime-hist svg').getAttribute('aria-label')) ?? '';
  expect(firstNumber(/Histogram of ([\d,]+) real signing times/.exec(label)?.[1] ?? null)).toBe(2000);
  expect(firstNumber(/Mean ([\d.]+) milliseconds/.exec(label)?.[1] ?? null)).toBeCloseTo(v('Mean'), 2);
});

// ---------------------------------------------------------------------------
// Exhibit 6 — the KS distinguishability verdicts
// ---------------------------------------------------------------------------

function parseKsVerdict(text: string): { statistic: number; critical: number; exceeds: boolean } {
  const stat = /KS statistic:\s+([\d.]+)/.exec(text);
  const crit = /alpha=[\d.]+ threshold:\s+([\d.]+)/.exec(text);
  const result = /Result:\s+(exceeds threshold — distinguishable|below threshold — indistinguishable)/.exec(text);
  expect(stat, `no KS statistic in output: ${text}`).not.toBeNull();
  expect(crit, `no KS threshold in output: ${text}`).not.toBeNull();
  expect(result, `no KS verdict in output: ${text}`).not.toBeNull();
  return {
    statistic: Number(stat![1]),
    critical: Number(crit![1]),
    exceeds: result![1] === 'exceeds threshold — distinguishable',
  };
}

test('the KS verdict on real keys follows from the statistic and threshold beside it', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await page.locator('#run-distinguishability').click();
  await expect(page.locator('#distinguishability-output')).toContainText('Result:', { timeout: HEAVY });

  const text = (await page.locator('#distinguishability-output').textContent()) ?? '';
  const { statistic, critical, exceeds } = parseKsVerdict(text);

  // The verdict is not narration: it is the comparison of the two numbers
  // printed above it. (~5% of honest runs legitimately exceed, so the claim
  // under test is the implication, not the outcome.)
  expect(exceeds).toBe(statistic > critical);
  expect(text).toContain(exceeds ? 'exceeds the alpha=0.05 critical value' : 'is below the alpha=0.05 critical value');
  expect(text).toContain('each with its own freshly generated secret key');

  // The CDF chart is labelled with the same statistic, and the KS gap marker
  // is drawn on it.
  const label = (await page.locator('#ks-chart svg').getAttribute('aria-label')) ?? '';
  expect(firstNumber(/KS statistic ([\d.]+)/.exec(label)?.[1] ?? null)).toBeCloseTo(statistic, 3);
  await expect(page.locator('#ks-chart .ks-gap-label')).toHaveText(`KS = ${statistic.toFixed(3)}`);
  await expect(page.locator('#ks-chart path.cdf-a')).toHaveCount(1);
  await expect(page.locator('#ks-chart path.cdf-b')).toHaveCount(1);
});

test('the leaky positive control is detected, named, and scored against the guess', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await page.locator('#ks-mode').selectOption('leaky');
  await page.locator('#run-distinguishability').click();
  await expect(page.locator('#leak-game')).toBeVisible({ timeout: HEAVY });

  // The verdict is withheld until the guess — that is the exercise.
  const before = (await page.locator('#distinguishability-output').textContent()) ?? '';
  expect(before).not.toContain('KS statistic:');
  expect(before).toContain('acceptance probability depends on the secret key');

  await page.locator('#guess-a').click();
  const reveal = (await page.locator('#leak-reveal').textContent()) ?? '';
  const named = /population ([AB]) is the leaky signer/.exec(reveal);
  expect(named, `reveal did not name the leaky population: ${reveal}`).not.toBeNull();

  // Guessed A: the scoring must agree with the population actually named.
  const guessedRight = named![1] === 'A';
  expect(reveal.startsWith(guessedRight ? '✓ Correct' : '✗ Not this one')).toBe(true);
  await expect(page.locator('#leak-reveal')).toHaveClass(new RegExp(`(^|\\s)${guessedRight ? 'ok' : 'bad'}(\\s|$)`));

  // The leaky signer accepts less often — that is why its CDF climbs slower.
  const ps = /p = ([\d.]+) vs the faithful ([\d.]+)/.exec(reveal);
  expect(ps, `reveal did not report both acceptance probabilities: ${reveal}`).not.toBeNull();
  expect(Number(ps![1])).toBeLessThan(Number(ps![2]));

  // And the positive control must actually fire: KS exceeds its threshold.
  const text = (await page.locator('#distinguishability-output').textContent()) ?? '';
  const { statistic, critical, exceeds } = parseKsVerdict(text);
  expect(exceeds).toBe(statistic > critical);
  expect(exceeds, `positive control failed to detect the leak: KS=${statistic} vs ${critical}`).toBe(true);
  expect(text).toContain('Positive control: the populations really do differ');

  // The game closes once revealed, so the answer cannot be re-guessed.
  await expect(page.locator('#leak-game')).toBeHidden();
});

// ---------------------------------------------------------------------------
// Reproducibility — the seeded / shareable-link claim
// ---------------------------------------------------------------------------

test('a seeded run replays the identical real trace, and a different seed does not', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await page.locator('#deterministic').check();
  await expect(page.locator('#seed')).toBeVisible();

  const { accepted: first } = await signOnce(page);
  await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(first, { timeout: HEAVY });
  const traceA = await feedFingerprints(page);
  expect(traceA.join()).toContain('c̃');

  // Regenerating the session keypair must not change a seeded trace: the seed
  // derives the keypair too, which is what makes the link reproducible.
  await page.locator('#regen-key').click();
  const { accepted: second } = await signOnce(page);
  await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(second, { timeout: HEAVY });
  expect(second).toBe(first);
  expect(await feedFingerprints(page)).toEqual(traceA);

  // A different seed is a different real trace.
  await page.locator('#seed').fill('4242');
  await page.locator('#seed').dispatchEvent('input');
  const { accepted: third } = await signOnce(page);
  await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(third, { timeout: HEAVY });
  expect(await feedFingerprints(page)).not.toEqual(traceA);
});

test('a shared link restores the state it encodes and replays the same trace', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('./?preset=ML-DSA-87&det=1&seed=7&msg=shared-link-message');

  await expect(page.locator('#message-input')).toHaveValue('shared-link-message');
  await expect(page.locator('#deterministic')).toBeChecked();
  await expect(page.locator('#seed')).toHaveValue('7');
  await expect(page.locator('#preset-select')).toHaveValue('ML-DSA-87');

  const { accepted, summary } = await signOnce(page);
  expect(summary).toContain('shared-link-message');
  expect(summary).toContain('seed 7 (seeded keypair)');
  await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(accepted, { timeout: HEAVY });
  const trace = await feedFingerprints(page);

  // Same link, fresh page load: byte-identical trace.
  await page.goto('./?preset=ML-DSA-87&det=1&seed=7&msg=shared-link-message');
  const { accepted: again } = await signOnce(page);
  await expect(page.locator('#iteration-feed article.iteration')).toHaveCount(again, { timeout: HEAVY });
  expect(again).toBe(accepted);
  expect(await feedFingerprints(page)).toEqual(trace);
});
