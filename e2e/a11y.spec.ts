import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST KAT vectors;
 * this gates them on accessibility the same way, in both themes.
 *
 * This lab has no native <details>. Instead several regions are hidden via the
 * `hidden` attribute (the tamper panel, the seed field, the "leaky signer"
 * game, the deterministic note) and the guided tour is a class-toggled panel
 * appended to the DOM on demand. Before scanning we reveal every `hidden`
 * region, start the guided tour so its panel is scanned too, and neutralize
 * animations/transitions so nothing is scanned mid-transition.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: '*, *::before, *::after { animation: none !important; transition: none !important; }',
  });
}

async function revealHidden(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Expand any native <details> (none today, but future-proof).
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal anything hidden via the `hidden` attribute or display:none.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
    for (const el of document.querySelectorAll<HTMLElement>('*')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function runSuite(page: Page): Promise<void> {
  await revealHidden(page);
  await neutralizeMotion(page);
  await scan(page);

  // Guided tour: a class-toggled panel appended to the DOM. Open it and scan.
  await page.locator('#tour-start').click();
  const tour = page.locator('.tour-panel');
  await expect(tour).toBeVisible();
  await revealHidden(page);
  await neutralizeMotion(page);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await runSuite(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runSuite(page);
});

test('per-check example reports a fresh measured signing-loop value', async ({ page }) => {
  await page.goto('.');
  await page.locator('button[data-check="hint"]').click();
  const evidence = page.locator('#ex-hint');
  await expect(evidence).toContainText('Fresh real ML-DSA-65 signature');
  await expect(evidence).toContainText('Measured:');
  await expect(evidence).toContainText('Threshold:');
  await expect(evidence).toContainText(/Check: (PASS|REJECT)/);
});
