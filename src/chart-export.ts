/**
 * Chart export helpers: serialize a rendered SVG chart (inlining the CSS
 * custom-property colors it depends on), download it as .svg or rasterized
 * .png, and build CSV from tabular rows. DOM-only, no chart knowledge.
 */

function triggerDownload(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  // Revoke on the next tick so the click has consumed the URL.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Serialize the first SVG inside `container` to a standalone document.
 * Computed styles for the chart classes are inlined so the exported file
 * renders with the on-screen theme colors instead of unstyled black.
 */
export function serializeChartSvg(container: Element): string | null {
  const svg = container.querySelector('svg');
  if (!svg) return null;
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');

  const styled = ['fill', 'stroke', 'stroke-width', 'stroke-dasharray', 'font-size', 'font-family', 'opacity'];
  const sourceNodes = [svg, ...svg.querySelectorAll('*')];
  const cloneNodes = [clone, ...clone.querySelectorAll('*')];
  for (let i = 0; i < sourceNodes.length; i += 1) {
    const src = sourceNodes[i];
    const dst = cloneNodes[i];
    if (!src || !dst) continue;
    const computed = window.getComputedStyle(src);
    const decl = styled
      .map((prop) => {
        const v = computed.getPropertyValue(prop);
        return v && v !== 'none' && v !== 'normal' ? `${prop}:${v}` : '';
      })
      .filter(Boolean)
      .join(';');
    if (decl) dst.setAttribute('style', decl);
    dst.removeAttribute('class');
  }
  // Solid background so dark-theme exports don't end up transparent-on-white.
  const bg = window.getComputedStyle(document.body).backgroundColor;
  const vb = svg.getAttribute('viewBox') ?? '0 0 760 340';
  const [, , w, h] = vb.split(/\s+/).map(Number);
  clone.insertAdjacentHTML('afterbegin', `<rect x="0" y="0" width="${w ?? 760}" height="${h ?? 340}" fill="${bg}"/>`);
  return new XMLSerializer().serializeToString(clone);
}

export function downloadChartSvg(container: Element, filename: string): boolean {
  const text = serializeChartSvg(container);
  if (!text) return false;
  triggerDownload(filename, new Blob([text], { type: 'image/svg+xml' }));
  return true;
}

/** Rasterize the chart at 2x for slide-quality PNGs. */
export function downloadChartPng(container: Element, filename: string): boolean {
  const text = serializeChartSvg(container);
  const svg = container.querySelector('svg');
  if (!text || !svg) return false;
  const vb = (svg.getAttribute('viewBox') ?? '0 0 760 340').split(/\s+/).map(Number);
  const width = (vb[2] ?? 760) * 2;
  const height = (vb[3] ?? 340) * 2;
  const img = new Image();
  const svgUrl = URL.createObjectURL(new Blob([text], { type: 'image/svg+xml' }));
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx2d = canvas.getContext('2d');
    if (ctx2d) {
      ctx2d.drawImage(img, 0, 0, width, height);
      canvas.toBlob((blob) => {
        if (blob) triggerDownload(filename, blob);
      }, 'image/png');
    }
    URL.revokeObjectURL(svgUrl);
  };
  img.onerror = () => URL.revokeObjectURL(svgUrl);
  img.src = svgUrl;
  return true;
}

/** RFC-4180-ish CSV: quotes any field containing comma, quote, or newline. */
export function toCsv(rows: (string | number)[][]): string {
  return rows
    .map((row) =>
      row
        .map((field) => {
          const s = String(field);
          return /[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
        })
        .join(','),
    )
    .join('\n');
}

export function downloadCsv(filename: string, rows: (string | number)[][]): void {
  triggerDownload(filename, new Blob([toCsv(rows)], { type: 'text/csv' }));
}
