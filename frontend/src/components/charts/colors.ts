/** Read a CSS custom-property value from :root. */
export function cssVar(name: string): string {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
}

export function piePalette(): string[] {
  return Array.from({ length: 8 }, (_, i) => cssVar(`--clr-pie-${i}`));
}

export function covColor(percent: number): string {
  if (percent < 50) return cssVar("--clr-cov-bad");
  if (percent < 75) return cssVar("--clr-cov-warn");
  if (percent < 90) return cssVar("--clr-cov-good");
  return cssVar("--clr-cov-great");
}

export function covColorT(percent: number): string {
  if (percent < 50) return cssVar("--clr-cov-bad-t");
  if (percent < 75) return cssVar("--clr-cov-warn-t");
  if (percent < 90) return cssVar("--clr-cov-good-t");
  return cssVar("--clr-cov-great-t");
}
