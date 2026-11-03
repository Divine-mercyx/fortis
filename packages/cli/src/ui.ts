/** Minimal terminal styling. Respects NO_COLOR and non-TTY output. */
const enabled = !process.env.NO_COLOR && (process.stdout.isTTY || Boolean(process.env.FORCE_COLOR));
const wrap = (open: number, close: number) => (s: string) => (enabled ? `\u001b[${open}m${s}\u001b[${close}m` : s);

export const c = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  cyan: wrap(36, 39),
  grey: wrap(90, 39),
  white: wrap(97, 39),
};

export const sevColour: Record<string, (s: string) => string> = {
  critical: (s) => c.bold(c.red(s)),
  high: (s) => c.bold(c.yellow(s)),
  medium: (s) => c.blue(s),
  low: (s) => c.grey(s),
  info: (s) => c.grey(s),
};

export const log = (...parts: string[]) => process.stdout.write(`${parts.join(' ')}\n`);
export const err = (...parts: string[]) => process.stderr.write(`${parts.join(' ')}\n`);
