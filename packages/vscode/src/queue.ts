/*
 * One scan at a time for each folder. Saves that arrive close together, or during a scan, are
 * gathered into the next one, so saving quickly never starts a pile of processes.
 */

export type Work = { all: boolean; paths: string[] };

export class ScanQueue {
  private pending: { all: boolean; paths: Set<string> } | null = null;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running = false;
  private disposed = false;

  constructor(
    private readonly run: (work: Work) => Promise<void>,
    private readonly delayMs = 300,
  ) {}

  /** Asks for a scan of these paths, or of everything when `paths` is omitted. */
  request(paths?: string[]) {
    if (this.disposed) return;
    const next = (this.pending ??= { all: false, paths: new Set() });
    if (paths) for (const p of paths) next.paths.add(p);
    else next.all = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.drain(), this.delayMs);
  }

  private async drain() {
    this.timer = undefined;
    if (this.running || !this.pending || this.disposed) return;
    const { all, paths } = this.pending;
    this.pending = null;
    this.running = true;
    try {
      await this.run({ all, paths: [...paths] });
    } finally {
      this.running = false;
      if (this.pending) void this.drain();
    }
  }

  dispose() {
    this.disposed = true;
    if (this.timer) clearTimeout(this.timer);
  }
}
