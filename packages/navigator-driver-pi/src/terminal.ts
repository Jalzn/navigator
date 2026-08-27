export class TerminalLineQueue {
  #tail: Promise<void> = Promise.resolve();
  #closed = false;

  enqueue(run: () => Promise<void>, failed: (error: unknown) => void): void {
    if (this.#closed) return;
    this.#tail = this.#tail.then(run, () => run()).catch((error) => { failed(error); });
  }

  async closeAndDrain(deadlineMs: number): Promise<boolean> {
    this.#closed = true;
    let timer: NodeJS.Timeout | undefined;
    const timedOut = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), deadlineMs);
    });
    try {
      return await Promise.race([this.#tail.then(() => true), timedOut]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
}
