interface Deadline<T> {
  key: T;
  at: number;
}

// Indexed deletion/replacement keeps refreshes from accumulating stale entries.
export class Deadlines<T> {
  private readonly nodes: Deadline<T>[] = [];
  private readonly positions = new Map<T, number>();

  set(key: T, at: number) {
    const found = this.positions.get(key);
    const index = found ?? this.nodes.length;
    this.nodes[index] = { key, at };
    this.positions.set(key, index);
    this.fix(index);
  }
  delete(key: T) {
    const index = this.positions.get(key);

    if (index === undefined) return;
    const last = this.nodes.pop()!;
    this.positions.delete(key);

    if (index === this.nodes.length) return;
    this.nodes[index] = last;
    this.positions.set(last.key, index);
    this.fix(index);
  }
  private swap(a: number, b: number) {
    [this.nodes[a], this.nodes[b]] = [this.nodes[b]!, this.nodes[a]!];
    this.positions.set(this.nodes[a]!.key, a);
    this.positions.set(this.nodes[b]!.key, b);
  }
  private fix(start: number) {
    let index = start;

    while (index > 0) {
      const parent = (index - 1) >> 1;

      if (this.nodes[parent]!.at <= this.nodes[index]!.at) break;
      this.swap(parent, index);
      index = parent;
    }

    while (true) {
      let next = index;

      for (const child of [index * 2 + 1, index * 2 + 2])
        if (
          child < this.nodes.length &&
          this.nodes[child]!.at < this.nodes[next]!.at
        )
          next = child;

      if (next === index) break;
      this.swap(index, next);
      index = next;
    }
  }
  drain(now: number, visit: (key: T) => void) {
    while (this.nodes[0] && this.nodes[0].at <= now) {
      const key = this.nodes[0].key;
      this.delete(key);
      visit(key);
    }
  }
  // The owner must not modify this queue while its cursor is being used. A
  // batch traverses confirmed expiry without changing the confirmed state.
  cursor() {
    const frontier = new Deadlines<number>();

    if (this.nodes[0]) frontier.set(0, this.nodes[0].at);

    return {
      drain: (now: number, visit: (key: T) => void) => {
        frontier.drain(now, (index) => {
          const node = this.nodes[index]!;

          for (const child of [index * 2 + 1, index * 2 + 2])
            if (this.nodes[child]) frontier.set(child, this.nodes[child]!.at);
          visit(node.key);
        });
      },
    };
  }
}
