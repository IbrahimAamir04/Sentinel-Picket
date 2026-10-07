/** Small deterministic PRNG (mulberry32) so demo data is stable between reloads. */
export function createRng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (min: number, max: number) => Math.floor(next() * (max - min + 1)) + min,
    pick: <T,>(arr: readonly T[]): T => arr[Math.floor(next() * arr.length)],
    weighted: <T,>(items: readonly { item: T; weight: number }[]): T => {
      const total = items.reduce((s, i) => s + i.weight, 0);
      let r = next() * total;
      for (const i of items) { r -= i.weight; if (r <= 0) return i.item; }
      return items[items.length - 1].item;
    },
    hex: (len: number) => Array.from({ length: len }, () => Math.floor(next() * 16).toString(16)).join(""),
  };
}
export type Rng = ReturnType<typeof createRng>;
