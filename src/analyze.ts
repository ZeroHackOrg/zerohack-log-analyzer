import { parseLine } from "./parsers.ts";
import type { AnalyzeResult, Counted, SlowEntry } from "./types.ts";

function asLines(lines: Iterable<string> | string): string[] {
  return typeof lines === "string" ? lines.split(/\r?\n/) : [...lines];
}

function rank(counts: Map<string, number>): Counted[] {
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

export function analyze(lines: Iterable<string> | string): AnalyzeResult {
  const ipCount = new Map<string, number>();
  const uaCount = new Map<string, number>();
  const statusHist: Record<string, number> = {};
  const methodCount = new Map<string, number>();
  const kindCount: Record<string, number> = {};
  const slowest: SlowEntry[] = [];

  let total = 0;
  for (const raw of asLines(lines)) {
    const p = parseLine(raw);
    total++;
    kindCount[p.kind] = (kindCount[p.kind] ?? 0) + 1;
    if (p.src) ipCount.set(p.src, (ipCount.get(p.src) ?? 0) + 1);
    if (p.ua && p.ua !== "-") uaCount.set(p.ua, (uaCount.get(p.ua) ?? 0) + 1);
    if (p.status !== undefined) statusHist[String(p.status)] = (statusHist[String(p.status)] ?? 0) + 1;
    if (p.method) methodCount.set(p.method, (methodCount.get(p.method) ?? 0) + 1);
    if (p.ms !== undefined && Number.isFinite(p.ms)) {
      slowest.push({ ms: p.ms, src: p.src, method: p.method, path: p.path, status: p.status, line: raw.trim() });
    }
  }

  slowest.sort((a, b) => b.ms - a.ms);

  return {
    total,
    uniqIps: ipCount.size,
    topIps: rank(ipCount),
    topUas: rank(uaCount),
    statusHist,
    slowest,
    methods: Object.fromEntries([...methodCount.entries()].sort((a, b) => a[0].localeCompare(b[0]))),
    kinds: Object.fromEntries(Object.keys(kindCount).sort().map((k) => [k, kindCount[k]])),
  };
}