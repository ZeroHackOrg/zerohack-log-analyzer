import { parseLine } from "./parsers.ts";
import type { DetectResult, FlagKind } from "./types.ts";

const FLAG_ORDER: readonly FlagKind[] = ["sqli", "auth-failure", "sensitive-path", "admin-scan"];
const SAMPLE_LIMIT = 3;

function asLines(lines: Iterable<string> | string): string[] {
  return typeof lines === "string" ? lines.split(/\r?\n/) : [...lines];
}

function push(bucket: Map<FlagKind, { count: number; sample: string[] }>, kind: FlagKind, line: string): void {
  const entry = bucket.get(kind) ?? { count: 0, sample: [] };
  entry.count += 1;
  if (entry.sample.length < SAMPLE_LIMIT) entry.sample.push(line);
  bucket.set(kind, entry);
}

export function detect(lines: Iterable<string> | string): DetectResult {
  const buckets = new Map<FlagKind, { count: number; sample: string[] }>();
  for (const raw of asLines(lines)) {
    const line = String(raw ?? "");
    const p = parseLine(line);
    const path = p.path ?? "";
    const msg = p.msg ?? line;

    if (/(?:' OR\b|\bOR\s+['"]|UNION\s+SELECT|--(?:\s|$)|(?:\/\*|\*\/))/.test(`${path} ${msg}`)) {
      push(buckets, "sqli", line);
    }
    if (p.status === 401 || /login failed|authentication failure/i.test(msg)) {
      push(buckets, "auth-failure", line);
    }
    if (/\/etc\/passwd|\.env(?=$|[?\s/])/i.test(path)) {
      push(buckets, "sensitive-path", line);
    }
    if (/^\/admin(?:\/|$)/i.test(path)) {
      push(buckets, "admin-scan", line);
    }
  }

  const flags = FLAG_ORDER.flatMap((kind) => {
    const entry = buckets.get(kind);
    return entry ? [{ kind, count: entry.count, sample: [...entry.sample] }] : [];
  });

  return { flags };
}