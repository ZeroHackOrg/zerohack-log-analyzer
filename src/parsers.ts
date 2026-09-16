import type { LineKind, ParsedLine } from "./types.ts";

const CLF_COMBINED =
  /^(?<src>\S+)\s+\S+\s+\S+\s+\[(?<ts>[^\]]+)\]\s+"(?<method>[A-Z]+)\s+(?<path>\S+)(?:[^"]*)"\s+(?<status>\d{3})\s+(?<size>\d+|-)\s+"[^"]*"\s+"(?<ua>[^"]*)"/;

const CLF_COMMON =
  /^(?<src>\S+)\s+\S+\s+\S+\s+\[(?<ts>[^\]]+)\]\s+"(?<method>[A-Z]+)\s+(?<path>\S+)(?:[^"]*)"\s+(?<status>\d{3})\s+(?<size>\d+|-)$/;

const SYSLOG_CLASSIC =
  /^(?<mm>[A-Z][a-z]{2})[ ]+(?<dd>\d{1,2})[ ]+(?<hh>\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<prog>[^:]+):\s*(?<msg>.*)$/;

const SYSLOG_ISO =
  /^(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(?<host>\S+)\s+(?<prog>[^:]+):\s*(?<msg>.*)$/;

const FIREWALL =
  /^(?<action>BLOCK|DROP|REJECT)\s+src=(?<src>\d{1,3}(?:\.\d{1,3}){3})\s+dst=\S+\s+sport=\d+\s+dport=\d+/i;

function str(v: unknown): string | undefined {
  return v == null ? undefined : String(v);
}

function num(v: unknown): number | undefined {
  if (v == null) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function parseJsonLine(raw: string): ParsedLine | undefined {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) return undefined;
  const o = data as Record<string, unknown>;
  const out: ParsedLine = { kind: "json" };
  out.src = str(o.src ?? o.ip ?? o.remote_addr ?? o.host ?? o.client_ip);
  out.method = str(o.method ?? o.request_method);
  out.path = str(o.path ?? o.url ?? o.request_uri) ?? str(o.metadata);
  out.status = num(o.status ?? o.code ?? o.response_code);
  out.size = num(o.bytes ?? o.size ?? o.body_bytes);
  out.ua = str(o.user_agent ?? o.ua ?? o.http_user_agent);
  out.ts = str(o.time ?? o.timestamp ?? o.ts ?? o["@timestamp"]);
  out.msg = str(o.msg ?? o.message ?? o.log ?? o.error);
  const ms = num(o.ms ?? o.duration_ms ?? o.response_ms);
  if (ms !== undefined) out.ms = ms;
  return out;
}

export function parseLine(raw: string): ParsedLine {
  const line = String(raw ?? "");
  const trimmed = line.trim();
  if (!trimmed) return { kind: "drop" };

  const clf = CLF_COMBINED.exec(line) ?? CLF_COMMON.exec(line);
  if (clf?.groups) {
    const g = clf.groups;
    return {
      kind: "clf",
      src: str(g.src) || undefined,
      method: str(g.method) || undefined,
      path: str(g.path) || undefined,
      status: num(g.status),
      size: g.size === "-" ? undefined : num(g.size),
      ua: !g.ua || g.ua === "-" ? undefined : g.ua,
      ts: str(g.ts) || undefined,
    };
  }

  const json = parseJsonLine(line);
  if (json) return json;

  const fw = FIREWALL.exec(trimmed);
  if (fw?.groups) {
    return { kind: "drop", src: str(fw.groups.src) || undefined, msg: trimmed };
  }

  const sys = SYSLOG_CLASSIC.exec(line) ?? SYSLOG_ISO.exec(line);
  if (sys?.groups) {
    const g = sys.groups;
    const ts = g.mm ? `${g.mm} ${g.dd} ${g.hh}` : str(g.ts);
    const msg = (g.msg ?? "").trim();
    return {
      kind: "syslog",
      src: str(g.host) || undefined,
      ts: ts || undefined,
      msg: msg || undefined,
    };
  }

  return { kind: "unknown", msg: trimmed };
}

export const LINE_KINDS: readonly LineKind[] = ["clf", "json", "syslog", "drop", "unknown"];