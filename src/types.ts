export type LineKind = "clf" | "json" | "syslog" | "drop" | "unknown";

export interface ParsedLine {
  kind: LineKind;
  src?: string;
  method?: string;
  path?: string;
  status?: number;
  size?: number;
  ua?: string;
  ts?: string;
  msg?: string;
  ms?: number;
}

export interface Counted {
  name: string;
  count: number;
}

export interface SlowEntry {
  ms: number;
  src?: string;
  method?: string;
  path?: string;
  status?: number;
  line: string;
}

export interface AnalyzeResult {
  total: number;
  uniqIps: number;
  topIps: Counted[];
  topUas: Counted[];
  statusHist: Record<string, number>;
  slowest: SlowEntry[];
  methods: Record<string, number>;
  kinds: Record<string, number>;
}

export type FlagKind = "sqli" | "auth-failure" | "sensitive-path" | "admin-scan";

export interface LogFlag {
  kind: FlagKind;
  count: number;
  sample: string[];
}

export interface DetectResult {
  flags: LogFlag[];
}