import { describe, expect, it } from "vitest";
import { analyze } from "../src/analyze.ts";

const SAMPLE = [
  '10.0.0.1 - - [01/Jan/2026:00:00:01 +0000] "GET /a HTTP/1.1" 200 100 "https://r.example/" "curl/8.0"',
  '10.0.0.1 - - [01/Jan/2026:00:00:02 +0000] "GET /b HTTP/1.1" 404 20 "-" "curl/8.0"',
  '10.0.0.2 - - [01/Jan/2026:00:00:03 +0000] "POST /c HTTP/1.1" 500 0 "-" "Mozilla/5.0 (X11)"',
  '{"ip":"10.0.0.1","method":"GET","path":"/slow","status":200,"ua":"bot/1.0","ms":120}',
  "",
  "??garbage??",
];

const SNAPSHOT = {
  total: 6,
  uniqIps: 2,
  topIps: [
    { name: "10.0.0.1", count: 3 },
    { name: "10.0.0.2", count: 1 },
  ],
  topUas: [
    { name: "curl/8.0", count: 2 },
    { name: "bot/1.0", count: 1 },
    { name: "Mozilla/5.0 (X11)", count: 1 },
  ],
};

describe("analyze", () => {
  it("aggregates totals, histograms and rankings in memory", () => {
    const r = analyze(SAMPLE);
    expect(r.total).toBe(SNAPSHOT.total);
    expect(r.uniqIps).toBe(SNAPSHOT.uniqIps);
    expect(r.topIps).toEqual(SNAPSHOT.topIps);
    expect(r.topUas).toEqual(SNAPSHOT.topUas);
    expect(r.statusHist).toEqual({ "200": 2, "404": 1, "500": 1 });
    expect(r.methods).toEqual({ GET: 3, POST: 1 });
    expect(r.kinds).toEqual({ clf: 3, drop: 1, json: 1, unknown: 1 });
  });

  it("ranks slowest requests by the ms field in JSON lines", () => {
    const r = analyze(SAMPLE);
    expect(r.slowest).toHaveLength(1);
    expect(r.slowest[0]).toMatchObject({ ms: 120, src: "10.0.0.1", method: "GET", path: "/slow", status: 200 });
    expect(r.slowest[0].line).toContain('"ms":120');
  });

  it("sorts slowest descending and ties by input order", () => {
    const lines = [
      '{"ip":"a","ms":50}',
      '{"ip":"b","ms":500}',
      '{"ip":"c","ms":200}',
      '{"ip":"d","ms":50}',
    ];
    const r = analyze(lines);
    expect(r.slowest.map((s) => s.src)).toEqual(["b", "c", "a", "d"]);
  });

  it("accepts a raw multi-line string", () => {
    const r = analyze(SAMPLE.join("\n"));
    expect(r.total).toBe(6);
    expect(r.uniqIps).toBe(2);
  });

  it("handles empty input deterministically", () => {
    const r = analyze([]);
    expect(r).toEqual({
      total: 0,
      uniqIps: 0,
      topIps: [],
      topUas: [],
      statusHist: {},
      slowest: [],
      methods: {},
      kinds: {},
    });
  });
});