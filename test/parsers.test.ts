import { describe, expect, it } from "vitest";
import { LINE_KINDS, parseLine } from "../src/parsers.ts";

const CLF =
  '10.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326 "http://example.com/start" "Mozilla/4.08 (Win98)"';

describe("parseLine", () => {
  it("parses Combined Log Format", () => {
    const p = parseLine(CLF);
    expect(p.kind).toBe("clf");
    expect(p.src).toBe("10.0.0.1");
    expect(p.method).toBe("GET");
    expect(p.path).toBe("/a.gif");
    expect(p.status).toBe(200);
    expect(p.size).toBe(2326);
    expect(p.ua).toBe("Mozilla/4.08 (Win98)");
    expect(p.ts).toBe("10/Oct/2000:13:55:36 -0700");
  });

  it("parses CLF with negated fields", () => {
    const p = parseLine('10.0.0.2 - - [01/Oct/2001:00:00:00 +0000] "POST /api HTTP/1.1" 404 - "-" "curl/8.0"');
    expect(p.kind).toBe("clf");
    expect(p.method).toBe("POST");
    expect(p.status).toBe(404);
    expect(p.size).toBeUndefined();
    expect(p.ua).toBe("curl/8.0");
  });

  it("parses common log format (no referer/user-agent)", () => {
    const p = parseLine('10.0.0.3 - - [02/Oct/2001:00:00:00 +0000] "GET /x HTTP/1.1" 304 0');
    expect(p.kind).toBe("clf");
    expect(p.status).toBe(304);
    expect(p.size).toBe(0);
    expect(p.ua).toBeUndefined();
  });

  it("parses JSON lines and extracts ms for latency analysis", () => {
    const p = parseLine('{"ip":"10.0.0.9","method":"POST","path":"/api/login","status":200,"ua":"Go-http-client/2.0","ms":235}');
    expect(p.kind).toBe("json");
    expect(p.src).toBe("10.0.0.9");
    expect(p.method).toBe("POST");
    expect(p.path).toBe("/api/login");
    expect(p.status).toBe(200);
    expect(p.ua).toBe("Go-http-client/2.0");
    expect(p.ms).toBe(235);
  });

  it("keeps JSON scalar/malformed lines as unknown", () => {
    expect(parseLine('"just a string"').kind).toBe("unknown");
    expect(parseLine('{"broken json').kind).toBe("unknown");
  });

  it("parses classic BSD syslog", () => {
    const p = parseLine("Mar 1 12:00:00 web01 sshd[123]: Failed password for root from 192.168.1.5 port 22 ssh2");
    expect(p.kind).toBe("syslog");
    expect(p.src).toBe("web01");
    expect(p.ts).toBe("Mar 1 12:00:00");
    expect(p.msg).toContain("Failed password for root");
  });

  it("parses ISO-8601 syslog", () => {
    const p = parseLine("2026-09-16T12:34:56Z fw1 kernel: SYN flood detected from 10.0.0.7");
    expect(p.kind).toBe("syslog");
    expect(p.src).toBe("fw1");
    expect(p.ts).toBe("2026-09-16T12:34:56Z");
    expect(p.msg).toContain("SYN flood");
  });

  it("flags firewall BLOCK/DROP lines as kind drop", () => {
    const p = parseLine("BLOCK src=1.2.3.4 dst=5.6.7.8 sport=443 dport=80");
    expect(p.kind).toBe("drop");
    expect(p.src).toBe("1.2.3.4");
    expect(p.msg).toContain("BLOCK");
  });

  it("drops blank lines", () => {
    expect(parseLine("").kind).toBe("drop");
    expect(parseLine("   \n").kind).toBe("drop");
  });

  it("falls back to unknown for garbage", () => {
    const p = parseLine("garbage nonsense 123");
    expect(p.kind).toBe("unknown");
    expect(p.msg).toBe("garbage nonsense 123");
  });

  it("exposes the canonical kind order", () => {
    expect(LINE_KINDS).toEqual(["clf", "json", "syslog", "drop", "unknown"]);
  });
});