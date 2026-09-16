import { describe, expect, it } from "vitest";
import { detect } from "../src/detect.ts";

describe("detect", () => {
  it("flags SQLi payloads in paths and messages", () => {
    const r = detect([
      '{"ip":"1.1.1.1","method":"GET","path":"/search?q=\' OR 1=1 --","msg":"sqli attempt"}',
      "Mar 1 12:00:00 web app: USER: UNION SELECT username,password FROM users",
    ]);
    const sqli = r.flags.find((f) => f.kind === "sqli");
    expect(sqli).toBeDefined();
    expect(sqli?.count).toBe(2);
    expect(sqli?.sample).toHaveLength(2);
  });

  it("flags 401s and auth-failure messages", () => {
    const r = detect([
      '{"ip":"2.2.2.2","status":401,"path":"/admin"}',
      "Mar 1 12:00:00 web sshd[99]: authentication failure; logname= root uid=0",
      "Sep 16 09:00:00 web login[5]: Login failed for user admin",
    ]);
    const auth = r.flags.find((f) => f.kind === "auth-failure");
    expect(auth?.count).toBe(3);
  });

  it("flags sensitive-path access", () => {
    const r = detect([
      '{"ip":"3.3.3.3","method":"GET","path":"/etc/passwd"}',
      '{"ip":"3.3.3.3","method":"GET","path":"/.env?raw=1"}',
    ]);
    const sp = r.flags.find((f) => f.kind === "sensitive-path");
    expect(sp?.count).toBe(2);
    expect(sp?.sample).toHaveLength(2);
  });

  it("flags /admin volume", () => {
    const r = detect([
      '{"ip":"4.4.4.4","path":"/admin/login"}',
      '{"ip":"4.4.4.4","path":"/admin"}',
    ]);
    const admin = r.flags.find((f) => f.kind === "admin-scan");
    expect(admin?.count).toBe(2);
  });

  it("keeps flags in canonical order and caps samples at three", () => {
    const lines = Array.from({ length: 10 }, (_, i) => `' OR 1=1 -- ${i}`);
    const r = detect(lines);
    expect(r.flags.map((f) => f.kind)).toEqual(["sqli"]);
    expect(r.flags[0].count).toBe(10);
    expect(r.flags[0].sample).toHaveLength(3);
  });

  it("returns no flags for clean traffic", () => {
    const r = detect([
      '10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 42 "-" "curl/8.0"',
      '{"ip":"10.0.0.2","method":"GET","path":"/about","status":200,"ms":12}',
    ]);
    expect(r.flags).toEqual([]);
  });
});