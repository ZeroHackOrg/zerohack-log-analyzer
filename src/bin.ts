#!/usr/bin/env node
/** zh-log — parse, aggregate and triage nginx/apache/jsonl/syslog/firewall logs. */

import { readFile } from "node:fs/promises";
import { Command } from "commander";
import { table, truncate } from "@zerohack/shared";
import { analyze } from "./analyze.ts";
import { detect } from "./detect.ts";

const program = new Command();

program
  .name("zh-log")
  .description("Log forensics: parse access/syslog/jsonl lines, print traffic stats and heuristic attack flags. Use `-` as the file to read stdin.")
  .version("0.1.0", "-v, --version")
  .showHelpAfterError();

async function readSource(file: string): Promise<string> {
  if (file === "-") {
    let data = "";
    process.stdin.setEncoding("utf8");
    for await (const chunk of process.stdin) data += chunk;
    return data;
  }
  return readFile(file, "utf8");
}

const countRows = (r: Record<string, number>) =>
  Object.entries(r)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([k, v]) => [k, String(v)]);

program
  .command("analyze <file|->")
  .description("parse the log and print traffic statistics")
  .option("-j, --json", "print JSON")
  .option("--top <n>", "how many rows per ranking table", "5")
  .action(async (file: string, opts: { json?: boolean; top?: string }) => {
    const top = Math.max(1, Number(opts.top) || 5);
    const result = analyze(await readSource(file));
    if (opts.json) {
      console.log(JSON.stringify({ ...result, statusHist: result.statusHist }, null, 2));
      return;
    }
    console.log(`[zh-log] ${result.total} lines over ${result.uniqIps} unique sources`);
    console.log(
      table({
        headers: ["kind", "lines"],
        rows: countRows(result.kinds),
      })
    );
    if (result.topIps.length) {
      console.log(`[zh-log] top sources (top ${top})`);
      console.log(
        table({
          headers: ["ip", "hits"],
          rows: result.topIps.slice(0, top).map((r) => [r.name, String(r.count)]),
        })
      );
    }
    if (result.statusHist && Object.keys(result.statusHist).length) {
      console.log("[zh-log] status histogram");
      console.log(
        table({
          headers: ["status", "count"],
          rows: countRows(result.statusHist),
        })
      );
    }
    if (result.topUas.length) {
      console.log(`[zh-log] top user agents (top ${top})`);
      console.log(
        table({
          headers: ["user-agent", "hits"],
          rows: result.topUas.slice(0, top).map((r) => [truncate(r.name, 56), String(r.count)]),
        })
      );
    }
    if (Object.keys(result.methods).length) {
      console.log("[zh-log] methods");
      console.log(
        table({
          headers: ["method", "count"],
          rows: countRows(result.methods),
        })
      );
    }
    if (result.slowest.length) {
      console.log(`[zh-log] slowest requests (top ${top}, by ms)`);
      console.log(
        table({
          headers: ["ms", "source", "method", "path", "status"],
          rows: result.slowest.slice(0, top).map((s) => [
            String(s.ms),
            s.src ?? "-",
            s.method ?? "-",
            truncate(s.path ?? "-", 56),
            s.status === undefined ? "-" : String(s.status),
          ]),
        })
      );
    }
  });

program
  .command("detect <file|->")
  .description("heuristic attack/incident flags (SQLi, auth failures, sensitive paths, admin scans)")
  .option("-j, --json", "print JSON")
  .action(async (file: string, opts: { json?: boolean }) => {
    const result = detect(await readSource(file));
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    if (!result.flags.length) {
      console.log("[zh-log] no heuristic flags found.");
      return;
    }
    console.log(
      table({
        headers: ["flag", "hits", "sample"],
        rows: result.flags.map((f) => [f.kind, String(f.count), truncate(f.sample.join(" | "), 72)]),
      })
    );
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(`zh-log: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});