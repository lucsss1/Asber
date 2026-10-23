/** No client component may derive text from the clock during render.
 *
 *  Run with `npm test` — Node's own test runner, no framework.
 *
 *  A client component is rendered twice: once on the server to produce the
 *  HTML, and again in the browser to hydrate it. Anything it computes from
 *  `Date.now()` during render is therefore computed at two different moments,
 *  and the two disagree the instant a boundary falls between them — a row that
 *  said "59 min ago" when the page was built says "1h ago" a second later.
 *  React sees text it did not send, throws away the hydration for that
 *  subtree and re-renders it, which leaves the controls inside it briefly
 *  unresponsive.
 *
 *  That shipped. The Overview threw React #418 for exactly this reason, found
 *  by reading the console rather than the code, because the symptom is
 *  intermittent by construction: it only fires when the clock crosses a
 *  boundary between render and hydration.
 *
 *  The cure is always the same — format on the server and pass the string
 *  down, so one clock decides. This fails if anything reaches for the other
 *  shape again.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/** Helpers in lib/format that read the clock, and so cannot run on both sides. */
const CLOCK_BOUND = ["relative"];

const ROOTS = ["app", "components"];

function tsxFiles(dir: string): string[] {
  let out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      if (entry === "node_modules" || entry === ".next") continue;
      out = out.concat(tsxFiles(path));
    } else if (entry.endsWith(".tsx") || entry.endsWith(".ts")) {
      out.push(path);
    }
  }
  return out;
}

function clientComponents(): { path: string; source: string }[] {
  const found: { path: string; source: string }[] = [];
  for (const root of ROOTS) {
    let files: string[];
    try {
      files = tsxFiles(join(process.cwd(), root));
    } catch {
      continue; // the directory may not exist in a partial checkout
    }
    for (const path of files) {
      const source = readFileSync(path, "utf8");
      if (/^\s*["']use client["']/m.test(source)) found.push({ path, source });
    }
  }
  return found;
}

describe("hydration safety", () => {
  test("the scan actually sees the client components", () => {
    // A guard that finds nothing passes for the wrong reason. ThreatRows is
    // the component the original bug was in, so it has to be in the set.
    const paths = clientComponents().map((c) => c.path.replace(/\\/g, "/"));
    assert.ok(paths.length >= 3, `only found ${paths.length} client components`);
    assert.ok(
      paths.some((p) => p.endsWith("components/ThreatRows.tsx")),
      "ThreatRows.tsx was not scanned",
    );
  });

  for (const helper of CLOCK_BOUND) {
    test(`no client component calls ${helper}() during render`, () => {
      const offenders = clientComponents()
        .filter(({ source }) => new RegExp(`\\b${helper}\\s*\\(`).test(source))
        .map(({ path }) => path.replace(/\\/g, "/").split("/frontend/").pop());
      assert.deepEqual(
        offenders,
        [],
        `${helper}() reads the clock, so a client component renders it twice and the ` +
          `two results disagree across a boundary (React #418). Format it on the server ` +
          `and pass the string down. Offending files: ${offenders.join(", ")}`,
      );
    });
  }

  test("no component formats a number without pinning the locale", () => {
    /* This was the one that actually shipped, and the clock had nothing to do
     * with it. `toLocaleString()` with no argument follows whoever runs it:
     * `en-US` in the server container, giving "2,149", and the operating
     * system's regional settings in Chromium, giving "2.149" — on a machine
     * set to Brazil even while `navigator.language` still reports `en-US`.
     *
     * Server and client components both get this wrong, in different ways. A
     * server component renders one form while a client component beside it
     * renders the other, so the same screen disagrees with itself; and inside
     * a client component the string is produced twice and React throws #418.
     *
     * `num()` pins it. `fmtDate` had already pinned its own locale and
     * timezone for the same reason — numbers were simply missed. */
    const offenders: string[] = [];
    for (const root of ROOTS) {
      let files: string[];
      try {
        files = tsxFiles(join(process.cwd(), root));
      } catch {
        continue;
      }
      for (const path of files) {
        if (/toLocaleString\(\s*\)/.test(readFileSync(path, "utf8"))) {
          offenders.push(path.replace(/\\/g, "/").split("/frontend/").pop()!);
        }
      }
    }
    assert.deepEqual(
      offenders,
      [],
      `toLocaleString() with no locale renders differently on the server than in the ` +
        `browser. Use num() from lib/format. Offending files: ${offenders.join(", ")}`,
    );
  });

  test("Date.now is not read during a client component's render", () => {
    const offenders = clientComponents()
      .filter(({ source }) => {
        if (!/Date\.now\s*\(/.test(source)) return false;
        // Inside an effect or a handler it runs only in the browser, which is
        // fine; it is render-time reads that differ between the two passes.
        const guarded = /use(Effect|LayoutEffect)\s*\(|on[A-Z]\w*\s*=|function handle/.test(source);
        return !guarded;
      })
      .map(({ path }) => path.replace(/\\/g, "/").split("/frontend/").pop());
    assert.deepEqual(offenders, [], `Date.now() read during render in: ${offenders.join(", ")}`);
  });
});
