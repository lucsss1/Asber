"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

type Item = { id: string; label: string; hint?: string; href: string; group: string };

/** Everywhere you can go, and the filters worth reaching directly. */
const PLACES: Item[] = [
  { id: "p-overview", label: "Overview", href: "/", group: "Go to" },
  { id: "p-threats", label: "Active threats", href: "/threats", group: "Go to" },
  { id: "p-vulns", label: "Vulnerabilities", href: "/vulnerabilities", group: "Go to" },
  { id: "p-exploits", label: "Exploits & PoCs", href: "/exploits", group: "Go to" },
  { id: "p-actors", label: "Threat actors", href: "/actors", group: "Go to" },
  { id: "p-malware", label: "Malware", href: "/malware", group: "Go to" },
  { id: "p-campaigns", label: "Campaigns", href: "/campaigns", group: "Go to" },
  { id: "p-attack", label: "MITRE ATT&CK", href: "/attack", group: "Go to" },
  { id: "p-research", label: "Research", href: "/research", group: "Go to" },
  { id: "p-news", label: "News", href: "/news", group: "Go to" },
  { id: "p-sources", label: "Source health", href: "/sources", group: "Go to" },
  { id: "p-data", label: "Data sources", href: "/data-sources", group: "Go to" },
  { id: "p-settings", label: "Settings", href: "/settings", group: "Go to" },
  { id: "f-exploited", label: "Being exploited", hint: "in the wild", href: "/threats?exploited=true", group: "Filter" },
  { id: "f-kev", label: "In CISA KEV", hint: "known exploited catalog", href: "/threats?kev=true", group: "Filter" },
  { id: "f-exploit", label: "Has a public exploit", href: "/threats?has_exploit=true", group: "Filter" },
  { id: "f-poc", label: "Has a public PoC", href: "/threats?has_poc=true", group: "Filter" },
];

type Hit = { cve_id?: string; title?: string | null; name?: string; external_id?: string | null; stix_id?: string };

/**
 * Cmd/Ctrl+K. Deliberately has no open or close animation: this is a
 * keyboard action someone performs dozens of times a day, and motion on it
 * reads as lag. Raycast has none either, for the same reason.
 *
 * It searches the collection, not just the menu — typing a vendor name or a
 * technique finds the thing itself, which is how you learn what is in here.
 */
export function Palette() {
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Item[]>([]);
  const [active, setActive] = useState(0);
  const router = useRouter();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        const d = dialog.current;
        if (!d) return;
        if (d.open) d.close();
        else {
          d.showModal();
          input.current?.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const term = q.trim();
    if (term.length < 2) {
      setHits([]);
      return;
    }
    const abort = new AbortController();
    const timer = setTimeout(() => {
      fetch(`/api/search?q=${encodeURIComponent(term)}&limit=6`, { signal: abort.signal })
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
        .then((d) => {
          const out: Item[] = [];
          for (const v of (d.vulnerabilities ?? []) as Hit[]) {
            if (!v.cve_id) continue;
            out.push({ id: `v-${v.cve_id}`, label: v.cve_id, hint: v.title ?? undefined, href: `/cve/${v.cve_id}`, group: "Vulnerabilities" });
          }
          for (const a of (d.attack ?? []) as Hit[]) {
            const key = a.external_id || a.stix_id;
            if (!key) continue;
            out.push({ id: `a-${key}`, label: a.name ?? key, hint: a.external_id ?? undefined, href: `/attack/${key}`, group: "ATT&CK" });
          }
          setHits(out);
        })
        .catch((e) => {
          if (e.name !== "AbortError") setHits([]);
        });
    }, 150);
    return () => {
      clearTimeout(timer);
      abort.abort();
    };
  }, [q]);

  const term = q.trim().toLowerCase();
  const places = term ? PLACES.filter((p) => p.label.toLowerCase().includes(term)) : PLACES;
  const items = [...places, ...hits];
  const clamped = Math.min(active, Math.max(0, items.length - 1));

  const go = (item?: Item) => {
    if (!item) return;
    dialog.current?.close();
    router.push(item.href);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive(items.length ? (clamped + 1) % items.length : 0);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive(items.length ? (clamped + items.length - 1) % items.length : 0);
    } else if (e.key === "Enter") {
      e.preventDefault();
      go(items[clamped]);
    }
  };

  let lastGroup = "";

  return (
    <dialog
      ref={dialog}
      className="palette"
      aria-label="Command palette"
      onClose={() => {
        setQ("");
        setActive(0);
      }}
      onClick={(e) => {
        if (e.target === dialog.current) dialog.current?.close();
      }}
    >
      <div className="palette-box">
        <input
          ref={input}
          className="palette-input"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setActive(0);
          }}
          onKeyDown={onKeyDown}
          placeholder="Jump to a page, a filter, a CVE, an actor…"
          aria-label="Search Asber"
          autoComplete="off"
          maxLength={120}
        />
        <ul className="palette-list" role="listbox" aria-label="Results">
          {items.length === 0 ? (
            <li className="palette-empty">No match for “{q.trim()}”.</li>
          ) : (
            items.map((item, i) => {
              const head = item.group !== lastGroup ? ((lastGroup = item.group), item.group) : null;
              return (
                <li key={item.id}>
                  {head ? <div className="palette-group">{head}</div> : null}
                  <button
                    type="button"
                    role="option"
                    aria-selected={i === clamped}
                    className={`palette-item${i === clamped ? " on" : ""}`}
                    onMouseMove={() => setActive(i)}
                    onClick={() => go(item)}
                  >
                    <span className="palette-label">{item.label}</span>
                    {item.hint ? <span className="palette-hint">{item.hint}</span> : null}
                  </button>
                </li>
              );
            })
          )}
        </ul>
        <div className="palette-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> move</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </dialog>
  );
}
