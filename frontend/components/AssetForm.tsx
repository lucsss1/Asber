"use client";

import { useActionState, useEffect, useRef, useState } from "react";

import { CATEGORIES, type Asset } from "@/lib/rampart";
import { createAsset, updateAsset, type ActionResult } from "@/app/rampart/actions";

type Suggestion = { vendor: string; product: string };

/**
 * Adding a piece of the environment.
 *
 * The form asks for the *software*, not the box, because that is what the
 * matcher can reason about: "FortiOS 7.2.8" produces a verdict, "FortiGate
 * 100F" produces nothing. The hardware model is still worth recording — it is
 * how you find the thing in a rack — so it is here as a label that says plainly
 * that it is not used for matching.
 *
 * Vendor and product autocomplete from the vocabulary already present in
 * collected data. Free text is accepted, because the inventory should never be
 * blocked by a gap in NVD's naming, but it is marked and shown as unmatched
 * rather than quietly pretending it will match.
 */
export function AssetForm({ asset, onDone }: { asset?: Asset; onDone?: () => void }) {
  const editing = Boolean(asset);
  const [state, action, pending] = useActionState<ActionResult | null, FormData>(
    editing ? updateAsset : createAsset,
    null,
  );

  const [vendor, setVendor] = useState(asset?.vendor ?? "");
  const [product, setProduct] = useState(asset?.product ?? "");
  const [catalogued, setCatalogued] = useState(asset?.catalogued ?? false);
  const [hits, setHits] = useState<Suggestion[]>([]);
  const [version, setVersion] = useState(asset?.version ?? "");
  const [versions, setVersions] = useState<string[]>([]);
  const [showVersions, setShowVersions] = useState(false);
  const form = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (state?.ok) {
      if (!editing) form.current?.reset();
      setVendor("");
      setProduct("");
      setCatalogued(false);
      setHits([]);
      setVersion("");
      setVersions([]);
      onDone?.();
    }
  }, [state, editing, onDone]);

  // Suggestions come from the corpus, debounced: the catalogue is a query
  // against 82k product rows, not a static list.
  useEffect(() => {
    const term = product.trim();
    if (term.length < 2 || catalogued) {
      setHits([]);
      return;
    }
    const abort = new AbortController();
    const timer = setTimeout(() => {
      fetch(`/api/rampart/catalogue?q=${encodeURIComponent(term)}`, { signal: abort.signal })
        .then((r) => (r.ok ? r.json() : { items: [] }))
        .then((d) => setHits(d.items ?? []))
        .catch(() => undefined);
    }, 180);
    return () => {
      clearTimeout(timer);
      abort.abort();
    };
  }, [product, catalogued]);

  // Once a product is named, offer the versions advisories have mentioned for
  // it. This is not a release catalogue — Asber has no such thing — so the list
  // is a shortcut, never a constraint: the field stays free text for the very
  // common case of running something no advisory has named yet.
  useEffect(() => {
    const p = product.trim();
    if (p.length < 2) {
      setVersions([]);
      return;
    }
    const abort = new AbortController();
    const timer = setTimeout(() => {
      const q = new URLSearchParams({ product: p, vendor: vendor.trim() });
      fetch(`/api/rampart/versions?${q}`, { signal: abort.signal })
        .then((r) => (r.ok ? r.json() : { items: [] }))
        .then((d) => setVersions(d.items ?? []))
        .catch(() => undefined);
    }, 220);
    return () => {
      clearTimeout(timer);
      abort.abort();
    };
  }, [product, vendor]);

  const typed = version.trim().toLowerCase();
  const versionHits = typed ? versions.filter((v) => v.startsWith(typed)) : versions;

  const pick = (s: Suggestion) => {
    setVendor(s.vendor);
    setProduct(s.product);
    setCatalogued(true);
    setHits([]);
    setVersion("");
  };

  return (
    <form ref={form} action={action} className="asset-form">
      {editing ? <input type="hidden" name="id" value={asset!.id} /> : null}
      <input type="hidden" name="catalogued" value={String(catalogued)} />
      <input type="hidden" name="cpe" value={asset?.cpe ?? ""} />

      <label className="field">
        <span>Name</span>
        <input name="label" defaultValue={asset?.label} maxLength={120} required
               placeholder="Edge firewall, main site" />
      </label>

      <label className="field">
        <span>Category</span>
        <select name="category" defaultValue={asset?.category ?? "firewall"}>
          {CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>{c.label}</option>
          ))}
        </select>
      </label>

      <label className="field field-wide field-data">
        <span>Product</span>
        <input
          name="product"
          value={product}
          onChange={(e) => {
            setProduct(e.target.value);
            setCatalogued(false);
          }}
          maxLength={300}
          required
          autoComplete="off"
          placeholder="fortios"
        />
        {hits.length ? (
          <ul className="suggest">
            {hits.map((s) => (
              <li key={`${s.vendor}/${s.product}`}>
                <button type="button" onClick={() => pick(s)}>
                  <b>{s.product}</b>
                  <span>{s.vendor}</span>
                </button>
              </li>
            ))}
          </ul>
        ) : null}
      </label>

      <label className="field field-data">
        <span>Vendor</span>
        <input name="vendor" value={vendor} onChange={(e) => setVendor(e.target.value)}
               maxLength={200} required autoComplete="off" placeholder="fortinet" />
      </label>

      <label className="field field-data">
        <span>
          Version{" "}
          <em>{versions.length ? `${versions.length} seen in advisories` : "the software, not the box"}</em>
        </span>
        <input
          name="version"
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          onFocus={() => setShowVersions(true)}
          onBlur={() => setTimeout(() => setShowVersions(false), 120)}
          maxLength={64}
          autoComplete="off"
          placeholder="7.2.8"
        />
        {showVersions && versionHits.length ? (
          <ul className="suggest suggest-versions">
            {versionHits.slice(0, 40).map((v) => (
              <li key={v}>
                <button type="button" onMouseDown={() => { setVersion(v); setShowVersions(false); }}>
                  <b>{v}</b>
                </button>
              </li>
            ))}
          </ul>
        ) : null}
      </label>

      <label className="field">
        <span>
          Hardware model <em>label only</em>
        </span>
        <input name="hardware_model" defaultValue={asset?.hardware_model ?? ""} maxLength={120}
               autoComplete="off" placeholder="FortiGate 100F" />
      </label>

      <div className="asset-form-foot">
        {catalogued ? (
          <span className="faint">Matched to the catalogue — version comparison will work.</span>
        ) : (
          <span className="faint">
            Not in the catalogue. It will still be tracked, but matching falls back to the name.
          </span>
        )}
        <span className="row">
          {state && !state.ok ? <span className="asset-error">{state.error}</span> : null}
          <button type="submit" className="btn btn-primary" disabled={pending}>
            {pending ? "Saving…" : editing ? "Save" : "Add to environment"}
          </button>
        </span>
      </div>
    </form>
  );
}
