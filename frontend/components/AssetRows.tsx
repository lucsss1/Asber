"use client";

import { useState } from "react";

import { CATEGORIES, type Asset } from "@/lib/rampart";
import { AssetForm } from "@/components/AssetForm";
import { deleteAsset } from "@/app/rampart/actions";

const CATEGORY_LABEL = Object.fromEntries(CATEGORIES.map((c) => [c.value, c.label]));

/**
 * The inventory, and editing it in place.
 *
 * Editing opens the row rather than a dialog, the same way a threat row opens:
 * what you are changing stays visible next to everything you are not, and the
 * list you were reading does not go away to make room for a form.
 *
 * Removal is two-step. It became easy to hit by accident once an Edit button
 * landed beside it, and a removed asset takes its matches with it — the cost of
 * a misclick is the whole verdict history for that piece of equipment.
 */
export function AssetRows({ assets }: { assets: Asset[] }) {
  const [editing, setEditing] = useState<number | null>(null);
  const [confirming, setConfirming] = useState<number | null>(null);

  return (
    <div className="asset-list">
      <div className="asset-row-main asset-head">
        <span>Asset</span>
        <span>Software</span>
        <span>Version</span>
        <span>Category</span>
        <span />
      </div>
      {assets.map((a) => {
        const open = editing === a.id;
        return (
          <div key={a.id} className={`asset-row${open ? " row-open" : ""}`}>
            <div className="asset-row-main">
                  <div className="asset-col asset-col-name">
                    <div className="asset-label">{a.label}</div>
                    {a.hardware_model ? <div className="faint">{a.hardware_model}</div> : null}
                  </div>
                  <div className="asset-col">
                    <div className="mono">{a.product}</div>
                    <div className="faint">{a.vendor}</div>
                  </div>
                  <div className="asset-col">
                    {a.version ? (
                      <span className="mono">{a.version}</span>
                    ) : (
                      <span className="tag" title="Without a version every match stays unconfirmed">
                        not set
                      </span>
                    )}
                  </div>
                  <div className="asset-col faint">{CATEGORY_LABEL[a.category] ?? a.category}</div>
                  <div className="asset-col asset-col-actions">
                    {!a.catalogued ? (
                      <span className="tag" title="Typed by hand — matching falls back to the name">
                        unmatched
                      </span>
                    ) : null}

                    <button
                      type="button"
                      className="btn btn-ghost small"
                      aria-expanded={open}
                      onClick={() => {
                        setEditing(open ? null : a.id);
                        setConfirming(null);
                      }}
                    >
                      {open ? "Cancel" : "Edit"}
                    </button>

                    {confirming === a.id ? (
                      <span className="row" style={{ gap: 4 }}>
                        <form action={deleteAsset}>
                          <input type="hidden" name="id" value={a.id} />
                          <button type="submit" className="btn btn-ghost small asset-remove">
                            Remove?
                          </button>
                        </form>
                        <button type="button" className="btn btn-ghost small"
                                onClick={() => setConfirming(null)}>
                          Keep
                        </button>
                      </span>
                    ) : (
                      <button type="button" className="btn btn-ghost small"
                              onClick={() => setConfirming(a.id)}>
                        Remove
                      </button>
                    )}
                  </div>
                </div>

                <div className="asset-edit" data-open={open ? "" : undefined}>
                  <div>
                    {open ? (
                      <div className="asset-edit-body">
                        <AssetForm asset={a} onDone={() => setEditing(null)} />
                        <p className="faint" style={{ marginTop: "var(--space-3)" }}>
                          Changing the version or product re-runs the match for this asset.
                        </p>
                      </div>
                    ) : null}
                  </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
