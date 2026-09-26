import Link from "next/link";
import { AutoForm } from "@/components/AutoForm";
import { Pending } from "@/components/Pending";

export type SP = Record<string, string | string[] | undefined>;

export function one(sp: SP, key: string): string | undefined {
  const v = sp[key];
  return Array.isArray(v) ? v[0] : v;
}

export function href(base: string, sp: SP, changes: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(sp)) {
    if (k === "page" || k in changes || v === undefined) continue;
    if (Array.isArray(v)) v.forEach((x) => p.append(k, x));
    else p.append(k, v);
  }
  for (const [k, v] of Object.entries(changes)) if (v !== undefined && v !== "") p.append(k, v);
  const q = p.toString();
  return q ? `${base}?${q}` : base;
}

/** Segmented control — one option selected at a time (time window, etc.). */
export function Segmented({
  base,
  sp,
  param,
  options,
  fallback,
}: {
  base: string;
  sp: SP;
  param: string;
  options: { value: string; label: string }[];
  fallback: string;
}) {
  const current = one(sp, param) || fallback;
  return (
    <div className="segmented" role="group">
      {options.map((o) => (
        <Link key={o.value} className={current === o.value ? "on" : ""} href={href(base, sp, { [param]: o.value })}>
          {o.label}
          <Pending />
        </Link>
      ))}
    </div>
  );
}

/** Boolean pills. Active ones show an × so it is obvious how to remove them. */
export function Toggles({
  base,
  sp,
  options,
}: {
  base: string;
  sp: SP;
  options: { param: string; label: string; title?: string }[];
}) {
  return (
    <>
      {options.map((o) => {
        const on = one(sp, o.param) === "true";
        return (
          <Link
            key={o.param}
            className={`toggle${on ? " on" : ""}`}
            title={o.title}
            href={href(base, sp, { [o.param]: on ? undefined : "true" })}
          >
            {o.label}
            {on ? <span className="x">×</span> : null}
            <Pending />
          </Link>
        );
      })}
    </>
  );
}

/** Single-select pills (impact, platform…). Clicking an active one clears it. */
export function PillSelect({
  base,
  sp,
  param,
  options,
  label,
}: {
  base: string;
  sp: SP;
  param: string;
  options: { value: string; label: string }[];
  label?: string;
}) {
  const current = one(sp, param);
  return (
    <>
      {label ? <span className="faint">{label}</span> : null}
      {options.map((o) => {
        const on = current === o.value;
        return (
          <Link
            key={o.value}
            className={`toggle${on ? " on" : ""}`}
            href={href(base, sp, { [param]: on ? undefined : o.value })}
          >
            {o.label}
            {on ? <span className="x">×</span> : null}
            <Pending />
          </Link>
        );
      })}
    </>
  );
}

/** Text/select filters that submit as soon as you change them (no Apply button). */
export function TextFilters({
  base,
  sp,
  fields,
  sorts,
  sortDefault,
}: {
  base: string;
  sp: SP;
  fields: { name: string; placeholder: string }[];
  sorts?: { value: string; label: string }[];
  sortDefault?: string;
}) {
  const names = new Set([...fields.map((f) => f.name), "sort", "page"]);
  const hidden = Object.entries(sp).filter(([k]) => !names.has(k));
  return (
    <AutoForm action={base}>
      {hidden.map(([k, v]) =>
        (Array.isArray(v) ? v : [v]).map((x, i) =>
          x === undefined ? null : <input type="hidden" key={`${k}-${i}`} name={k} value={x} />,
        ),
      )}
      {fields.map((f) => (
        <input
          key={f.name}
          type="text"
          name={f.name}
          placeholder={f.placeholder}
          defaultValue={one(sp, f.name) || ""}
          style={{ width: 150 }}
        />
      ))}
      {sorts ? (
        <select name="sort" defaultValue={one(sp, "sort") || sortDefault}>
          {sorts.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
      ) : null}
      <noscript>
        <button type="submit">Apply</button>
      </noscript>
    </AutoForm>
  );
}

/** Shows "Clear all" only when something is actually filtered. */
export function ClearFilters({ base, sp, ignore = [] }: { base: string; sp: SP; ignore?: string[] }) {
  const active = Object.keys(sp).filter((k) => !ignore.includes(k) && k !== "page" && sp[k] !== undefined);
  if (!active.length) return null;
  return (
    <Link className="btn btn-ghost" href={base}>
      Clear {active.length} filter{active.length > 1 ? "s" : ""}
      <Pending />
    </Link>
  );
}

export const WINDOW_OPTIONS = [
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
  { value: "90d", label: "90d" },
  { value: "all", label: "All" },
];

export const IMPACT_OPTIONS = [
  { value: "rce", label: "RCE" },
  { value: "privilege_escalation", label: "Priv esc" },
  { value: "auth_bypass", label: "Auth bypass" },
];

export const PLATFORM_OPTIONS = [
  { value: "windows", label: "Windows" },
  { value: "linux", label: "Linux" },
  { value: "cloud", label: "Cloud" },
  { value: "active_directory", label: "Active Directory" },
  { value: "identity", label: "Identity" },
  { value: "web", label: "Web" },
  { value: "network", label: "Network" },
];
