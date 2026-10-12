"use client";

import { useEffect, useRef, useState } from "react";

export type Option = { value: string; label: string };

/**
 * A select that this design system can actually draw.
 *
 * A native <select> renders its popup in the operating system, not the page:
 * the option background, the font, the corner radius and the highlight colour
 * are all outside CSS's reach. Transparent options over an OS-painted white
 * panel is how it ends up showing pale text on a pale background in the dark
 * theme — and even once the colour is forced, the shape and the type still
 * belong to the platform rather than to this console.
 *
 * So the list is ours, drawn with the same panel the product and version
 * suggestions use. The cost is that keyboard behaviour has to be written
 * rather than inherited, which is what the handler below is for; the value
 * still travels in a real input, so the form submits exactly as before.
 */
export function Picker({
  name,
  options,
  defaultValue,
  onChange,
}: {
  name: string;
  options: Option[];
  defaultValue?: string;
  onChange?: (value: string) => void;
}) {
  const [value, setValue] = useState(defaultValue ?? options[0]?.value ?? "");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);

  const current = options.find((o) => o.value === value) ?? options[0];

  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const choose = (v: string) => {
    setValue(v);
    setOpen(false);
    onChange?.(v);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      setOpen(false);
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) {
        setOpen(true);
        setActive(Math.max(0, options.findIndex((o) => o.value === value)));
        return;
      }
      const step = e.key === "ArrowDown" ? 1 : options.length - 1;
      setActive((i) => (i + step) % options.length);
      return;
    }
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (open) choose(options[active].value);
      else {
        setOpen(true);
        setActive(Math.max(0, options.findIndex((o) => o.value === value)));
      }
    }
  };

  return (
    <div className="picker" ref={box}>
      <input type="hidden" name={name} value={value} />
      <button
        type="button"
        className="picker-value"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => {
          setOpen((v) => !v);
          setActive(Math.max(0, options.findIndex((o) => o.value === value)));
        }}
        onKeyDown={onKeyDown}
      >
        <span>{current?.label}</span>
        <i className="picker-caret" aria-hidden="true" />
      </button>

      {open ? (
        <ul className="suggest picker-list" role="listbox" aria-label={name}>
          {options.map((o, i) => (
            <li key={o.value}>
              <button
                type="button"
                role="option"
                aria-selected={o.value === value}
                className={i === active ? "on" : undefined}
                onMouseMove={() => setActive(i)}
                onMouseDown={() => choose(o.value)}
              >
                {o.label}
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
