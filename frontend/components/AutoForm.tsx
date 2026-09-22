"use client";

import { useRef } from "react";

/**
 * A GET form that submits itself: selects on change, text inputs on blur or Enter.
 * Progressive enhancement — without JavaScript the <noscript> Apply button works.
 */
export function AutoForm({ action, children }: { action: string; children: React.ReactNode }) {
  const ref = useRef<HTMLFormElement>(null);

  const submit = () => ref.current?.requestSubmit();

  return (
    <form
      ref={ref}
      action={action}
      method="get"
      className="row"
      style={{ gap: 8 }}
      onChange={(e) => {
        if ((e.target as HTMLElement).tagName === "SELECT") submit();
      }}
      onBlur={(e) => {
        const el = e.target as unknown as HTMLInputElement;
        if (el.tagName === "INPUT" && el.type === "text" && el.value !== el.defaultValue) submit();
      }}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          submit();
        }
      }}
    >
      {children}
    </form>
  );
}
