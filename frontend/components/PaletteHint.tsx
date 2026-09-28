"use client";

import { useEffect, useState } from "react";

/**
 * A shortcut nobody can see is a shortcut nobody uses. This sits in the search
 * field and is the only thing that tells you the palette exists.
 *
 * Rendered after mount because the right symbol depends on the platform, and
 * guessing on the server would mean a hydration mismatch on half of them.
 */
export function PaletteHint() {
  const [label, setLabel] = useState<string | null>(null);

  useEffect(() => {
    const mac = /Mac|iPhone|iPad/.test(navigator.userAgent);
    setLabel(mac ? "⌘K" : "Ctrl K");
  }, []);

  if (!label) return null;
  return (
    <kbd className="searchfield-kbd" aria-hidden="true">
      {label}
    </kbd>
  );
}
