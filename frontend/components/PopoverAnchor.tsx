"use client";

import { useEffect } from "react";

/** Gap between the control and the panel it opens. */
const MARGIN = 8;

/**
 * Places every score popover next to the control that opened it.
 *
 * The popovers are plain HTML rendered on the server: the Popover API supplies
 * open, close, Escape and click-outside for free, and puts them in the top
 * layer, which is what lets them escape the table's horizontal scroll
 * container. Only the placement needs script, and one listener covers every
 * row rather than one client component per row.
 */
export function PopoverAnchor() {
  useEffect(() => {
    let closeOnScroll: (() => void) | null = null;

    const place = (event: Event) => {
      const pop = event.target;
      if (!(pop instanceof HTMLElement) || !pop.classList.contains("score-pop")) return;

      if ((event as ToggleEvent).newState !== "open") {
        closeOnScroll?.();
        return;
      }

      const trigger = document.querySelector<HTMLElement>(`[popovertarget="${CSS.escape(pop.id)}"]`);
      if (!trigger) return;

      // beforetoggle runs while the popover is still display:none, so it has no
      // box to measure. An inline display beats the UA rule; hiding it in the
      // same breath means nothing is painted in the wrong place, because the
      // browser does not get a frame until this handler returns.
      pop.style.visibility = "hidden";
      pop.style.display = "block";
      const box = pop.getBoundingClientRect();
      pop.style.display = "";
      pop.style.visibility = "";

      const anchor = trigger.getBoundingClientRect();

      const left = Math.max(MARGIN, Math.min(anchor.left, window.innerWidth - box.width - MARGIN));
      const roomBelow = window.innerHeight - anchor.bottom - MARGIN;
      const flip = box.height > roomBelow && anchor.top - MARGIN - box.height > 0;

      pop.style.left = `${Math.round(left)}px`;
      pop.style.top = `${Math.round(flip ? anchor.top - MARGIN - box.height : anchor.bottom + MARGIN)}px`;
      // Grow out of the control, not out of the panel's own middle.
      pop.style.transformOrigin = `${Math.round(anchor.left + anchor.width / 2 - left)}px ${flip ? "100%" : "0"}`;

      // It is positioned against the viewport, so it would drift away from its
      // row on scroll. Leaving is the clearest resolution.
      const dismiss = () => pop.hidePopover();
      window.addEventListener("scroll", dismiss, { once: true, capture: true });
      closeOnScroll = () => window.removeEventListener("scroll", dismiss, { capture: true });
    };

    document.addEventListener("beforetoggle", place, true);
    return () => {
      document.removeEventListener("beforetoggle", place, true);
      closeOnScroll?.();
    };
  }, []);

  return null;
}
