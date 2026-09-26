"use client";

import { useLinkStatus } from "next/link";

/**
 * An invisible marker rendered inside a <Link>. While that navigation is in
 * flight the parent control selects on it with :has(> .pending) and dims.
 *
 * It has to be a client child rather than a prop because useLinkStatus only
 * reports for the Link it sits under, and the filters and sidebar that need
 * it are server components.
 */
export function Pending() {
  const { pending } = useLinkStatus();
  return pending ? <span className="pending" /> : null;
}
